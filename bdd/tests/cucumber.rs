//! Netns-based BDD tests (cucumber, `harness = false`). Privileged (sudo), Linux-only —
//! run with `cargo test -p bdd`.
//!
//! Two features:
//! - `n6_datapath` — self-contained: the test plays SMF+gNB against a live `nf-upf` in a
//!   namespace and proves an ICMP echo round-trips N3↔N6.
//! - `datapath_e2e` (`@sim`) — the whole stack: the radiant core plus the **free-ran-ue**
//!   simulator (gNB + UE) register, establish a PDU session, and ping the data network.
//!   Runs only when `FREE_RAN_UE_BIN` points at the simulator binary.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bdd::{datapath, netns};
use cucumber::{given, then, when, World as CucumberWorld};
use tokio::time::{sleep, Instant};

// Addresses are fixed: both features are @serial and single-instance.
const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1); // host end of the host↔core-ns veth
const NS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2); // core-facing ns end (datapath: UPF; e2e: RAN)
const RAN_UE_GW: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 1); // RAN end of the RAN↔UE veth (e2e)
const UE_NS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2); // UE end of the RAN↔UE veth (e2e)
const N3_PORT: u16 = 2152;
const N4_PORT: u16 = 8805;
const GNB_TEID: u32 = 0x1001; // datapath feature: the downlink F-TEID we install and expect
const UDR_KEK: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[derive(Debug, Default, CucumberWorld)]
struct World {
    feature_tag: String,
    // datapath (self-contained) state
    ue_ip: Option<Ipv4Addr>,
    uplink_teid: Option<u32>,
    ping_ok: bool,
    // e2e (simulator) state — spawned processes kept owned for the scenario's lifetime
    procs: Vec<tokio::process::Child>,
}

impl World {
    /// FNV-1a of the feature tag — a short, interface-name-safe id.
    fn short(&self) -> String {
        let mut h: u32 = 0x811c_9dc5;
        for b in self.feature_tag.as_bytes() {
            h ^= *b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        format!("{h:08x}")
    }
    fn ns(&self, logical: &str) -> String {
        format!("{}_{}", self.feature_tag, logical)
    }
    /// Host-side veth name (≤15 chars via the hash), swept in cleanup.
    fn host_veth(&self) -> String {
        format!("h{}", self.short())
    }
}

/// Path to a radiant NF binary (`nf-<name>`); `RADIANT_TARGET_DIR` overrides the dir.
fn radiant_bin(name: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("RADIANT_TARGET_DIR") {
        return PathBuf::from(dir).join(format!("nf-{name}"));
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(format!("target/debug/nf-{name}"))
}

/// The free-ran-ue simulator binary (`FREE_RAN_UE_BIN`); `None` disables the `@sim` feature.
fn free_ran_ue_bin() -> Option<PathBuf> {
    std::env::var("FREE_RAN_UE_BIN").ok().map(PathBuf::from).filter(|p| p.exists())
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

/// Poll `cond` every 200ms until it returns true or `secs` elapse.
async fn wait_until<F, Fut>(secs: u64, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if cond().await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(200)).await;
    }
}

// ── shared: clean / verify ──────────────────────────────────────────────────────────────

#[given("a clean test environment")]
async fn clean_environment(world: &mut World) {
    assert!(!world.feature_tag.is_empty(), "feature must declare a tag for resource scoping");
    // Sweep whatever a crashed prior run of this feature left behind.
    let _ = netns::kill_host_procs("target/debug/nf-").await;
    for ns in netns::list_netns_with_prefix(&format!("{}_", world.feature_tag)).await.unwrap_or_default() {
        let _ = netns::kill_netns_procs(&ns).await;
        let _ = netns::delete_netns(&ns).await;
    }
    let _ = netns::delete_veth(&world.host_veth()).await;
}

#[then("the test environment should be clean")]
async fn verify_clean(world: &mut World) {
    let leftover = netns::list_netns_with_prefix(&format!("{}_", world.feature_tag)).await.unwrap_or_default();
    assert!(leftover.is_empty(), "namespaces still exist: {leftover:?}");
    println!("✓ Test environment is clean");
}

// ── feature: n6_datapath (self-contained) ──────────────────────────────────────────────

#[when("I set up the UPF namespace")]
async fn setup_upf_namespace(world: &mut World) {
    let ns = world.ns("upf");
    netns::create_netns(&ns).await.expect("create UPF namespace");
    netns::connect_host_to_netns(&ns, &world.host_veth(), "vupf", &HOST_IP.to_string(), &NS_IP.to_string())
        .await
        .expect("wire host<->UPF veth");
}

#[when("I start the UPF with its N6 TUN")]
async fn start_upf_in_ns(world: &mut World) {
    let bin = radiant_bin("upf");
    assert!(bin.exists(), "nf-upf not found at {} — run `cargo build -p nf-upf`", bin.display());
    let ns = world.ns("upf");
    netns::spawn_in_netns_env(&ns, &[("RADIANT_UPF_N3_ADDR", &NS_IP.to_string())], &bin.to_string_lossy(), &[])
        .await
        .expect("spawn nf-upf in namespace");
    let up = wait_until(5, || netns::iface_exists(&ns, "n6upf0")).await;
    assert!(up, "UPF N6 TUN (n6upf0) did not come up in {ns}");
}

#[when(regex = r#"^I establish a PFCP session for UE "([^"]+)"$"#)]
async fn establish_session(world: &mut World, ue: String) {
    let ue_ip: Ipv4Addr = ue.parse().expect("valid UE IP");
    let upf_n4 = SocketAddrV4::new(NS_IP, N4_PORT);
    let uplink_teid = datapath::establish_session(upf_n4, HOST_IP, ue_ip, GNB_TEID, HOST_IP)
        .await
        .expect("SMF establishes + modifies the PFCP session");
    world.ue_ip = Some(ue_ip);
    world.uplink_teid = Some(uplink_teid);
}

#[when(regex = r#"^the UE sends an ICMP echo to the gateway "([^"]+)"$"#)]
async fn ue_sends_echo(world: &mut World, gw: String) {
    let gw_ip: Ipv4Addr = gw.parse().expect("valid gateway IP");
    let ue_ip = world.ue_ip.expect("session established first");
    let uplink_teid = world.uplink_teid.expect("session established first");
    let gnb_bind = SocketAddrV4::new(HOST_IP, N3_PORT);
    let upf_n3 = SocketAddrV4::new(NS_IP, N3_PORT);
    world.ping_ok = datapath::ping_through_datapath(gnb_bind, upf_n3, uplink_teid, GNB_TEID, ue_ip, gw_ip)
        .await
        .expect("run datapath ping");
}

#[then("the datapath forwards the packet round trip")]
async fn assert_round_trip(world: &mut World) {
    assert!(world.ping_ok, "no ICMP echo reply returned through the N3/N6 datapath");
}

#[given("the datapath topology exists")]
async fn datapath_topology_exists(world: &mut World) {
    assert!(netns::netns_exists(&world.ns("upf")).await, "UPF namespace is not up");
}

#[when("I stop the UPF")]
async fn stop_upf(world: &mut World) {
    netns::kill_netns_procs(&world.ns("upf")).await.expect("kill UPF");
}

#[when("I delete the UPF namespace")]
async fn delete_upf_namespace(world: &mut World) {
    netns::delete_netns(&world.ns("upf")).await.expect("delete UPF namespace");
    netns::delete_veth(&world.host_veth()).await.expect("delete host veth");
}

// ── feature: datapath_e2e (@sim, free-ran-ue) ──────────────────────────────────────────

#[given("the free-ran-ue simulator is available")]
async fn sim_available(_world: &mut World) {
    assert!(free_ran_ue_bin().is_some(), "FREE_RAN_UE_BIN must point at the simulator binary");
}

#[when("I set up the RAN and UE namespaces")]
async fn setup_ran_ue(world: &mut World) {
    let (ran, ue) = (world.ns("ran"), world.ns("ue"));
    netns::create_netns(&ran).await.expect("create RAN namespace");
    netns::create_netns(&ue).await.expect("create UE namespace");
    // host 10.0.1.1 ↔ RAN 10.0.1.2 (N2/N3 to the core), RAN 10.0.2.1 ↔ UE 10.0.2.2 (RAN planes).
    netns::connect_host_to_netns(&ran, &world.host_veth(), "veth0", &HOST_IP.to_string(), &NS_IP.to_string())
        .await
        .expect("wire host<->RAN veth");
    netns::connect_netns_pair(&ran, "veth1", &RAN_UE_GW.to_string(), &ue, "veth0", &UE_NS_IP.to_string())
        .await
        .expect("wire RAN<->UE veth");
    netns::add_route(&ran, "default", &["via", &HOST_IP.to_string()]).await.expect("RAN default route");
    netns::add_route(&ue, "default", &["via", &RAN_UE_GW.to_string()]).await.expect("UE default route");
}

#[when("I start the radiant core")]
async fn start_core(world: &mut World) {
    let nrf = "http://127.0.0.1:8000";
    let db = format!("/tmp/{}_udr.redb", world.feature_tag);
    let _ = std::fs::remove_file(&db);

    // NRF first — the UDR, UDM, AUSF and SMF register with it on startup.
    world.procs.push(spawn_core(false, &[], "nrf").await);
    assert!(wait_until(5, || netns::host_port_listening(8000, "tcp")).await, "NRF SBI not up");

    // UDR owns the subscriber store; the UDM is a stateless Nudr front-end.
    world.procs.push(
        spawn_core(false, &[("RADIANT_UDR_PROVISION_DEMO", "1"), ("RADIANT_UDR_DB", &db), ("RADIANT_UDR_MASTER_KEY", UDR_KEK)], "udr").await,
    );
    world.procs.push(spawn_core(false, &[], "udm").await);
    world.procs.push(spawn_core(false, &[("RADIANT_AUSF_NRF", nrf)], "ausf").await);
    // UPF needs CAP_NET_ADMIN for its N6 TUN → run under sudo; advertise the host N3 address.
    world.procs.push(spawn_core(true, &[("RADIANT_UPF_N3_ADDR", &HOST_IP.to_string())], "upf").await);
    assert!(wait_until(6, || netns::host_iface_exists("n6upf0")).await, "UPF N6 TUN did not come up");

    world.procs.push(
        spawn_core(false, &[("RADIANT_SMF_UPF_N4", "127.0.0.1:8805"), ("RADIANT_SMF_NRF", nrf)], "smf").await,
    );
    world.procs.push(spawn_core(false, &[], "amf").await);
    let ready = wait_until(6, || async {
        netns::host_port_listening(8002, "tcp").await // SMF (registered before serving)
            && netns::host_port_listening(8003, "tcp").await // AUSF
            && netns::host_port_listening(38412, "sctp").await // AMF N2
    })
    .await;
    assert!(ready, "radiant core did not become ready");
}

/// Spawn one radiant NF in the host namespace (under sudo when `root`), tracking it.
async fn spawn_core(root: bool, env: &[(&str, &str)], name: &str) -> tokio::process::Child {
    let bin = radiant_bin(name);
    assert!(bin.exists(), "nf-{name} not found at {} — run `cargo build`", bin.display());
    netns::spawn_host_env(root, env, &bin.to_string_lossy(), &[]).await.unwrap_or_else(|e| panic!("spawn nf-{name}: {e}"))
}

#[when("I start the gNB in the RAN namespace")]
async fn start_gnb(world: &mut World) {
    let sim = free_ran_ue_bin().expect("FREE_RAN_UE_BIN");
    let ran = world.ns("ran");
    let cfg = fixture("gnb.yaml");
    world.procs.push(
        netns::spawn_in_netns_env(&ran, &[], &sim.to_string_lossy(), &["gnb", "-c", &cfg.to_string_lossy()])
            .await
            .expect("spawn gNB"),
    );
    // The gNB opens its RAN control-plane listener after NG Setup completes.
    let up = wait_until(8, || async {
        tokio::process::Command::new("sudo")
            .args(["ip", "netns", "exec", &ran, "ss", "-lnt"])
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(":31413"))
            .unwrap_or(false)
    })
    .await;
    assert!(up, "gNB RAN control plane did not come up (NG Setup failed?)");
}

#[when("I start the UE in the UE namespace")]
async fn start_ue(world: &mut World) {
    let sim = free_ran_ue_bin().expect("FREE_RAN_UE_BIN");
    let ue = world.ns("ue");
    let cfg = fixture("ue.yaml");
    world.procs.push(
        netns::spawn_in_netns_env(&ue, &[], &sim.to_string_lossy(), &["ue", "-c", &cfg.to_string_lossy()])
            .await
            .expect("spawn UE"),
    );
    // The UE creates ueTun0 only after the PDU session establishment completes.
    let up = wait_until(12, || netns::iface_exists(&ue, "ueTun0")).await;
    assert!(up, "UE ueTun0 did not appear (registration or PDU session failed?)");
}

#[then(regex = r#"^the UE can ping the data network gateway "([^"]+)"$"#)]
async fn ue_pings_dn(world: &mut World, gw: String) {
    let ue = world.ns("ue");
    let ue_ip = netns::iface_ipv4(&ue, "ueTun0").await.expect("UE has no ueTun0 address");
    // Route the DN subnet out the UE's TUN (the UE assigns only a /32 to ueTun0).
    netns::add_route(&ue, "10.45.0.0/16", &["dev", "ueTun0"]).await.expect("add DN route in UE ns");
    let ok = netns::ping_from_netns(&ue, &ue_ip, &gw, 3, 2).await;
    assert!(ok, "UE ({ue_ip}) could not ping the data network gateway {gw} through the datapath");
}

#[given("the e2e topology exists")]
async fn e2e_topology_exists(world: &mut World) {
    assert!(netns::netns_exists(&world.ns("ran")).await, "RAN namespace is not up");
}

#[when("I stop the UE in the UE namespace")]
async fn stop_ue(world: &mut World) {
    let ue = world.ns("ue");
    netns::kill_netns_procs(&ue).await.expect("kill UE");
    // Its ueTun0 goes with it — a later "no tunnel" assertion must start clean.
    let gone = wait_until(5, || async { !netns::iface_exists(&ue, "ueTun0").await }).await;
    assert!(gone, "ueTun0 still present after stopping the UE");
}

#[when(regex = r#"^I start a UE requesting the unsubscribed DNN "([^"]+)"$"#)]
async fn start_ue_unsubscribed_dnn(world: &mut World, _dnn: String) {
    let sim = free_ran_ue_bin().expect("FREE_RAN_UE_BIN");
    let ue = world.ns("ue");
    // Same demo subscriber (registration succeeds) but pduSession.dnn = corporate.
    let cfg = fixture("ue_unsubscribed_dnn.yaml");
    world.procs.push(
        netns::spawn_in_netns_env(&ue, &[], &sim.to_string_lossy(), &["ue", "-c", &cfg.to_string_lossy()])
            .await
            .expect("spawn UE (unsubscribed DNN)"),
    );
}

#[then("the UE does not get a PDU session")]
async fn ue_gets_no_pdu_session(world: &mut World) {
    let ue = world.ns("ue");
    // The SMF refuses the DNN (403) and the AMF answers with a 5GSM Establishment
    // Reject — so ueTun0 must never appear. 8s is well past the happy-path
    // registration + PDU-session bring-up time.
    let appeared = wait_until(8, || netns::iface_exists(&ue, "ueTun0")).await;
    assert!(!appeared, "ueTun0 appeared — the unsubscribed DNN was not rejected");
}

#[when("I stop the simulator and core")]
async fn stop_sim_and_core(world: &mut World) {
    netns::kill_netns_procs(&world.ns("ue")).await.expect("kill UE");
    netns::kill_netns_procs(&world.ns("ran")).await.expect("kill gNB");
    netns::kill_host_procs("target/debug/nf-").await.expect("kill radiant core"); // also removes n6upf0
}

#[when("I delete the RAN and UE namespaces")]
async fn delete_ran_ue(world: &mut World) {
    netns::delete_netns(&world.ns("ue")).await.expect("delete UE namespace");
    netns::delete_netns(&world.ns("ran")).await.expect("delete RAN namespace");
    netns::delete_veth(&world.host_veth()).await.expect("delete host veth");
}

#[tokio::main]
async fn main() {
    let sim = free_ran_ue_bin().is_some();
    if !sim {
        println!("ℹ  FREE_RAN_UE_BIN not set — skipping the @sim end-to-end feature");
    }
    World::cucumber()
        .max_concurrent_scenarios(1) // serial: host-global namespaces + fixed ports
        .before(|feature, _rule, _scenario, world| {
            Box::pin(async move {
                // Scope resources by the feature's own tag (skip the meta-tags).
                world.feature_tag = feature
                    .tags
                    .iter()
                    .find(|t| *t != "serial" && *t != "sim")
                    .cloned()
                    .unwrap_or_default();
            })
        })
        .fail_on_skipped()
        .filter_run_and_exit("tests/features", move |feature, _rule, scenario| {
            let is_sim = feature.tags.iter().chain(&scenario.tags).any(|t| t == "sim");
            !is_sim || sim
        })
        .await;
}
