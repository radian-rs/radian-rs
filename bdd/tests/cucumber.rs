//! Netns-based BDD tests (cucumber, `harness = false`). Privileged (sudo), Linux-only —
//! run with `cargo test -p bdd`.
//!
//! Two features:
//! - `n6_datapath` — self-contained: the test plays SMF+gNB against a live `nf-upf` in a
//!   namespace and proves an ICMP echo round-trips N3↔N6.
//! - `datapath_e2e` (`@sim`) — the whole stack: the radian core plus the **free-ran-ue**
//!   simulator (gNB + UE) register, establish a PDU session, and ping the data network.
//!   Runs only when `FREE_RAN_UE_BIN` points at the simulator binary.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bdd::{datapath, netns, ran};
use cucumber::{given, then, when, World as CucumberWorld};
use tokio::time::{sleep, Instant};

// Addresses are fixed: both features are @serial and single-instance.
const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1); // host end of the host↔core-ns veth
const NS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2); // core-facing ns end (datapath: UPF; e2e: RAN)
const RAN_UE_GW: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 1); // RAN end of the RAN↔UE veth (e2e)
const UE_NS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2); // UE end of the RAN↔UE veth (e2e)
const N3_PORT: u16 = 2152;
const N4_PORT: u16 = 8805;
/// The scripted core runs on the host loopback. The UPF binds a **distinct**
/// loopback alias so its N3 (GTP-U :2152) doesn't collide with the scripted gNB's
/// N3 (:2152 on 127.0.0.1) — the two speak GTP-U to each other across 127.0.0.1↔.2.
const UPF_N3_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const GNB_N3_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;
const GNB_TEID: u32 = 0x1001; // datapath feature: the downlink F-TEID we install and expect
const UDR_KEK: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[derive(Debug, Default, CucumberWorld)]
struct World {
    feature_tag: String,
    // datapath (self-contained) state
    ue_ip: Option<Ipv4Addr>,
    /// The IPv6 interface identifier the UE read from an IPv6/IPv4v6 accept (design/131).
    ue_v6_iid: Option<[u8; 8]>,
    uplink_teid: Option<u32>,
    ping_ok: bool,
    // e2e (simulator) state — spawned processes kept owned for the scenario's lifetime
    procs: Vec<tokio::process::Child>,
    // scripted gNB/UE state (design/116 Tier B)
    gnb: Option<ran::ScriptedGnb>,
    ue: Option<ran::ScriptedUe>,
    amf_ue_id: Option<u64>,
    /// The last downlink NAS the gNB received, awaiting the UE's handling.
    pending_nas: Option<Vec<u8>>,
    /// The PDU session id the scripted UE established.
    pdu_psi: Option<u8>,
    /// The UPF's N3 F-TEID address learned from the N2 setup (datapath echo).
    upf_n3_addr: Option<Ipv4Addr>,
    /// The gNB's N3 (GTP-U) socket, bound early so it can receive a downlink G-PDU
    /// the UPF flushes after a CM-IDLE resume.
    gnb_n3: Option<tokio::net::UdpSocket>,
    // standalone gNB tier (@gnb, design/128 Phase 1)
    /// A UE speaking real RRC over PDCP to the standalone `radian-gnb` (owns its NAS/USIM).
    ue_rrc: Option<ran::UeRrc>,
    /// The 5G-TMSI the UE reads from its Registration Accept (its paging identity).
    ue_tmsi: Option<u32>,
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

/// Path to a radian NF binary (`nf-<name>`); `RADIAN_TARGET_DIR` overrides the dir.
fn radian_bin(name: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("RADIAN_TARGET_DIR") {
        return PathBuf::from(dir).join(format!("nf-{name}"));
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(format!("target/debug/nf-{name}"))
}

/// Path to a RAN binary (e.g. `radian-gnb`); `RADIAN_TARGET_DIR` overrides the dir.
fn radian_ran_bin(name: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("RADIAN_TARGET_DIR") {
        return PathBuf::from(dir).join(format!("radian-{name}"));
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(format!("target/debug/radian-{name}"))
}

/// The Uu endpoint a UE camps on — bound by the gNB-DU (`RADIAN_DU_UU_BIND` default), which
/// carries the UE's RRC/data over F1 to the CU (design/128 Phase 3e).
const GNB_UU_ADDR: &str = "127.0.0.1:4997";

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
    let _ = netns::kill_host_procs("target/debug/radian-du").await;
    let _ = netns::kill_host_procs("target/debug/radian-gnb").await;
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
    let bin = radian_bin("upf");
    assert!(bin.exists(), "nf-upf not found at {} — run `cargo build -p nf-upf`", bin.display());
    let ns = world.ns("upf");
    netns::spawn_in_netns_env(&ns, &[("RADIAN_UPF_N3_ADDR", &NS_IP.to_string())], &bin.to_string_lossy(), &[])
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

#[when("I start the radian core")]
async fn start_core(world: &mut World) {
    let nrf = "http://127.0.0.1:8000";
    let db = format!("/tmp/{}_udr.redb", world.feature_tag);
    let _ = std::fs::remove_file(&db);
    let tag = world.feature_tag.clone();

    // NRF first — the UDR, UDM, AUSF and SMF register with it on startup.
    world.procs.push(spawn_core(&tag, false, &[], "nrf").await);
    assert!(wait_until(5, || netns::host_port_listening(8000, "tcp")).await, "NRF SBI not up");

    // UDR owns the subscriber store; the UDM is a stateless Nudr front-end.
    world.procs.push(
        spawn_core(&tag, false, &[("RADIAN_UDR_PROVISION_DEMO", "1"), ("RADIAN_UDR_DB", &db), ("RADIAN_UDR_MASTER_KEY", UDR_KEK)], "udr").await,
    );
    world.procs.push(spawn_core(&tag, false, &[], "udm").await);
    world.procs.push(spawn_core(&tag, false, &[("RADIAN_AUSF_NRF", nrf)], "ausf").await);
    // PCF serves Npcf_SMPolicyControl; the SMF discovers it for the SM policy.
    world.procs.push(spawn_core(&tag, false, &[("RADIAN_PCF_NRF", nrf)], "pcf").await);
    // CHF serves Nchf_ConvergedCharging; the SMF opens a charging session per PDU session.
    world.procs.push(spawn_core(&tag, false, &[("RADIAN_CHF_NRF", nrf)], "chf").await);
    // NSSF serves Nnssf_NSSelection; the AMF discovers it at registration for per-TA
    // slice availability (design/133). Started before the AMF so the first
    // registration already finds it.
    world.procs.push(spawn_core(&tag, false, &[("RADIAN_NSSF_NRF", nrf)], "nssf").await);
    // UPF needs CAP_NET_ADMIN for its N6 TUN → run under sudo; advertise the host N3 address.
    // The UPF binds a distinct loopback alias (127.0.0.2) for N3/N4 + advertises it
    // as its N3 F-TEID address, so a scripted gNB can run real GTP-U on 127.0.0.1:2152
    // without a port clash.
    world.procs.push(
        spawn_core(
            &tag,
            true,
            &[
                ("RADIAN_UPF_BIND", &UPF_N3_IP.to_string()),
                ("RADIAN_UPF_N3_ADDR", &UPF_N3_IP.to_string()),
            ],
            "upf",
        )
        .await,
    );
    assert!(wait_until(6, || netns::host_iface_exists("n6upf0")).await, "UPF N6 TUN did not come up");

    let smf_n4 = format!("{UPF_N3_IP}:{N4_PORT}");
    world.procs.push(
        spawn_core(&tag, false, &[("RADIAN_SMF_UPF_N4", &smf_n4), ("RADIAN_SMF_NRF", nrf)], "smf").await,
    );
    // Shrink T3513 so the paging-retransmission scenario runs in a few seconds. It
    // stays comfortably longer than a scripted resume takes, so scenarios whose UE
    // resumes (the buffer-flush arc) still stop paging before the first retransmit.
    world.procs.push(spawn_core(&tag, false, &[("RADIAN_AMF_T3513_SECS", "2")], "amf").await);
    let ready = wait_until(6, || async {
        netns::host_port_listening(8002, "tcp").await // SMF (registered before serving)
            && netns::host_port_listening(8003, "tcp").await // AUSF
            && netns::host_port_listening(8006, "tcp").await // PCF (AM/SM policy source)
            && netns::host_port_listening(38412, "sctp").await // AMF N2
    })
    .await;
    assert!(ready, "radian core did not become ready");
}

/// Spawn one radian NF in the host namespace (under sudo when `root`), tracking it;
/// its stdout+stderr are captured to `/tmp/<tag>_<nf>.log` for log-assertion steps.
async fn spawn_core(tag: &str, root: bool, env: &[(&str, &str)], name: &str) -> tokio::process::Child {
    let bin = radian_bin(name);
    assert!(bin.exists(), "nf-{name} not found at {} — run `cargo build`", bin.display());
    netns::spawn_host_env_logged(root, env, &bin.to_string_lossy(), &[], &nf_log(tag, name))
        .await
        .unwrap_or_else(|e| panic!("spawn nf-{name}: {e}"))
}

/// Path of the captured log for one core NF under this feature's tag.
fn nf_log(tag: &str, nf: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/{tag}_{nf}.log"))
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
    netns::kill_host_procs("target/debug/nf-").await.expect("kill radian core"); // also removes n6upf0
}

#[when("I delete the RAN and UE namespaces")]
async fn delete_ran_ue(world: &mut World) {
    netns::delete_netns(&world.ns("ue")).await.expect("delete UE namespace");
    netns::delete_netns(&world.ns("ran")).await.expect("delete RAN namespace");
    netns::delete_veth(&world.host_veth()).await.expect("delete host veth");
}

// ── feature: scripted_registration (@scripted, design/116 Tier B) ──────────────────────

/// The RAN-UE-NGAP-ID the scripted gNB assigns its single UE.
const SCRIPTED_RAN_UE_ID: u32 = 1;

/// Parse a 6-hex-digit TAC string ("000001") into its 3 wire bytes.
fn parse_tac(tac: &str) -> [u8; 3] {
    let v: Vec<u8> = (0..6).step_by(2).map(|i| u8::from_str_radix(&tac[i..i + 2], 16).expect("hex TAC")).collect();
    [v[0], v[1], v[2]]
}

#[when("the scripted gNB connects and completes NG Setup")]
async fn scripted_gnb_connects(world: &mut World) {
    let amf = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 38412);
    let gnb = ran::ScriptedGnb::connect(amf.into()).await.expect("connect to the AMF N2");
    gnb.ng_setup(0x314, "999", "70", &[[0, 0, 1]]).await.expect("NG Setup");
    world.gnb = Some(gnb);
    world.ue = Some(ran::ScriptedUe::demo());
}

#[when(regex = r#"^the scripted UE sends its registration request from TAC "([0-9a-fA-F]{6})"$"#)]
async fn scripted_ue_registers(world: &mut World, tac: String) {
    let (gnb, ue) = (world.gnb.as_ref().expect("gNB connected"), world.ue.as_ref().expect("UE"));
    let msg = ngap::initial_ue_message_with_nas_at(
        SCRIPTED_RAN_UE_ID,
        ue.registration_request(),
        "999",
        "70",
        &parse_tac(&tac),
    );
    gnb.send(&msg).await.expect("send InitialUEMessage");
}

#[then("the AMF challenges the UE with 5G-AKA")]
async fn amf_challenges(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let (amf_ue_id, nas_pdu) = gnb.recv_downlink_nas().await.expect("the authentication downlink");
    assert!(
        nas::parse_authentication_request(&nas_pdu).is_some(),
        "expected an Authentication Request NAS PDU"
    );
    world.amf_ue_id = Some(amf_ue_id);
    world.pending_nas = Some(nas_pdu);
}

#[when("the scripted UE answers the challenge with RES*")]
async fn ue_answers_challenge(world: &mut World) {
    let challenge = world.pending_nas.take().expect("a pending Authentication Request");
    let reply = world.ue.as_mut().expect("UE").authenticate(&challenge).expect("the USIM answers");
    let response = match reply {
        ran::ChallengeReply::Response(bytes) => bytes,
        ran::ChallengeReply::SynchFailure(_) => panic!("the USIM unexpectedly failed synchronisation"),
    };
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, response))
        .await
        .expect("send AuthenticationResponse");
}

#[then("the AMF selects NEA2/NIA2 in a security mode command")]
async fn amf_commands_security(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let (amf_ue_id, smc) = gnb.recv_downlink_nas().await.expect("the security mode downlink");
    assert_eq!(Some(amf_ue_id), world.amf_ue_id, "the SMC addresses the same UE");
    assert_eq!(
        smc.get(1),
        Some(&nas::sht::INTEGRITY_NEW_CONTEXT),
        "the SMC is integrity-protected with a new context"
    );
    // SHT 3 is not ciphered — the announcement is readable before the UE holds keys.
    let inner = nas::decode_nas_5gs_message(&smc[7..]).expect("SMC payload decodes");
    assert_eq!(
        nas::security_mode_selection(&inner),
        Some((2, 2, ran::ScriptedUe::SEC_CAP.to_vec())),
        "NEA2/NIA2 selected and the UE's capability replayed for the bidding-down check"
    );
    world.pending_nas = Some(smc);
}

#[when("the scripted UE completes the security mode procedure")]
async fn ue_completes_security(world: &mut World) {
    let smc = world.pending_nas.take().expect("a pending Security Mode Command");
    let ue = world.ue.as_mut().expect("UE");
    let (nea, nia, _replayed, complete) =
        ue.complete_security(&smc).expect("the UE verifies the SMC and derives its keys");
    assert_eq!((nea, nia), (2, 2));
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, complete))
        .await
        .expect("send SecurityModeComplete");
}

#[then("the AMF sets up the initial context carrying the registration accept")]
async fn amf_sets_up_context(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let pdu = gnb.recv().await.expect("the initial context setup");
    let (amf_ue_id, ran_ue_id, ic) =
        ngap::initial_context_setup_params(&pdu).expect("an InitialContextSetupRequest");
    assert_eq!(Some(amf_ue_id), world.amf_ue_id);
    assert_eq!(ran_ue_id, SCRIPTED_RAN_UE_ID);

    let ue = world.ue.as_ref().expect("UE");
    // The AS root key the AMF hands the gNB must equal the UE's own derivation —
    // the whole K_AUSF → K_SEAF → K_AMF → K_gNB chain crosses here.
    assert_eq!(ic.security_key, ue.kgnb.expect("UE-derived K_gNB"), "K_gNB mismatch");
    assert_eq!(ic.ue_sec_cap, ran::ScriptedUe::SEC_CAP, "capabilities replayed to the RAN");
    assert_eq!(ic.allowed_nssai, vec![(1, Some([1, 2, 3]))], "the subscribed slice is allowed");
    assert_eq!(ic.rfsp, Some(5), "RFSP from the UDR AM policy");
    assert_eq!(ic.ue_ambr, Some((600_000_000, 300_000_000)), "PCF UE-AMBR override (dl/ul)");
    assert_eq!(
        ic.area_restriction,
        Some((vec![[0, 0, 1]], vec![])),
        "the UDR servAreaRes rides as the Mobility Restriction List"
    );
    assert!(ic.pdu_sessions.is_empty(), "initial registration sets up no inline sessions");
    world.pending_nas = Some(ic.nas);
}

#[then("the accept grants the subscribed slice, a GUTI, and the registration area")]
async fn accept_grants(world: &mut World) {
    let accept = world.pending_nas.take().expect("the ICS NAS PDU");
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let ue = world.ue.as_mut().expect("UE");
    let msg = ue.read_downlink(&accept).expect("the accept verifies at the UE");
    assert_eq!(nas::gmm_message_type(&msg), Some(nas::Nas5gmmMessageType::RegistrationAccept));
    assert_eq!(nas::allowed_nssai_from_registration_accept(&msg), vec![(1, Some([1, 2, 3]))]);
    assert_eq!(
        nas::guti_tmsi_from_registration_accept(&msg),
        Some(amf_ue_id as u32),
        "a 5G-GUTI is assigned"
    );
    assert_eq!(
        nas::registration_area_from_registration_accept(&msg),
        Some(vec![[0, 0, 1]]),
        "registration area = the serving gNB's TA ∪ the UE's TAI"
    );
    assert!(nas::t3512_octet_from_registration_accept(&msg).is_some(), "T3512 assigned");
}

#[when("the gNB confirms the context and the UE completes the registration")]
async fn gnb_confirms_ue_completes(world: &mut World) {
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let complete = world
        .ue
        .as_mut()
        .expect("UE")
        .protected_uplink(&nas::registration_complete())
        .expect("protect RegistrationComplete");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::initial_context_setup_response(amf_ue_id, SCRIPTED_RAN_UE_ID))
        .await
        .expect("send InitialContextSetupResponse");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, complete))
        .await
        .expect("send RegistrationComplete");
}

#[then("the AMF nudges the registered UE with a configuration update")]
async fn amf_nudges_config_update(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let (amf_ue_id, bytes) = gnb.recv_downlink_nas().await.expect("the post-registration downlink");
    assert_eq!(Some(amf_ue_id), world.amf_ue_id);
    let msg = world.ue.as_mut().expect("UE").read_downlink(&bytes).expect("the CUC verifies");
    assert_eq!(
        nas::gmm_message_type(&msg),
        Some(nas::Nas5gmmMessageType::ConfigurationUpdateCommand)
    );
}

/// The scripted gNB's DL N3 F-TEID reported in the setup response (control-plane
/// slice — no GTP-U flows on it yet). Loopback, since the core runs on the host.
const SCRIPTED_GNB_DL_TEID: u32 = 0x2001;

/// The RAN-UE-NGAP-ID the gNB assigns when a CM-IDLE UE resumes (a fresh RAN
/// context after the AN release tore down the old one).
const SCRIPTED_RESUME_RAN_UE_ID: u32 = 2;

#[when("the gNB releases the UE context via AN release")]
async fn gnb_an_release(world: &mut World) {
    let amf_ue_id = world.amf_ue_id.expect("registered UE");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    // Radio cause 20 = user-inactivity, what a real gNB sends for AN release.
    gnb.send(&ngap::ue_context_release_request(amf_ue_id, SCRIPTED_RAN_UE_ID, 20))
        .await
        .expect("send UEContextReleaseRequest");
    let pdu = gnb.recv().await.expect("the release command");
    assert!(
        ngap::parse_ue_context_release_command(&pdu).is_some(),
        "expected a UEContextReleaseCommand for the AN release"
    );
}

#[when("the scripted UE resumes with a Service Request")]
async fn ue_resumes_with_service_request(world: &mut World) {
    let tmsi = world.amf_ue_id.expect("registered UE") as u32;
    let sr = world.ue.as_mut().expect("UE").service_request(tmsi).expect("build Service Request");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::initial_ue_message_with_stmsi_at(
        SCRIPTED_RESUME_RAN_UE_ID,
        tmsi,
        sr,
        "999",
        "70",
        &[0, 0, 1],
    ))
    .await
    .expect("send InitialUEMessage (Service Request)");
}

#[then("the AMF re-establishes the context and reactivates the session")]
async fn amf_reestablishes_on_resume(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let pdu = gnb.recv().await.expect("the resume initial context setup");
    let (amf_ue_id, ran_ue_id, ic) =
        ngap::initial_context_setup_params(&pdu).expect("an InitialContextSetupRequest");
    assert_eq!(ran_ue_id, SCRIPTED_RESUME_RAN_UE_ID);
    // A fresh K_gNB derived from the Service Request's NAS COUNT (TS 33.501
    // §6.9.2.1.1) — the UE's own resume derivation must match.
    assert_eq!(
        ic.security_key,
        world.ue.as_ref().expect("UE").kgnb.expect("resume K_gNB"),
        "resume K_gNB mismatch"
    );
    // The PDU session comes back **inline** in the context setup, carrying the
    // UPF's retained uplink F-TEID (the SMF/UPF reactivated the user plane).
    let sessions = ngap::initial_context_setup_request_session_ids(&pdu);
    let (psi, upf_teid, _addr) = sessions.into_iter().next().expect("the reactivated session");
    assert_eq!(Some(psi), world.pdu_psi);
    assert_ne!(upf_teid, 0, "the UPF returned a retained uplink F-TEID on reactivation");
    // The gNB confirms the context, reporting its DL F-TEID for the session.
    gnb.send(&ngap::initial_context_setup_response_with_sessions(
        amf_ue_id,
        ran_ue_id,
        &[(psi, SCRIPTED_GNB_DL_TEID, Ipv4Addr::LOCALHOST)],
    ))
    .await
    .expect("send InitialContextSetupResponse");
    world.amf_ue_id = Some(amf_ue_id); // the resume assigned a fresh AMF-UE-NGAP-ID
    world.pending_nas = Some(ic.nas);
}

#[then("the UE reads the service accept")]
async fn ue_reads_service_accept(world: &mut World) {
    let accept = world.pending_nas.take().expect("the ServiceAccept NAS");
    let msg = world.ue.as_mut().expect("UE").read_downlink(&accept).expect("verify the accept");
    assert_eq!(
        nas::gmm_message_type(&msg),
        Some(nas::Nas5gmmMessageType::ServiceAccept),
        "expected a Service Accept"
    );
}

#[when("the scripted UE requests a PDU session")]
async fn ue_requests_pdu_session(world: &mut World) {
    let psi = 1u8;
    let request = world.ue.as_mut().expect("UE").pdu_session_request(psi).expect("build the request");
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, request))
        .await
        .expect("send UL NAS Transport (PDU session request)");
    world.pdu_psi = Some(psi);
}

#[then("the AMF sets up the PDU session at the gNB")]
async fn amf_sets_up_pdu_session(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let pdu = gnb.recv().await.expect("the PDU session resource setup");
    let (amf_ue_id, ran_ue_id, sessions) =
        ngap::pdu_session_resource_setup_request_params(&pdu).expect("a PDUSessionResourceSetupRequest");
    assert_eq!(Some(amf_ue_id), world.amf_ue_id);
    assert_eq!(ran_ue_id, SCRIPTED_RAN_UE_ID);
    let (psi, upf_teid, upf_addr, nas) = sessions.into_iter().next().expect("one PDU session");
    assert_eq!(Some(psi), world.pdu_psi);
    assert_ne!(upf_teid, 0, "the UPF allocated a non-zero uplink N3 F-TEID");
    // The gNB accepts the session, reporting its own DL F-TEID at its real N3 address
    // (→ the AMF installs the downlink at the UPF via UpdateSMContext, so a later
    // datapath echo returns here).
    gnb.send(&ngap::pdu_session_resource_setup_response(
        amf_ue_id,
        ran_ue_id,
        psi,
        1, // QFI of the default non-GBR flow
        SCRIPTED_GNB_DL_TEID,
        GNB_N3_IP,
    ))
    .await
    .expect("send PDUSessionResourceSetupResponse");
    // Hold the relayed NAS-PDU (the accept) + the UPF's uplink F-TEID for the datapath.
    world.pending_nas = Some(nas);
    world.uplink_teid = Some(upf_teid);
    world.upf_n3_addr = Some(upf_addr);
}

#[then(regex = r#"^the UE is assigned an IP address in "([^"]+)"$"#)]
async fn ue_assigned_ip(world: &mut World, subnet: String) {
    let accept = world.pending_nas.take().expect("the relayed accept NAS");
    let (psi, ip) = world.ue.as_mut().expect("UE").read_pdu_session_accept(&accept).expect("read accept");
    assert_eq!(Some(psi), world.pdu_psi);
    // Assert the assigned address falls in the DN pool (e.g. "10.45.0.0/16").
    let (net, prefix) = subnet.split_once('/').expect("subnet in CIDR form");
    let base: Ipv4Addr = net.parse().expect("valid subnet base");
    let bits: u32 = prefix.parse().expect("valid prefix length");
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    assert_eq!(
        u32::from(ip) & mask,
        u32::from(base) & mask,
        "assigned UE IP {ip} is not in {subnet}"
    );
    world.ue_ip = Some(ip); // for a datapath echo from this UE address
}

/// Map a feature-file type name ("IPV4"/"IPV6"/"IPV4V6") to the NAS enum.
fn pdu_type_from_name(name: &str) -> nas::PduSessionType {
    nas::PduSessionType::from_name(name).unwrap_or_else(|| panic!("unknown PDU session type {name:?}"))
}

#[when(regex = r#"^the scripted UE requests an? "(IPV4|IPV6|IPV4V6)" PDU session$"#)]
async fn ue_requests_typed_pdu_session(world: &mut World, ty: String) {
    let psi = 1u8;
    let request = world
        .ue
        .as_mut()
        .expect("UE")
        .pdu_session_request_typed(psi, pdu_type_from_name(&ty), None)
        .expect("build the typed request");
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, request))
        .await
        .expect("send UL NAS Transport (typed PDU session request)");
    world.pdu_psi = Some(psi);
}

#[when(regex = r#"^the scripted UE requests an? "(IPV4|IPV6|IPV4V6)" PDU session for DNN "([^"]+)"$"#)]
async fn ue_requests_typed_pdu_for_dnn(world: &mut World, ty: String, dnn: String) {
    let psi = 1u8;
    let request = world
        .ue
        .as_mut()
        .expect("UE")
        .pdu_session_request_typed(psi, pdu_type_from_name(&ty), Some(&dnn))
        .expect("build the typed request");
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, request))
        .await
        .expect("send UL NAS Transport (typed PDU session request)");
    world.pdu_psi = Some(psi);
}

/// Assert the relayed accept carries the expected PDU address family (design/131):
/// IPv4 (a v4 address), IPv6 (an interface identifier), or IPv4v6 (both).
#[then(regex = r#"^the UE reads an? "(IPV4|IPV6|IPV4V6)" PDU address$"#)]
async fn ue_reads_pdu_address(world: &mut World, family: String) {
    let accept = world.pending_nas.take().expect("the relayed accept NAS");
    let (psi, addr, _cause) =
        world.ue.as_mut().expect("UE").read_pdu_session_accept_addr(&accept).expect("read accept");
    assert_eq!(Some(psi), world.pdu_psi);
    match (family.as_str(), addr) {
        ("IPV4", nas::PduAddress::Ipv4(v4)) => {
            world.ue_ip = Some(v4);
        }
        ("IPV6", nas::PduAddress::Ipv6 { iid }) => {
            assert_ne!(iid, [0u8; 8], "the IPv6 interface identifier is non-zero");
            world.ue_v6_iid = Some(iid);
        }
        ("IPV4V6", nas::PduAddress::Ipv4v6 { iid, v4 }) => {
            assert_ne!(iid, [0u8; 8], "the IPv6 interface identifier is non-zero");
            world.ue_ip = Some(v4);
            world.ue_v6_iid = Some(iid);
        }
        (want, got) => panic!("expected a {want} PDU address, got {got:?}"),
    }
    world.pending_nas = Some(accept); // keep it for a following cause assertion
}

/// Assert the accept carries a session-type downgrade 5GSM cause (#50/#51).
#[then(regex = r#"^the accept carries 5GSM cause (\d+)$"#)]
async fn accept_carries_cause(world: &mut World, cause: u8) {
    let accept = world.pending_nas.as_ref().expect("the relayed accept NAS");
    let got = world
        .ue
        .as_mut()
        .expect("UE")
        .read_pdu_session_accept_addr(accept)
        .expect("read accept")
        .2
        .expect("the accept carries a 5GSM cause");
    assert_eq!(got, cause, "5GSM downgrade cause");
}

#[when(regex = r#"^the scripted UE requests an? "(IPV4|IPV6|IPV4V6)" PDU session requesting DNS$"#)]
async fn ue_requests_typed_pdu_session_dns(world: &mut World, ty: String) {
    let psi = 1u8;
    let request = world
        .ue
        .as_mut()
        .expect("UE")
        .pdu_session_request_typed_with_dns(psi, pdu_type_from_name(&ty))
        .expect("build the typed request with a DNS request");
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, request))
        .await
        .expect("send UL NAS Transport (DNS-requesting PDU session request)");
    world.pdu_psi = Some(psi);
}

#[then(regex = r#"^the accept returns the IPv6 DNS server "([^"]+)"$"#)]
async fn accept_returns_dns(world: &mut World, dns: String) {
    let expected: Ipv6Addr = dns.parse().expect("valid IPv6 DNS server");
    let accept = world.pending_nas.as_ref().expect("the relayed accept NAS");
    let got = world
        .ue
        .as_mut()
        .expect("UE")
        .read_pdu_session_dns_ipv6(accept)
        .expect("read the accept")
        .expect("the accept returned an IPv6 DNS server");
    assert_eq!(got, expected, "IPv6 DNS server from PCO");
}

/// The marker payload of the injected downlink packet — checked when it flushes.
const DL_MARKER: &[u8] = b"radian-downlink";

#[when("the gNB opens its N3 tunnel")]
async fn gnb_opens_n3(world: &mut World) {
    // Bind the gNB's N3 socket now so it is already listening when the UPF flushes
    // the buffered downlink after the CM-IDLE resume.
    let sock = datapath::bind_gnb_n3(SocketAddrV4::new(GNB_N3_IP, N3_PORT))
        .await
        .expect("bind the gNB N3 socket");
    world.gnb_n3 = Some(sock);
}

#[when("a downlink packet arrives for the UE on the data network")]
async fn downlink_packet_for_ue(world: &mut World) {
    let ue_ip = world.ue_ip.expect("the UE has an assigned IP");
    // Send to the UE address: the host routes 10.45.0.0/16 to the UPF's N6 TUN, so
    // the UPF sees a downlink packet for the (now CM-IDLE) UE — it buffers it and
    // raises a Downlink Data Report, which drives paging.
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.expect("bind DN socket");
    sock.send_to(DL_MARKER, SocketAddrV4::new(ue_ip, 9999))
        .await
        .expect("send a downlink packet to the UE");
}

#[then("the buffered downlink packet arrives on the gNB's N3 tunnel")]
async fn buffered_packet_flushes(world: &mut World) {
    let ue_ip = world.ue_ip.expect("the UE has an assigned IP");
    let sock = world.gnb_n3.as_ref().expect("the gNB opened its N3 tunnel");
    // On the resume, the AMF's ICS-response handling installs the downlink at the UPF,
    // which flushes the buffered packet as a G-PDU on our DL F-TEID.
    let inner = datapath::recv_downlink_gpdu(sock, SCRIPTED_GNB_DL_TEID, 5)
        .await
        .expect("receive the flushed downlink")
        .expect("the buffered downlink packet did not flush to the N3 tunnel");
    // The inner IP packet is the one we injected: destined for the UE, carrying the marker.
    assert!(inner.len() >= 20, "flushed G-PDU carries an IPv4 packet");
    let dst = Ipv4Addr::new(inner[16], inner[17], inner[18], inner[19]);
    assert_eq!(dst, ue_ip, "the flushed packet is addressed to the UE");
    assert!(
        inner.windows(DL_MARKER.len()).any(|w| w == DL_MARKER),
        "the flushed packet carries the injected payload"
    );
}

#[then(regex = r#"^the gNB is paged (\d+) times for the UE$"#)]
async fn gnb_paged_n_times(world: &mut World, n: usize) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let tmsi = world.amf_ue_id.expect("registered UE") as u32;
    // The UE never resumes, so the AMF retransmits the Paging under T3513 up to its
    // max-sends; each attempt reaches this gNB (it serves the UE's registration area).
    for i in 1..=n {
        let pdu = gnb.recv().await.unwrap_or_else(|e| panic!("paging attempt {i} not received: {e}"));
        assert_eq!(
            ngap::tmsi_from_paging(&pdu),
            Some(tmsi),
            "paging attempt {i} carries the UE's 5G-S-TMSI"
        );
    }
}

#[then(regex = r#"^the gNB is paged for the UE in TAC "([0-9a-fA-F]{6})"$"#)]
async fn gnb_is_paged(world: &mut World, tac: String) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let pdu = gnb.recv().await.expect("the paging message");
    let tmsi = world.amf_ue_id.expect("registered UE") as u32;
    assert_eq!(
        ngap::tmsi_from_paging(&pdu),
        Some(tmsi),
        "the Paging carries the UE's 5G-S-TMSI"
    );
    let tacs = ngap::tacs_from_paging(&pdu).unwrap_or_default();
    assert!(tacs.contains(&parse_tac(&tac)), "the Paging TAI list covers TAC {tac}: {tacs:02x?}");
}

#[then(regex = r#"^the UE can reach the data network gateway "([^"]+)" over the datapath$"#)]
async fn ue_reaches_dn_over_datapath(world: &mut World, gw: String) {
    let gw_ip: Ipv4Addr = gw.parse().expect("valid gateway IP");
    let ue_ip = world.ue_ip.expect("the UE has an assigned IP");
    let uplink_teid = world.uplink_teid.expect("the UPF uplink F-TEID was learned");
    let upf_addr = world.upf_n3_addr.expect("the UPF N3 address was learned");
    // Play the gNB's N3: GTP-U-encap an ICMP echo (UE → gateway) on the UPF's uplink
    // F-TEID, and expect the reply back on our DL F-TEID — the full N3 → N6 → N3 trip.
    let ok = datapath::ping_through_datapath(
        SocketAddrV4::new(GNB_N3_IP, N3_PORT),
        SocketAddrV4::new(upf_addr, N3_PORT),
        uplink_teid,
        SCRIPTED_GNB_DL_TEID,
        ue_ip,
        gw_ip,
    )
    .await
    .expect("run the datapath echo");
    assert!(ok, "no ICMP echo reply returned through the signalled N3/N6 datapath");
}

#[then(regex = r#"^the UE can reach the data network gateway "([^"]+)" over the IPv6 datapath$"#)]
async fn ue_reaches_dn_over_datapath_v6(world: &mut World, gw: String) {
    let gw_ip: Ipv6Addr = gw.parse().expect("valid IPv6 gateway");
    // The scripted UE knows only the interface identifier from the accept (the RA that
    // carries the prefix is design/131 Phase C). The SMF's pool is deterministic
    // (2001:db8::/32, the /64 index == the IID's low 4 bytes), so the UE reconstructs
    // its full address `2001:db8:<index>::<iid>` out-of-band (Phase B).
    let iid = world.ue_v6_iid.expect("the UE read an IPv6 interface identifier");
    let mut a = [0u8; 16];
    a[0..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]); // 2001:db8::/32 pool base
    a[4..8].copy_from_slice(&iid[4..8]); // the /64 index
    a[8..16].copy_from_slice(&iid);
    let ue_ip = Ipv6Addr::from(a);
    let uplink_teid = world.uplink_teid.expect("the UPF uplink F-TEID was learned");
    let upf_addr = world.upf_n3_addr.expect("the UPF N3 address was learned");
    let ok = datapath::ping_through_datapath_v6(
        SocketAddrV4::new(GNB_N3_IP, N3_PORT),
        SocketAddrV4::new(upf_addr, N3_PORT),
        uplink_teid,
        SCRIPTED_GNB_DL_TEID,
        ue_ip,
        gw_ip,
    )
    .await
    .expect("run the IPv6 datapath echo");
    assert!(ok, "no ICMPv6 echo reply returned through the signalled N3/N6 datapath");
}

#[then(regex = r#"^the UE configures its IPv6 address via SLAAC and reaches the gateway "([^"]+)"$"#)]
async fn ue_slaac_and_reaches_gw(world: &mut World, gw: String) {
    let gw_ip: Ipv6Addr = gw.parse().expect("valid IPv6 gateway");
    // Only the interface identifier is known from the accept; the /64 prefix must come
    // from the Router Advertisement the UPF sends in answer to a Router Solicitation
    // (design/131 Phase C) — real SLAAC, no out-of-band prefix.
    let iid = world.ue_v6_iid.expect("the UE read an IPv6 interface identifier");
    let uplink_teid = world.uplink_teid.expect("the UPF uplink F-TEID was learned");
    let upf_addr = world.upf_n3_addr.expect("the UPF N3 address was learned");
    let ok = datapath::slaac_and_ping_v6(
        SocketAddrV4::new(GNB_N3_IP, N3_PORT),
        SocketAddrV4::new(upf_addr, N3_PORT),
        uplink_teid,
        SCRIPTED_GNB_DL_TEID,
        iid,
        gw_ip,
    )
    .await
    .expect("run SLAAC + the datapath echo");
    assert!(ok, "the UE did not SLAAC from a Router Advertisement and reach the gateway");
}

// ── N2 interface management (TS 38.413 §8.7, design/132) ────────────────────────────

#[when("the gNB resets the whole NG interface")]
async fn gnb_resets_ng_interface(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::ng_reset_all(ngap::CauseRadioNetwork::UNSPECIFIED))
        .await
        .expect("send NGReset");
}

#[then("the AMF acknowledges the NG reset")]
async fn amf_acks_ng_reset(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let pdu = gnb.recv().await.expect("the NG Reset Acknowledge");
    assert!(
        ngap::parse_ng_reset_acknowledge(&pdu).is_some(),
        "expected an NGResetAcknowledge, got {}",
        pdu.procedure_name()
    );
}

#[when(regex = r#"^the gNB updates its configuration to serve TAC "([^"]+)"$"#)]
async fn gnb_updates_configuration(world: &mut World, tac: String) {
    let tacs = parse_tacs(&tac);
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::ran_configuration_update("radian-gnb-reconfigured", &tacs, "999", "70"))
        .await
        .expect("send RANConfigurationUpdate");
}

#[then("the AMF acknowledges the configuration update")]
async fn amf_acks_configuration_update(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let pdu = gnb.recv().await.expect("the RAN Configuration Update Acknowledge");
    assert!(
        matches!(pdu, ngap::NGAP_PDU::SuccessfulOutcome(_)),
        "expected a SuccessfulOutcome, got {}",
        pdu.procedure_name()
    );
}

#[when("the gNB sends an Error Indication")]
async fn gnb_sends_error_indication(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::error_indication(None, None, ngap::CauseRadioNetwork::UNSPECIFIED))
        .await
        .expect("send ErrorIndication");
}

#[when(regex = r#"^the operator (signals|clears) AMF overload$"#)]
async fn operator_overload(_world: &mut World, verb: String) {
    let action = if verb == "signals" { "start" } else { "stop" };
    let resp = sbi_core::sbi_client()
        .post("http://127.0.0.1:8001/oam/v1/overload")
        .header("content-type", "application/json")
        .body(format!(r#"{{"action":"{action}"}}"#))
        .send()
        .await
        .expect("POST the AMF's OAM overload endpoint");
    assert!(resp.status().is_success(), "OAM overload returned {}", resp.status());
}

#[then(regex = r#"^the gNB receives an Overload (Start|Stop)$"#)]
async fn gnb_receives_overload(world: &mut World, which: String) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let pdu = gnb.recv().await.expect("the overload message");
    if which == "Start" {
        assert!(
            ngap::overload_action(&pdu).is_some(),
            "expected an OverloadStart carrying an action, got {}",
            pdu.procedure_name()
        );
    } else {
        assert!(ngap::is_overload_stop(&pdu), "expected an OverloadStop, got {}", pdu.procedure_name());
    }
}

/// Parse a comma-separated TAC list like `"000001,000002"` into 3-byte TACs.
fn parse_tacs(spec: &str) -> Vec<[u8; 3]> {
    spec.split(',').filter(|s| !s.is_empty()).map(parse_tac).collect()
}

#[then(regex = r#"^the accept's registration area covers TACs "([0-9a-fA-F,]+)"$"#)]
async fn accept_registration_area(world: &mut World, spec: String) {
    let accept = world.pending_nas.take().expect("the ICS NAS PDU");
    let msg = world.ue.as_mut().expect("UE").read_downlink(&accept).expect("the accept verifies");
    assert_eq!(nas::gmm_message_type(&msg), Some(nas::Nas5gmmMessageType::RegistrationAccept));
    assert_eq!(
        nas::registration_area_from_registration_accept(&msg),
        Some(parse_tacs(&spec)),
        "registration area = the serving gNB's TA list ∪ the UE's TAI"
    );
}

#[when(regex = r#"^the scripted UE requests a PDU session for DNN "([^"]+)"$"#)]
async fn ue_requests_pdu_for_dnn(world: &mut World, dnn: String) {
    let psi = 1u8;
    let request =
        world.ue.as_mut().expect("UE").pdu_session_request_for_dnn(psi, &dnn).expect("build the request");
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, request))
        .await
        .expect("send UL NAS Transport (PDU session request)");
    world.pdu_psi = Some(psi);
}

#[then(regex = r#"^the AMF rejects the PDU session with 5GSM cause (\d+) and a back-off timer$"#)]
async fn amf_rejects_pdu_session(world: &mut World, cause: u8) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let (amf_ue_id, bytes) = gnb.recv_downlink_nas().await.expect("the reject downlink");
    assert_eq!(Some(amf_ue_id), world.amf_ue_id);
    let (got_cause, t3396) =
        world.ue.as_mut().expect("UE").read_pdu_session_reject(&bytes).expect("read the reject");
    assert_eq!(got_cause, cause, "5GSM reject cause");
    assert!(t3396.is_some(), "the reject carries a T3396 back-off timer");
}

#[when("the scripted UE re-registers with its 5G-GUTI")]
async fn ue_reregisters_with_guti(world: &mut World) {
    // The 5G-TMSI the AMF assigned at registration is this UE's AMF-UE-NGAP-ID.
    let tmsi = world.amf_ue_id.expect("registered UE") as u32;
    let req = world.ue.as_ref().expect("UE").guti_registration_request(tmsi);
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::initial_ue_message_with_nas_at(SCRIPTED_RAN_UE_ID, req, "999", "70", &[0, 0, 1]))
        .await
        .expect("send InitialUEMessage (GUTI re-registration)");
    // The AMF assigns a fresh AMF-UE-NGAP-ID for the re-registration; the next
    // downlink (the re-auth challenge) carries it — captured by the challenge step.
}

#[when("the scripted UE registers with an unknown 5G-GUTI")]
async fn ue_registers_unknown_guti(world: &mut World) {
    // A 5G-TMSI the AMF has never assigned — its GUTI directory misses, so it
    // must ask for the SUCI.
    let req = world.ue.as_ref().expect("UE").guti_registration_request(0xDEAD_BEEF);
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::initial_ue_message_with_nas_at(SCRIPTED_RAN_UE_ID, req, "999", "70", &[0, 0, 1]))
        .await
        .expect("send InitialUEMessage (unknown GUTI)");
}

#[then("the AMF requests the UE's identity")]
async fn amf_requests_identity(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let (amf_ue_id, bytes) = gnb.recv_downlink_nas().await.expect("the identity-request downlink");
    // The Identity Request is sent plain (no NAS security context yet).
    let msg = nas::decode_nas_5gs_message(&bytes).expect("decode the identity request");
    assert_eq!(
        nas::gmm_message_type(&msg),
        Some(nas::Nas5gmmMessageType::IdentityRequest),
        "expected an Identity Request"
    );
    world.amf_ue_id = Some(amf_ue_id);
}

#[when("the scripted UE answers with its SUCI")]
async fn ue_answers_with_suci(world: &mut World) {
    let response = world.ue.as_ref().expect("UE").identity_response();
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, response))
        .await
        .expect("send IdentityResponse");
}

/// Parse a slice spec like `"1:010203,2"` into `(sst, optional 3-byte SD)` pairs.
fn parse_slices(spec: &str) -> Vec<(u8, Option<[u8; 3]>)> {
    spec.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| match s.split_once(':') {
            Some((sst, sd)) => {
                let b: Vec<u8> = (0..6).step_by(2).map(|i| u8::from_str_radix(&sd[i..i + 2], 16).unwrap()).collect();
                (sst.parse().unwrap(), Some([b[0], b[1], b[2]]))
            }
            None => (s.parse().unwrap(), None),
        })
        .collect()
}

/// Register from a specific tracking area *and* request slices — the NSSF's per-TA
/// availability decision depends on both (design/133).
#[when(regex = r#"^the scripted UE sends its registration request from TAC "([0-9a-fA-F]{6})" requesting slices "([^"]+)"$"#)]
async fn scripted_ue_registers_from_tac_requesting(world: &mut World, tac: String, spec: String) {
    let tacs = parse_tacs(&tac);
    let (gnb, ue) = (world.gnb.as_ref().expect("gNB connected"), world.ue.as_ref().expect("UE"));
    let msg = ngap::initial_ue_message_with_nas_at(
        SCRIPTED_RAN_UE_ID,
        ue.registration_request_requesting(&parse_slices(&spec)),
        "999",
        "70",
        &tacs[0],
    );
    gnb.send(&msg).await.expect("send InitialUEMessage");
}

#[when(regex = r#"^the scripted UE sends its registration request requesting slices "([^"]+)"$"#)]
async fn scripted_ue_registers_requesting(world: &mut World, spec: String) {
    let (gnb, ue) = (world.gnb.as_ref().expect("gNB connected"), world.ue.as_ref().expect("UE"));
    let msg = ngap::initial_ue_message_with_nas_at(
        SCRIPTED_RAN_UE_ID,
        ue.registration_request_requesting(&parse_slices(&spec)),
        "999",
        "70",
        &[0, 0, 1],
    );
    gnb.send(&msg).await.expect("send InitialUEMessage");
}

#[when("the scripted UE's USIM is ahead of the network")]
async fn ue_usim_ahead(world: &mut World) {
    // A large stored SQN so the network's next challenge is guaranteed stale,
    // forcing the synchronisation-failure / AUTS resync path.
    world.ue.as_mut().expect("UE").set_sqn_ms([0x00, 0x00, 0x00, 0x10, 0x00, 0x00]);
}

#[when("the scripted UE rejects the stale challenge with an AUTS")]
async fn ue_rejects_stale_challenge(world: &mut World) {
    let challenge = world.pending_nas.take().expect("a pending Authentication Request");
    let reply = world.ue.as_mut().expect("UE").authenticate(&challenge).expect("the USIM answers");
    let auts = match reply {
        ran::ChallengeReply::SynchFailure(bytes) => bytes,
        ran::ChallengeReply::Response(_) => panic!("the USIM accepted a stale challenge"),
    };
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, auts))
        .await
        .expect("send AuthenticationFailure (synch)");
}

#[when("the scripted UE answers the challenge with a wrong RES*")]
async fn ue_answers_wrong(world: &mut World) {
    let challenge = world.pending_nas.take().expect("a pending Authentication Request");
    let response =
        world.ue.as_ref().expect("UE").wrong_challenge_response(&challenge).expect("a wrong response");
    let amf_ue_id = world.amf_ue_id.expect("AMF-UE-NGAP-ID assigned");
    let gnb = world.gnb.as_ref().expect("gNB connected");
    gnb.send(&ngap::uplink_nas_transport(amf_ue_id, SCRIPTED_RAN_UE_ID, response))
        .await
        .expect("send AuthenticationResponse (wrong RES*)");
}

#[then("the AMF rejects authentication and releases the UE")]
async fn amf_rejects_authentication(world: &mut World) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let (amf_ue_id, bytes) = gnb.recv_downlink_nas().await.expect("the authentication-reject downlink");
    assert_eq!(Some(amf_ue_id), world.amf_ue_id);
    // The Authentication Reject is sent unprotected (no NAS security context exists).
    let msg = nas::decode_nas_5gs_message(&bytes).expect("decode the reject");
    assert_eq!(
        nas::gmm_message_type(&msg),
        Some(nas::Nas5gmmMessageType::AuthenticationReject),
        "expected an Authentication Reject"
    );
    let pdu = gnb.recv().await.expect("the release command");
    assert!(
        ngap::parse_ue_context_release_command(&pdu).is_some(),
        "expected a UEContextReleaseCommand after the reject"
    );
}

#[then(regex = r#"^the AMF rejects the registration with 5GMM cause (\d+) and a back-off timer$"#)]
async fn amf_rejects_registration(world: &mut World, cause: u8) {
    let gnb = world.gnb.as_ref().expect("gNB connected");
    let (amf_ue_id, bytes) = gnb.recv_downlink_nas().await.expect("the reject downlink");
    assert_eq!(Some(amf_ue_id), world.amf_ue_id);
    let msg = world.ue.as_mut().expect("UE").read_downlink(&bytes).expect("the reject verifies");
    let (got_cause, rejected, t3346) =
        nas::parse_registration_reject(&msg).expect("a Registration Reject");
    assert_eq!(got_cause, cause, "5GMM reject cause");
    assert!(!rejected.is_empty(), "the reject carries the rejected NSSAI");
    assert!(t3346.is_some(), "the reject carries a T3346 back-off timer");
    // The gNB is then told to release the UE context.
    let pdu = gnb.recv().await.expect("the release command");
    assert!(
        ngap::parse_ue_context_release_command(&pdu).is_some(),
        "expected a UEContextReleaseCommand after the reject"
    );
}

#[then(regex = r#"^the accept allows slice "([^"]+)" and rejects slice "([^"]+)"$"#)]
async fn accept_allows_and_rejects(world: &mut World, allowed_spec: String, rejected_spec: String) {
    let accept = world.pending_nas.take().expect("the ICS NAS PDU");
    let msg = world.ue.as_mut().expect("UE").read_downlink(&accept).expect("the accept verifies");
    assert_eq!(nas::gmm_message_type(&msg), Some(nas::Nas5gmmMessageType::RegistrationAccept));
    assert_eq!(
        nas::allowed_nssai_from_registration_accept(&msg),
        parse_slices(&allowed_spec),
        "the allowed NSSAI is the requested ∩ subscribed"
    );
    let rejected: Vec<(u8, Option<[u8; 3]>)> =
        nas::rejected_nssai_from_registration_accept(&msg).into_iter().map(|(s, _cause)| s).collect();
    assert_eq!(rejected, parse_slices(&rejected_spec), "the unsubscribed slice is rejected");
}

#[then(regex = r#"^the "([a-z]+)" log should contain "([^"]+)"$"#)]
async fn log_should_contain(world: &mut World, nf: String, needle: String) {
    let path = nf_log(&world.feature_tag, &nf);
    let found = wait_until(5, || {
        let (path, needle) = (path.clone(), needle.clone());
        async move { netns::log_contains(&path, &needle) }
    })
    .await;
    assert!(found, "{} does not contain {needle:?}", path.display());
}

#[given("the scripted core is running")]
async fn scripted_core_running(_world: &mut World) {
    assert!(netns::host_port_listening(38412, "sctp").await, "the AMF N2 is not up");
}

#[when("I stop the radian core")]
async fn stop_core_only(_world: &mut World) {
    netns::kill_host_procs("target/debug/nf-").await.expect("kill radian core");
}

// ── feature: gnb_standalone (@gnb, design/128 Phase 0) ─────────────────────────────────

#[when("the standalone gNB connects and completes NG Setup")]
async fn start_standalone_gnb(world: &mut World) {
    let bin = radian_ran_bin("gnb");
    assert!(bin.exists(), "radian-gnb not found at {} — run `cargo build -p radian-gnb`", bin.display());
    let log = nf_log(&world.feature_tag, "gnb");
    // The gNB runs **CU-shaped** (design/128 Phase 3e): N2 at 127.0.0.1:38412, N3 at
    // 127.0.0.1:2152, and an F1 south side (F1-C 127.0.0.1:38472, F1-U 127.0.0.1:2153)
    // instead of the fake Uu — the gNB-DU below terminates the Uu the UE camps on.
    let child = netns::spawn_host_env_logged(false, &[("RADIAN_GNB_F1", "1")], &bin.to_string_lossy(), &[], &log)
        .await
        .expect("spawn radian-gnb");
    world.procs.push(child);
    let up = wait_until(8, || {
        let log = log.clone();
        async move { netns::log_contains(&log, "NG Setup complete") }
    })
    .await;
    assert!(up, "the standalone gNB did not complete NG Setup (see {})", log.display());
    // The CU accepts the F1-C association only after NG Setup, so start the DU now.
    start_gnb_du(world).await;
}

/// Start the Rust gNB-DU stub: it connects F1-C to the CU, runs F1 Setup, and binds the Uu
/// ([`GNB_UU_ADDR`]) the scripted UE camps on. Stands in for OCUDU's `odu` in CI.
async fn start_gnb_du(world: &mut World) {
    let bin = radian_ran_bin("du");
    assert!(bin.exists(), "radian-du not found at {} — run `cargo build -p radian-gnb`", bin.display());
    let log = nf_log(&world.feature_tag, "du");
    let child = netns::spawn_host_env_logged(false, &[], &bin.to_string_lossy(), &[], &log)
        .await
        .expect("spawn radian-du");
    world.procs.push(child);
    let up = wait_until(8, || {
        let log = log.clone();
        async move { netns::log_contains(&log, "gNB-DU up") }
    })
    .await;
    assert!(up, "the gNB-DU did not complete F1 Setup (see {})", log.display());
}

#[given("the standalone gNB is running")]
async fn standalone_gnb_running(world: &mut World) {
    // The gNB and its DU (like the core) are host processes started once and reused across a
    // feature's scenarios — their bring-up is recorded in their persistent logs.
    let log = nf_log(&world.feature_tag, "gnb");
    assert!(
        netns::log_contains(&log, "NG Setup complete"),
        "the standalone gNB is not up (no NG Setup in {})",
        log.display()
    );
    let du_log = nf_log(&world.feature_tag, "du");
    assert!(
        netns::log_contains(&du_log, "gNB-DU up"),
        "the gNB-DU is not up (no F1 Setup in {})",
        du_log.display()
    );
}

#[when(regex = r#"^a UE camps on the gNB and registers from TAC "([0-9a-fA-F]{6})"$"#)]
async fn ue_camps_and_registers(world: &mut World, _tac: String) {
    // The UE opens an RRC connection (RRCSetupRequest → RRCSetup on SRB0) and sends its
    // Registration Request inside RRCSetupComplete on SRB1 — the gNB relays it as an
    // NGAP InitialUEMessage from its own cell's TAC.
    let mut ue_rrc = ran::UeRrc::camp(GNB_UU_ADDR.parse().unwrap()).await.expect("camp on the gNB Uu");
    let registration_request = ue_rrc.ue.registration_request();
    ue_rrc.rrc_connect(registration_request).await.expect("RRC connection + registration request");
    world.ue_rrc = Some(ue_rrc);
}

#[then("the gNB relays the AMF's 5G-AKA challenge to the UE")]
async fn gnb_relays_challenge(world: &mut World) {
    let nas = world.ue_rrc.as_mut().expect("UE camped").recv_nas().await.expect("the challenge downlink");
    assert!(
        nas::parse_authentication_request(&nas).is_some(),
        "expected an Authentication Request relayed through the gNB (in an RRC DLInformationTransfer)"
    );
    world.pending_nas = Some(nas);
}

#[when("the UE answers the challenge through the gNB")]
async fn ue_answers_through_gnb(world: &mut World) {
    let challenge = world.pending_nas.take().expect("a pending Authentication Request");
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    let reply = ue_rrc.ue.authenticate(&challenge).expect("the USIM answers");
    let response = match reply {
        ran::ChallengeReply::Response(bytes) => bytes,
        ran::ChallengeReply::SynchFailure(_) => panic!("the USIM unexpectedly failed synchronisation"),
    };
    ue_rrc.send_nas(response).await.expect("send RES* in an RRC ULInformationTransfer");
}

#[then("the gNB relays the NAS security mode command to the UE")]
async fn gnb_relays_smc(world: &mut World) {
    let smc = world.ue_rrc.as_mut().expect("UE camped").recv_nas().await.expect("the NAS security mode downlink");
    assert_eq!(
        smc.get(1),
        Some(&nas::sht::INTEGRITY_NEW_CONTEXT),
        "the NAS SMC is integrity-protected with a new context"
    );
    world.pending_nas = Some(smc);
}

#[when("the UE completes NAS security through the gNB")]
async fn ue_completes_security_through_gnb(world: &mut World) {
    let smc = world.pending_nas.take().expect("a pending NAS Security Mode Command");
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    let (nea, nia, _replayed, complete) =
        ue_rrc.ue.complete_security(&smc).expect("the UE derives its NAS + K_gNB keys");
    assert_eq!((nea, nia), (2, 2));
    ue_rrc.send_nas(complete).await.expect("send NAS Security Mode Complete");
    // K_gNB is now known — arm SRB1 AS integrity so the coming AS SecurityModeCommand verifies.
    ue_rrc.arm_as_security().expect("derive K_RRC and arm SRB1 integrity");
}

#[then("the gNB commands AS security over SRB1")]
async fn gnb_commands_as_security(world: &mut World) {
    // The gNB derived K_RRC from the K_gNB in the Initial Context Setup and sent an RRC
    // SecurityModeCommand on SRB1 (integrity-protected). The UE verifies it, activates
    // ciphering, and answers with SecurityModeComplete (integrity + ciphered).
    let (nea, nia) = world.ue_rrc.as_mut().expect("UE camped").complete_as_security().await.expect("AS security");
    assert_eq!((nea, nia), (2, 2), "the gNB selected NEA2/NIA2 for AS security");
}

#[then("the gNB relays the registration accept to the UE")]
async fn gnb_relays_accept(world: &mut World) {
    // Now over ciphered SRB1: the gNB delivers the Registration Accept the ICS carried.
    let accept = world.ue_rrc.as_mut().expect("UE camped").recv_nas().await.expect("the registration accept");
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    let msg = ue_rrc.ue.read_downlink(&accept).expect("the accept verifies at the UE");
    assert_eq!(nas::gmm_message_type(&msg), Some(nas::Nas5gmmMessageType::RegistrationAccept));
    world.ue_tmsi = nas::guti_tmsi_from_registration_accept(&msg);
    assert!(world.ue_tmsi.is_some(), "the accept assigns a 5G-GUTI");
}

#[when("the UE completes the registration through the gNB")]
async fn ue_completes_registration_through_gnb(world: &mut World) {
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    let complete = ue_rrc.ue.protected_uplink(&nas::registration_complete()).expect("protect RegistrationComplete");
    ue_rrc.send_nas(complete).await.expect("send RegistrationComplete");
}

#[then("the gNB relays a configuration update to the UE")]
async fn gnb_relays_config_update(world: &mut World) {
    let bytes = world.ue_rrc.as_mut().expect("UE camped").recv_nas().await.expect("the post-registration downlink");
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    let msg = ue_rrc.ue.read_downlink(&bytes).expect("the CUC verifies");
    assert_eq!(nas::gmm_message_type(&msg), Some(nas::Nas5gmmMessageType::ConfigurationUpdateCommand));
}

#[when("the UE requests a PDU session through the gNB")]
async fn ue_requests_pdu_through_gnb(world: &mut World) {
    let psi = 1u8;
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    let request = ue_rrc.ue.pdu_session_request(psi).expect("build the request");
    ue_rrc.send_nas(request).await.expect("send the PDU session request");
    world.pdu_psi = Some(psi);
}

#[then(regex = r#"^the UE is assigned an IP address in "([^"]+)" through the gNB$"#)]
async fn ue_assigned_ip_through_gnb(world: &mut World, subnet: String) {
    let accept = world.ue_rrc.as_mut().expect("UE camped").recv_nas().await.expect("the session accept");
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    let (psi, ip) = ue_rrc.ue.read_pdu_session_accept(&accept).expect("read the accept");
    assert_eq!(Some(psi), world.pdu_psi);
    let (net, prefix) = subnet.split_once('/').expect("subnet in CIDR form");
    let base: Ipv4Addr = net.parse().expect("valid subnet base");
    let bits: u32 = prefix.parse().expect("valid prefix length");
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    assert_eq!(u32::from(ip) & mask, u32::from(base) & mask, "assigned UE IP {ip} is not in {subnet}");
    // The session is up: establish the DRB (QFI 1, the default non-GBR flow the core uses).
    ue_rrc.establish_drb(psi, 1).expect("establish the DRB");
    world.ue_ip = Some(ip);
}

#[then(regex = r#"^the UE can reach the data network gateway "([^"]+)" through the gNB datapath$"#)]
async fn ue_reaches_dn_through_gnb(world: &mut World, gw: String) {
    let gw_ip: Ipv4Addr = gw.parse().expect("valid gateway IP");
    let ue_ip = world.ue_ip.expect("the UE has an assigned IP");
    let psi = world.pdu_psi.expect("a PDU session");
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    // The UE sends the ICMP echo up the DRB (SDAP header + ciphered PDCP); the gNB
    // deciphers it, strips SDAP, and encaps it (with QFI) to the UPF's N3. The reply
    // returns the same way — down the DRB — as a Data message.
    let mut reached = false;
    for seq in 1..=3u16 {
        let echo = datapath::icmp_echo_request(ue_ip, gw_ip, 0x4242, seq, b"radian-gnb-dp");
        ue_rrc.send_data(psi, echo).await.expect("send uplink data over the Uu");
        if let Some((got_psi, packet)) = ue_rrc.recv_data(2).await.expect("await a downlink data reply")
            && got_psi == psi
            && datapath::is_icmp_echo_reply(&packet, gw_ip, ue_ip)
        {
            reached = true;
            break;
        }
    }
    assert!(reached, "no ICMP echo reply returned through the gNB's N3/N6 datapath");
}

#[when("the UE goes idle and the gNB releases it")]
async fn ue_goes_idle_through_gnb(world: &mut World) {
    let ue_rrc = world.ue_rrc.as_mut().expect("UE camped");
    ue_rrc.go_idle().await.expect("send the idle indication over the Uu");
    // The gNB requests AN release; the AMF commands it; the gNB sends an RRCRelease on
    // SRB1 then the Uu released marker.
    ue_rrc.await_release().await.expect("the gNB releases the RRC connection");
}

#[then("the gNB pages the UE")]
async fn gnb_pages_ue(world: &mut World) {
    let tmsi = world.ue_tmsi.expect("the UE holds a 5G-TMSI");
    let paged = world.ue_rrc.as_ref().expect("UE camped").recv_paging().await.expect("the paging downlink");
    assert_eq!(paged, tmsi, "the gNB pages the UE's own 5G-TMSI");
}

#[when("I stop the standalone gNB and the radian core")]
async fn stop_gnb_and_core(_world: &mut World) {
    netns::kill_host_procs("target/debug/radian-du").await.expect("kill the gNB-DU");
    netns::kill_host_procs("target/debug/radian-gnb").await.expect("kill the standalone gNB");
    netns::kill_host_procs("target/debug/nf-").await.expect("kill radian core");
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
            if is_sim && !sim {
                return false;
            }
            // Optional local filter: `BDD_TAG=<tag>` runs only features carrying that
            // tag (e.g. `scripted_reg` — the loopback tier, no namespaces). Unset ⇒
            // run everything (CI behaviour).
            match std::env::var("BDD_TAG") {
                Ok(tag) if !tag.is_empty() => feature.tags.iter().any(|t| *t == tag),
                _ => true,
            }
        })
        .await;
}
