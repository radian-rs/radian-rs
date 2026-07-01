//! Netns-based datapath BDD test (cucumber, `harness = false`).
//!
//! Runs a real `nf-upf` inside a network namespace with its N6 TUN, then plays the SMF and
//! gNB to push a crafted ICMP echo through the live N3/N6 user plane and confirm it returns.
//! Privileged (sudo) and Linux-only — run with `cargo test -p bdd`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bdd::{datapath, netns};
use cucumber::{given, then, when, World as CucumberWorld};

// The datapath test is @serial and single-feature, so fixed addresses are safe.
const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1); // our (SMF+gNB) end of the veth
const NS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2); // the UPF's end of the veth
const N3_PORT: u16 = 2152;
const N4_PORT: u16 = 8805;
const GNB_TEID: u32 = 0x1001; // the downlink F-TEID we install and expect on the reply

#[derive(Debug, Default, CucumberWorld)]
struct World {
    feature_tag: String,
    ue_ip: Option<Ipv4Addr>,
    uplink_teid: Option<u32>,
    ping_ok: bool,
}

impl World {
    fn ns(&self) -> String {
        format!("{}_upf", self.feature_tag)
    }
    fn host_veth(&self) -> String {
        // Keep under the 15-char interface-name limit.
        format!("hu_{}", self.feature_tag)
    }
}

/// Path to the `nf-upf` binary (override with `RADIANT_UPF_BIN`; default = workspace debug).
fn upf_bin() -> PathBuf {
    if let Ok(p) = std::env::var("RADIANT_UPF_BIN") {
        return PathBuf::from(p);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("target/debug/nf-upf")
}

#[given("a clean test environment")]
async fn clean_environment(world: &mut World) {
    assert!(!world.feature_tag.is_empty(), "feature must declare a tag for resource scoping");
    // Sweep anything a crashed prior run of this feature left behind.
    let prefix = format!("{}_", world.feature_tag);
    for ns in netns::list_netns_with_prefix(&prefix).await.unwrap_or_default() {
        let _ = netns::kill_netns_procs(&ns).await;
        let _ = netns::delete_netns(&ns).await;
    }
    let _ = netns::delete_veth(&world.host_veth()).await;
}

#[when("I set up the UPF namespace")]
async fn setup_namespace(world: &mut World) {
    let ns = world.ns();
    netns::create_netns(&ns).await.expect("create UPF namespace");
    netns::connect_host_to_netns(&ns, &world.host_veth(), "vupf", &HOST_IP.to_string(), &NS_IP.to_string())
        .await
        .expect("wire host<->UPF veth");
}

#[when("I start the UPF with its N6 TUN")]
async fn start_upf(world: &mut World) {
    let bin = upf_bin();
    assert!(bin.exists(), "nf-upf binary not found at {} — run `cargo build -p nf-upf`", bin.display());
    let ns = world.ns();
    // Bind all interfaces; advertise this namespace's veth IP as the N3 F-TEID address.
    netns::spawn_in_netns_env(&ns, &[("RADIANT_UPF_N3_ADDR", &NS_IP.to_string())], &bin.to_string_lossy(), &[])
        .await
        .expect("spawn nf-upf in namespace");
    // The UPF opens n6upf0 right after binding N3/N4; poll for it (up to 5s) as readiness.
    for _ in 0..50 {
        let up = tokio::process::Command::new("sudo")
            .args(["ip", "netns", "exec", &ns, "ip", "link", "show", "n6upf0"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if up {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("UPF N6 TUN (n6upf0) did not come up in namespace {ns}");
}

#[when(regex = r#"^I establish a PFCP session for UE "([^"]+)"$"#)]
async fn establish_session(world: &mut World, ue: String) {
    let ue_ip: Ipv4Addr = ue.parse().expect("valid UE IP");
    let upf_n4 = SocketAddrV4::new(NS_IP, N4_PORT);
    // Install our own veth IP as the downlink gNB F-TEID address, so the UPF sends the
    // downlink G-PDU back to us.
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

// ── teardown ──────────────────────────────────────────────────────────────────────────

#[given("the datapath topology exists")]
async fn topology_exists(world: &mut World) {
    assert!(netns::netns_exists(&world.ns()).await, "UPF namespace {} is not up", world.ns());
}

#[when("I stop the UPF")]
async fn stop_upf(world: &mut World) {
    netns::kill_netns_procs(&world.ns()).await.expect("kill UPF");
}

#[when("I delete the UPF namespace")]
async fn delete_namespace(world: &mut World) {
    netns::delete_netns(&world.ns()).await.expect("delete UPF namespace");
    netns::delete_veth(&world.host_veth()).await.expect("delete host veth");
}

#[then("the test environment should be clean")]
async fn verify_clean(world: &mut World) {
    let leftover = netns::list_netns_with_prefix(&format!("{}_", world.feature_tag)).await.unwrap_or_default();
    assert!(leftover.is_empty(), "namespaces still exist: {leftover:?}");
    println!("✓ Test environment is clean");
}

#[tokio::main]
async fn main() {
    World::cucumber()
        .max_concurrent_scenarios(1) // serial: the topology uses host-global namespaces
        .before(|feature, _rule, _scenario, world| {
            Box::pin(async move {
                world.feature_tag =
                    feature.tags.iter().find(|t| *t != "serial").cloned().unwrap_or_default();
            })
        })
        .fail_on_skipped()
        .run_and_exit("tests/features")
        .await;
}
