//! Netns-based BDD tests (cucumber, `harness = false`). Privileged (sudo), Linux-only —
//! run with `cargo test -p bdd`.
//!
//! Two features:
//! - `n6_datapath` — self-contained: the test plays SMF+gNB against a live `nf-upf` in a
//!   namespace and proves an ICMP echo round-trips N3↔N6.
//! - `datapath_e2e` (`@sim`) — the whole stack: the radian core plus the **free-ran-ue**
//!   simulator (gNB + UE) register, establish a PDU session, and ping the data network.
//!   Runs only when `FREE_RAN_UE_BIN` points at the simulator binary.

use std::net::{Ipv4Addr, SocketAddrV4};
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
    // scripted gNB/UE state (design/116 Tier B)
    gnb: Option<ran::ScriptedGnb>,
    ue: Option<ran::ScriptedUe>,
    amf_ue_id: Option<u64>,
    /// The last downlink NAS the gNB received, awaiting the UE's handling.
    pending_nas: Option<Vec<u8>>,
    /// The PDU session id the scripted UE established.
    pdu_psi: Option<u8>,
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
    // UPF needs CAP_NET_ADMIN for its N6 TUN → run under sudo; advertise the host N3 address.
    world.procs.push(spawn_core(&tag, true, &[("RADIAN_UPF_N3_ADDR", &HOST_IP.to_string())], "upf").await);
    assert!(wait_until(6, || netns::host_iface_exists("n6upf0")).await, "UPF N6 TUN did not come up");

    world.procs.push(
        spawn_core(&tag, false, &[("RADIAN_SMF_UPF_N4", "127.0.0.1:8805"), ("RADIAN_SMF_NRF", nrf)], "smf").await,
    );
    world.procs.push(spawn_core(&tag, false, &[], "amf").await);
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
    let (psi, upf_teid, _upf_addr, nas) = sessions.into_iter().next().expect("one PDU session");
    assert_eq!(Some(psi), world.pdu_psi);
    assert_ne!(upf_teid, 0, "the UPF allocated a non-zero uplink N3 F-TEID");
    // The gNB accepts the session, reporting its own DL F-TEID (→ the AMF installs
    // the downlink at the UPF via UpdateSMContext).
    gnb.send(&ngap::pdu_session_resource_setup_response(
        amf_ue_id,
        ran_ue_id,
        psi,
        1, // QFI of the default non-GBR flow
        SCRIPTED_GNB_DL_TEID,
        Ipv4Addr::LOCALHOST,
    ))
    .await
    .expect("send PDUSessionResourceSetupResponse");
    // Hold the relayed NAS-PDU (the accept) for the UE to read.
    world.pending_nas = Some(nas);
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
