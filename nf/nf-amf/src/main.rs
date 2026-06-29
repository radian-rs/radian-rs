//! AMF — Access and Mobility Management Function: **N2 + authentication slice**.
//!
//! Terminates N2 (NGAP/SCTP, TS 38.413) and drives UE registration into 5G-AKA,
//! joining the N2 (binary) and SBI (JSON) planes:
//!
//! * `InitialUEMessage` → identify the UE from the RegistrationRequest SUCI (or ask
//!   for identity), then discover the AUSF via the NRF, run `Nausf` to get a
//!   challenge, and send a NAS **Authentication Request** over N2.
//! * `UplinkNASTransport` → an **Authentication Response** is verified (SEAF HRES*
//!   check) and confirmed with the AUSF; on success the AMF holds K_SEAF.
//!
//! Per-UE context is keyed by AMF-UE-NGAP-ID, held per SCTP association. Security
//! Mode Command and Registration Accept are the next steps (TODO).

mod auth;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Context;
use nas::{Nas5gmmMessage, Nas5gsMessage, Suci};
use ngap::{
    InitialUEMessage, InitialUEMessageProtocolIEs_EntryValue, InitiatingMessage,
    InitiatingMessageValue, NGAP_PDU, UplinkNASTransport, UplinkNASTransportProtocolIEs_EntryValue,
};
use sctp_rs::{
    ConnectedSocket, NotificationOrData, SendData, SendInfo, Socket, SocketToAssociation,
};
use tracing::{error, info, warn};

/// SCTP Payload Protocol Identifier for NGAP (TS 38.412 §7).
const NGAP_PPID: u32 = 60;
/// Default N2 SCTP port (TS 38.412).
const N2_PORT: u16 = 38412;

const AMF_NAME: &str = "radiant-amf";
const PLMN_MCC: &str = "999";
const PLMN_MNC: &str = "70";
/// NRF the AMF uses to discover the AUSF.
const NRF_BASE: &str = "http://127.0.0.1:8000";

/// Allocator for AMF-UE-NGAP-IDs (one per UE the AMF takes context of).
static NEXT_AMF_UE_ID: AtomicU64 = AtomicU64::new(1);

/// Where a UE is in the (partial) registration flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegState {
    IdentityRequested,
    Identified,
    Authenticating,
    Authenticated,
}

/// Per-UE context held by the AMF, keyed by AMF-UE-NGAP-ID.
#[derive(Debug)]
struct UeContext {
    ran_ue_id: u32,
    state: RegState,
    suci: Option<String>,
    auth: Option<auth::PendingAuth>,
    kseaf: Option<String>,
}

/// What an `InitialUEMessage` asks the AMF to do next.
enum InitialUeOutcome {
    /// Send this Identity Request downlink (no usable identity yet).
    NeedIdentity(NGAP_PDU),
    /// UE is identified — start authentication for this SUPI.
    Identified { ran_ue_id: u32, supi: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("amf");

    let amf_auth = Arc::new(auth::AmfAuth::new(NRF_BASE, PLMN_MCC, PLMN_MNC));

    let addr: SocketAddr = format!("0.0.0.0:{N2_PORT}").parse()?;
    let socket = Socket::new_v4(SocketToAssociation::OneToOne).context("create SCTP socket")?;
    socket.bind(addr).context("bind N2 SCTP")?;
    let listener = socket.listen(64).context("listen N2 SCTP")?;
    info!(%addr, ppid = NGAP_PPID, nrf = NRF_BASE, "N2 (NGAP/SCTP) listener up");

    loop {
        let (conn, peer) = listener.accept().await.context("accept SCTP association")?;
        info!(%peer, "gNB associated");
        let amf_auth = amf_auth.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_gnb(conn, amf_auth).await {
                warn!("gNB session ended: {e:#}");
            }
        });
    }
}

/// Receive loop for one gNB SCTP association, owning that association's UE contexts.
async fn serve_gnb(conn: ConnectedSocket, amf_auth: Arc<auth::AmfAuth>) -> anyhow::Result<()> {
    let mut ues: HashMap<u64, UeContext> = HashMap::new();
    loop {
        match conn.sctp_recv().await? {
            NotificationOrData::Notification(n) => info!("SCTP notification: {n:?}"),
            NotificationOrData::Data(data) => {
                if data.payload.is_empty() {
                    info!("gNB association closed");
                    return Ok(());
                }
                handle_ngap(&conn, &mut ues, &amf_auth, &data.payload).await;
            }
        }
    }
}

/// Decode one NGAP PDU and dispatch it.
async fn handle_ngap(
    conn: &ConnectedSocket,
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    bytes: &[u8],
) {
    let pdu = match NGAP_PDU::decode(bytes) {
        Ok(p) => p,
        Err(e) => {
            error!("NGAP decode failed: {e:?}");
            return;
        }
    };
    info!("recv {pdu}");

    match &pdu {
        NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) => match value {
            InitiatingMessageValue::Id_NGSetup(_req) => {
                let resp = ngap::ng_setup_response(AMF_NAME, PLMN_MCC, PLMN_MNC);
                send_or_log(conn, &resp, "NGSetupResponse").await;
            }
            InitiatingMessageValue::Id_InitialUEMessage(msg) => {
                let amf_ue_id = NEXT_AMF_UE_ID.fetch_add(1, Ordering::Relaxed);
                match on_initial_ue(ues, msg, amf_ue_id) {
                    Some(InitialUeOutcome::NeedIdentity(dl)) => {
                        send_or_log(conn, &dl, "DownlinkNASTransport (IdentityRequest)").await;
                    }
                    Some(InitialUeOutcome::Identified { ran_ue_id, supi }) => {
                        start_authentication(conn, ues, amf_auth, amf_ue_id, ran_ue_id, &supi).await;
                    }
                    None => warn!("InitialUEMessage missing RAN-UE-NGAP-ID; cannot respond"),
                }
            }
            InitiatingMessageValue::Id_UplinkNASTransport(msg) => {
                on_uplink_nas(ues, amf_auth, msg).await;
            }
            _ => info!("unhandled initiating message: {}", pdu.procedure_name()),
        },
        _ => info!("unhandled PDU: {}", pdu.procedure_name()),
    }
}

/// Identify the UE and create its context. Returns what to do next.
fn on_initial_ue(
    ues: &mut HashMap<u64, UeContext>,
    msg: &InitialUEMessage,
    amf_ue_id: u64,
) -> Option<InitialUeOutcome> {
    let ran_ue_id = initial_ue_ran_id(msg)?;
    let suci = initial_ue_nas_pdu(msg)
        .and_then(|b| nas::decode_nas_5gs_message(b).ok())
        .and_then(registration_suci);

    match suci {
        Some(supi) => {
            ues.insert(
                amf_ue_id,
                UeContext {
                    ran_ue_id,
                    state: RegState::Identified,
                    suci: Some(supi.clone()),
                    auth: None,
                    kseaf: None,
                },
            );
            Some(InitialUeOutcome::Identified { ran_ue_id, supi })
        }
        None => {
            ues.insert(
                amf_ue_id,
                UeContext {
                    ran_ue_id,
                    state: RegState::IdentityRequested,
                    suci: None,
                    auth: None,
                    kseaf: None,
                },
            );
            let dl = ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, nas::identity_request_suci());
            Some(InitialUeOutcome::NeedIdentity(dl))
        }
    }
}

/// Discover the AUSF, fetch a challenge, and send the NAS Authentication Request.
async fn start_authentication(
    conn: &ConnectedSocket,
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_ue_id: u64,
    ran_ue_id: u32,
    supi: &str,
) {
    info!("UE {amf_ue_id} identified ({supi}); starting authentication");
    match amf_auth.begin(supi).await {
        Ok((pending, nas_req)) => {
            if let Some(ctx) = ues.get_mut(&amf_ue_id) {
                ctx.auth = Some(pending);
                ctx.state = RegState::Authenticating;
            }
            let dl = ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, nas_req);
            send_or_log(conn, &dl, "DownlinkNASTransport (AuthenticationRequest)").await;
        }
        Err(e) => warn!("UE {amf_ue_id}: authentication start failed: {e}"),
    }
}

/// Correlate an uplink NAS message to its UE and, if it's an Authentication
/// Response, complete authentication. Returns `true` if the UE was known.
async fn on_uplink_nas(
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    msg: &UplinkNASTransport,
) -> bool {
    let Some(amf_ue_id) = uplink_amf_ue_id(msg) else {
        warn!("UplinkNASTransport without AMF-UE-NGAP-ID");
        return false;
    };
    if !ues.contains_key(&amf_ue_id) {
        warn!("uplink NAS for unknown UE {amf_ue_id}");
        return false;
    }
    let Some(nas_msg) = uplink_nas_pdu(msg).and_then(|b| nas::decode_nas_5gs_message(b).ok()) else {
        warn!("UE {amf_ue_id}: undecodable uplink NAS-PDU");
        return true;
    };

    match nas::res_star_from_authentication_response(&nas_msg).map(<[u8]>::to_vec) {
        Some(res_star) => complete_authentication(ues, amf_auth, amf_ue_id, &res_star).await,
        None => info!("UE {amf_ue_id}: uplink NAS {nas_msg}"),
    }
    true
}

/// Verify the UE's RES* with the AUSF and record K_SEAF on success.
async fn complete_authentication(
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_ue_id: u64,
    res_star: &[u8],
) {
    let Some(pending) = ues.get_mut(&amf_ue_id).and_then(|c| c.auth.take()) else {
        warn!("UE {amf_ue_id}: Authentication Response with no pending authentication");
        return;
    };

    match amf_auth.finish(&pending, res_star).await {
        Ok(outcome) if outcome.success => {
            if let Some(ctx) = ues.get_mut(&amf_ue_id) {
                ctx.state = RegState::Authenticated;
                ctx.kseaf = outcome.kseaf;
                info!(
                    "UE {amf_ue_id} authenticated (ran_ue_id={}, suci={:?}, state={:?}, kseaf_set={}); \
                     registration would proceed to Security Mode (TODO)",
                    ctx.ran_ue_id,
                    ctx.suci,
                    ctx.state,
                    ctx.kseaf.is_some(),
                );
            }
        }
        Ok(_) => warn!("UE {amf_ue_id}: authentication failed (RES* rejected)"),
        Err(e) => warn!("UE {amf_ue_id}: authentication confirm failed: {e}"),
    }
}

/// Extract the SUCI (if any) from a decoded NAS RegistrationRequest.
fn registration_suci(msg: Nas5gsMessage) -> Option<String> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = msg else {
        return None;
    };
    reg.fgs_mobile_identity.as_suci().map(|s| suci_string(&s))
}

/// Render a parsed SUCI as the canonical `suci-0-<mcc>-<mnc>-...` text form.
fn suci_string(s: &Suci) -> String {
    fn digits(d: &[u8]) -> String {
        d.iter().filter(|&&n| n <= 9).map(|n| char::from(b'0' + n)).collect()
    }
    fn hex_lower(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
        out
    }
    format!(
        "suci-0-{}-{}-{}-{}-{}-{}",
        digits(&s.mcc),
        digits(&s.mnc),
        hex_lower(&s.routing_indicator),
        s.protection_scheme,
        s.home_nw_public_key_id,
        hex_lower(&s.scheme_output),
    )
}

fn initial_ue_nas_pdu(msg: &InitialUEMessage) -> Option<&[u8]> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        InitialUEMessageProtocolIEs_EntryValue::Id_NAS_PDU(nas) => Some(nas.0.as_slice()),
        _ => None,
    })
}

fn initial_ue_ran_id(msg: &InitialUEMessage) -> Option<u32> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        InitialUEMessageProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(id) => Some(id.0),
        _ => None,
    })
}

fn uplink_nas_pdu(msg: &UplinkNASTransport) -> Option<&[u8]> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        UplinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(nas) => Some(nas.0.as_slice()),
        _ => None,
    })
}

fn uplink_amf_ue_id(msg: &UplinkNASTransport) -> Option<u64> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        UplinkNASTransportProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => Some(id.0),
        _ => None,
    })
}

/// APER-encode and send an NGAP PDU, logging success/failure under `label`.
async fn send_or_log(conn: &ConnectedSocket, pdu: &NGAP_PDU, label: &str) {
    match send_ngap(conn, pdu).await {
        Ok(()) => info!("sent {label}"),
        Err(e) => error!("send {label} failed: {e:#}"),
    }
}

/// APER-encode an NGAP PDU and send it on the association with the NGAP PPID.
async fn send_ngap(conn: &ConnectedSocket, pdu: &NGAP_PDU) -> anyhow::Result<()> {
    let payload = pdu
        .encode()
        .map_err(|e| anyhow::anyhow!("NGAP encode failed: {e:?}"))?;
    conn.sctp_send(SendData {
        payload,
        snd_info: Some(SendInfo {
            ppid: NGAP_PPID,
            ..Default::default()
        }),
    })
    .await
    .context("sctp_send")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const REG_REQUEST_HEX: &str = "7e004179000d0199f9070000000000000010022e08a020000000000000";

    fn registration_request() -> Vec<u8> {
        hex::decode(REG_REQUEST_HEX).unwrap()
    }

    fn initial_ue_message(ran_ue_id: u32) -> NGAP_PDU {
        ngap::initial_ue_message_with_nas(ran_ue_id, registration_request())
    }

    fn as_initial_ue(pdu: &NGAP_PDU) -> &InitialUEMessage {
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
            panic!("expected InitiatingMessage");
        };
        let InitiatingMessageValue::Id_InitialUEMessage(msg) = value else {
            panic!("expected InitialUEMessage");
        };
        msg
    }

    fn as_uplink(pdu: &NGAP_PDU) -> &UplinkNASTransport {
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
            panic!("expected InitiatingMessage");
        };
        let InitiatingMessageValue::Id_UplinkNASTransport(msg) = value else {
            panic!("expected UplinkNASTransport");
        };
        msg
    }

    fn test_subscriber() -> aka::SubscriberKey {
        aka::SubscriberKey {
            k: hex!("465b5ce8b199b49faa5f0a2ee238a6bc"),
            opc: hex!("cd63cb71954a9f4e48a5994e37a02baf"),
            amf: hex!("8000"),
        }
    }

    #[test]
    fn registration_with_suci_is_identified() {
        let mut ues = HashMap::new();
        let pdu = initial_ue_message(7);
        let outcome = on_initial_ue(&mut ues, as_initial_ue(&pdu), 100);
        match outcome {
            Some(InitialUeOutcome::Identified { ran_ue_id, supi }) => {
                assert_eq!(ran_ue_id, 7);
                assert!(supi.contains("999-70"), "unexpected SUPI: {supi}");
            }
            _ => panic!("expected Identified"),
        }
        assert_eq!(ues.get(&100).unwrap().state, RegState::Identified);
    }

    #[test]
    fn unidentified_initial_ue_needs_identity() {
        let mut ues = HashMap::new();
        // NAS that is not a RegistrationRequest → no SUCI → ask for identity.
        let pdu = ngap::initial_ue_message_with_nas(8, nas::identity_request_suci());
        match on_initial_ue(&mut ues, as_initial_ue(&pdu), 200) {
            Some(InitialUeOutcome::NeedIdentity(dl)) => {
                assert_eq!(dl.procedure_name(), "DownlinkNASTransport");
            }
            _ => panic!("expected NeedIdentity"),
        }
        assert_eq!(ues.get(&200).unwrap().state, RegState::IdentityRequested);
    }

    #[tokio::test]
    async fn uplink_nas_correlates_to_known_ue_only() {
        let mut ues = HashMap::new();
        on_initial_ue(&mut ues, as_initial_ue(&initial_ue_message(7)), 100);
        // NRF base is unused: a RegistrationRequest uplink isn't an Auth Response.
        let amf_auth = auth::AmfAuth::new("http://127.0.0.1:1", "999", "70");

        let known = ngap::uplink_nas_transport(100, 7, registration_request());
        assert!(on_uplink_nas(&mut ues, &amf_auth, as_uplink(&known)).await);

        let unknown = ngap::uplink_nas_transport(999, 7, registration_request());
        assert!(!on_uplink_nas(&mut ues, &amf_auth, as_uplink(&unknown)).await);
    }

    /// The payoff: discover AUSF via NRF, run 5G-AKA, confirm RES* → K_SEAF.
    #[tokio::test]
    async fn authenticated_registration_over_sbi() {
        use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, NrfClient, NrfStore};

        let supi = "imsi-999700000000001";
        let sub = test_subscriber();

        // Spin NRF, UDM (with the subscriber), and AUSF (pointed at the UDM).
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        tokio::spawn(async move {
            sbi_core::run_on(nrf_l, sbi_core::nnrf::router(NrfStore::default())).await.unwrap()
        });

        let db = sbi_core::nudm::SubscriberDb::new();
        db.insert(supi, sub.clone());
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udm_l, sbi_core::nudm::router(db)).await.unwrap() });

        let ausf_state = sbi_core::nausf::AusfState::new(format!("http://{udm_addr}"));
        let ausf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ausf_addr = ausf_l.local_addr().unwrap();
        tokio::spawn(async move {
            sbi_core::run_on(ausf_l, sbi_core::nausf::router(ausf_state)).await.unwrap()
        });

        // Register the AUSF (with its service endpoint) in the NRF.
        let mut profile = NfProfile::new("ausf-1", "AUSF", ausf_addr.ip().to_string());
        profile.nf_services = Some(vec![NfService {
            service_instance_id: "nausf-auth-1".into(),
            service_name: "nausf-auth".into(),
            scheme: "http".into(),
            ip_end_points: vec![IpEndPoint {
                ipv4_address: Some(ausf_addr.ip().to_string()),
                port: Some(ausf_addr.port()),
            }],
        }]);
        NrfClient::new(format!("http://{nrf_addr}")).register(&profile).await.unwrap();

        // AMF: discover AUSF via NRF, begin authentication → NAS Authentication Request.
        let amf_auth = auth::AmfAuth::new(format!("http://{nrf_addr}"), "999", "70");
        let (pending, nas_req) = amf_auth.begin(supi).await.expect("begin authentication");

        // UE: parse the challenge, compute RES*, build the Authentication Response.
        let (rand, autn) = nas::parse_authentication_request(&nas_req).expect("parse challenge");
        let res_star = aka::ue_compute_res_star(&sub, &rand, &autn, "999", "70").unwrap();
        let nas_resp = nas::authentication_response(&res_star);
        let decoded = nas::decode_nas_5gs_message(&nas_resp).unwrap();
        let res = nas::res_star_from_authentication_response(&decoded).unwrap();

        // AMF: SEAF-verify + confirm with the AUSF.
        let outcome = amf_auth.finish(&pending, res).await.expect("finish authentication");
        assert!(outcome.success, "authentication should succeed");
        assert!(outcome.kseaf.is_some(), "K_SEAF derived");
    }
}
