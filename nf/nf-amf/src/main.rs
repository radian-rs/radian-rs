//! AMF — Access and Mobility Management Function: **N2 (NGAP over SCTP) slice**.
//!
//! Terminates the N2 interface (TS 38.412 / 38.413): accepts gNB SCTP
//! associations, decodes NGAP PDUs, answers NG Setup, and drives the start of UE
//! registration with **per-UE context**:
//!
//! * `InitialUEMessage` → decode the `RegistrationRequest`; if it already carries a
//!   SUCI the UE is identified, otherwise reply with a NAS **Identity Request**
//!   (`DownlinkNASTransport`).
//! * `UplinkNASTransport` → correlate to the UE by AMF-UE-NGAP-ID; an Identity
//!   Response completes identification.
//!
//! Context is keyed by AMF-UE-NGAP-ID and held per SCTP association. Authentication
//! (AUSF/UDM over SBI) and the rest of the registration call flow are TODO.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Allocator for AMF-UE-NGAP-IDs (one per UE the AMF takes context of).
static NEXT_AMF_UE_ID: AtomicU64 = AtomicU64::new(1);

/// Where a UE is in the (very partial) registration flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegState {
    /// Identity Request sent, awaiting the UE's Identity Response.
    IdentityRequested,
    /// SUCI known (from the RegistrationRequest or an Identity Response).
    Identified,
}

/// Per-UE context held by the AMF, keyed by AMF-UE-NGAP-ID.
#[derive(Debug)]
struct UeContext {
    amf_ue_id: u64,
    ran_ue_id: u32,
    state: RegState,
    suci: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("amf");

    let addr: SocketAddr = format!("0.0.0.0:{N2_PORT}").parse()?;
    let socket = Socket::new_v4(SocketToAssociation::OneToOne).context("create SCTP socket")?;
    socket.bind(addr).context("bind N2 SCTP")?;
    let listener = socket.listen(64).context("listen N2 SCTP")?;
    info!(%addr, ppid = NGAP_PPID, "N2 (NGAP/SCTP) listener up");

    loop {
        let (conn, peer) = listener.accept().await.context("accept SCTP association")?;
        info!(%peer, "gNB associated");
        tokio::spawn(async move {
            if let Err(e) = serve_gnb(conn).await {
                warn!("gNB session ended: {e:#}");
            }
        });
    }
}

/// Receive loop for one gNB SCTP association, owning that association's UE contexts.
async fn serve_gnb(conn: ConnectedSocket) -> anyhow::Result<()> {
    let mut ues: HashMap<u64, UeContext> = HashMap::new();
    loop {
        match conn.sctp_recv().await? {
            NotificationOrData::Notification(n) => info!("SCTP notification: {n:?}"),
            NotificationOrData::Data(data) => {
                if data.payload.is_empty() {
                    info!("gNB association closed");
                    return Ok(());
                }
                handle_ngap(&conn, &mut ues, &data.payload).await;
            }
        }
    }
}

/// Decode one NGAP PDU and dispatch it.
async fn handle_ngap(conn: &ConnectedSocket, ues: &mut HashMap<u64, UeContext>, bytes: &[u8]) {
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
                if let Some(dl) = on_initial_ue(ues, msg, amf_ue_id) {
                    send_or_log(conn, &dl, "DownlinkNASTransport (IdentityRequest)").await;
                }
            }
            InitiatingMessageValue::Id_UplinkNASTransport(msg) => {
                on_uplink_nas(ues, msg);
            }
            _ => info!("unhandled initiating message: {}", pdu.procedure_name()),
        },
        _ => info!("unhandled PDU: {}", pdu.procedure_name()),
    }
}

/// Handle an `InitialUEMessage`: create UE context, and either identify the UE from
/// the SUCI in its RegistrationRequest or return an Identity Request downlink to
/// send. Pure (no I/O) so the registration step is unit-testable.
fn on_initial_ue(
    ues: &mut HashMap<u64, UeContext>,
    msg: &InitialUEMessage,
    amf_ue_id: u64,
) -> Option<NGAP_PDU> {
    let ran_ue_id = initial_ue_ran_id(msg)?;
    let suci = initial_ue_nas_pdu(msg)
        .and_then(|b| nas::decode_nas_5gs_message(b).ok())
        .and_then(registration_suci);

    let (state, downlink) = match &suci {
        Some(s) => {
            info!("UE {amf_ue_id} identified from RegistrationRequest ({s}); authentication needs AUSF (TODO)");
            (RegState::Identified, None)
        }
        None => {
            info!("UE {amf_ue_id}: no usable identity in RegistrationRequest; sending Identity Request");
            let dl = ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, nas::identity_request_suci());
            (RegState::IdentityRequested, Some(dl))
        }
    };

    ues.insert(
        amf_ue_id,
        UeContext { amf_ue_id, ran_ue_id, state, suci },
    );
    downlink
}

/// Handle an `UplinkNASTransport`: correlate to a known UE by AMF-UE-NGAP-ID and
/// advance its state. Returns `true` if the UE was known. Pure, for testing.
fn on_uplink_nas(ues: &mut HashMap<u64, UeContext>, msg: &UplinkNASTransport) -> bool {
    let Some(amf_ue_id) = uplink_amf_ue_id(msg) else {
        warn!("UplinkNASTransport without AMF-UE-NGAP-ID");
        return false;
    };
    let decoded = uplink_nas_pdu(msg).and_then(|b| nas::decode_nas_5gs_message(b).ok());
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        warn!("uplink NAS for unknown UE {amf_ue_id}");
        return false;
    };

    match decoded {
        Some(m) => {
            // An Identity Response completes identification.
            if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::IdentityResponse(resp)) = &m {
                ctx.suci = resp.mobile_identity.as_suci().map(|s| suci_string(&s));
                ctx.state = RegState::Identified;
            }
            info!(
                "uplink NAS for UE {} (ran_ue_id={}, state={:?}, suci={:?}): {m}",
                ctx.amf_ue_id, ctx.ran_ue_id, ctx.state, ctx.suci
            );
        }
        None => warn!("UE {amf_ue_id}: uplink NAS-PDU missing or undecodable"),
    }
    true
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

    // RegistrationRequest sample (TS 24.501) from oxirush-nas — carries a SUCI for
    // PLMN MCC=999 MNC=70.
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

    #[test]
    fn initial_ue_message_nas_decodes_to_registration() {
        // Decode an InitialUEMessage off the wire exactly as the AMF does.
        let wire = initial_ue_message(1).encode().expect("APER encode");
        let decoded = NGAP_PDU::decode(&wire).expect("APER decode");
        let nas_bytes = initial_ue_nas_pdu(as_initial_ue(&decoded)).expect("NAS-PDU present");
        let msg = nas::decode_nas_5gs_message(nas_bytes).expect("NAS decode");
        assert!(
            matches!(msg, Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(_))),
            "unexpected NAS: {msg}"
        );
    }

    #[test]
    fn registration_with_suci_identifies_without_identity_request() {
        let mut ues = HashMap::new();
        let pdu = initial_ue_message(7);
        let dl = on_initial_ue(&mut ues, as_initial_ue(&pdu), 100);

        assert!(dl.is_none(), "SUCI present → no Identity Request");
        let ctx = ues.get(&100).expect("context created");
        assert_eq!(ctx.ran_ue_id, 7);
        assert_eq!(ctx.state, RegState::Identified);
        let suci = ctx.suci.as_deref().expect("SUCI stored");
        assert!(suci.contains("999-70"), "unexpected SUCI: {suci}");
    }

    #[test]
    fn unidentified_initial_ue_triggers_identity_request() {
        let mut ues = HashMap::new();
        // An InitialUEMessage whose NAS carries no usable SUCI (here: not a
        // RegistrationRequest) → the AMF asks for the identity.
        let pdu = ngap::initial_ue_message_with_nas(8, nas::identity_request_suci());
        let dl = on_initial_ue(&mut ues, as_initial_ue(&pdu), 200).expect("Identity Request downlink");
        assert_eq!(dl.procedure_name(), "DownlinkNASTransport");
        assert_eq!(ues.get(&200).unwrap().state, RegState::IdentityRequested);
    }

    #[test]
    fn uplink_nas_correlates_to_known_ue_only() {
        let mut ues = HashMap::new();
        on_initial_ue(&mut ues, as_initial_ue(&initial_ue_message(7)), 100);

        // Known AMF-UE-NGAP-ID → correlated.
        let known = ngap::uplink_nas_transport(100, 7, registration_request());
        assert!(on_uplink_nas(&mut ues, as_uplink(&known)));

        // Unknown AMF-UE-NGAP-ID → not correlated.
        let unknown = ngap::uplink_nas_transport(999, 7, registration_request());
        assert!(!on_uplink_nas(&mut ues, as_uplink(&unknown)));
    }
}
