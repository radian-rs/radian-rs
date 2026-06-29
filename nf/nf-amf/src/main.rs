//! AMF — Access and Mobility Management Function: **N2 (NGAP over SCTP) slice**.
//!
//! Terminates the N2 interface (TS 38.412 / 38.413): accepts gNB SCTP
//! associations, decodes NGAP PDUs, answers NG Setup, and drives the start of UE
//! registration — on receiving the UE's `RegistrationRequest` (in
//! `InitialUEMessage`) it replies with a NAS **Identity Request** (asking for the
//! SUCI) wrapped in `DownlinkNASTransport`. Subsequent uplink NAS is decoded and
//! logged.
//!
//! Scope of this slice: NG Setup + one downlink NAS round. Authentication
//! (AUSF/UDM over SBI) and the rest of the registration call flow are TODO.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
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

/// Receive loop for one gNB SCTP association.
async fn serve_gnb(conn: ConnectedSocket) -> anyhow::Result<()> {
    loop {
        match conn.sctp_recv().await? {
            NotificationOrData::Notification(n) => info!("SCTP notification: {n:?}"),
            NotificationOrData::Data(data) => {
                if data.payload.is_empty() {
                    info!("gNB association closed");
                    return Ok(());
                }
                handle_ngap(&conn, &data.payload).await;
            }
        }
    }
}

/// Decode one NGAP PDU and dispatch it.
async fn handle_ngap(conn: &ConnectedSocket, bytes: &[u8]) {
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
                match on_initial_ue(msg, amf_ue_id) {
                    Some(dl) => {
                        send_or_log(conn, &dl, "DownlinkNASTransport (IdentityRequest)").await
                    }
                    None => warn!("InitialUEMessage missing RAN-UE-NGAP-ID; cannot respond"),
                }
            }
            InitiatingMessageValue::Id_UplinkNASTransport(msg) => {
                log_nas("UplinkNASTransport", uplink_nas_pdu(msg));
            }
            _ => info!("unhandled initiating message: {}", pdu.procedure_name()),
        },
        _ => info!("unhandled PDU: {}", pdu.procedure_name()),
    }
}

/// Handle an `InitialUEMessage`: log the UE's NAS and, if the UE is addressable,
/// build the Identity Request downlink to send back. Pure (no I/O) so the
/// registration step is unit-testable.
fn on_initial_ue(msg: &InitialUEMessage, amf_ue_id: u64) -> Option<NGAP_PDU> {
    log_nas("InitialUEMessage", initial_ue_nas_pdu(msg));
    let ran_ue_id = initial_ue_ran_id(msg)?;
    let identity_request = nas::identity_request_suci();
    Some(ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, identity_request))
}

/// Decode and log a NAS payload, if present.
fn log_nas(carrier: &str, nas_bytes: Option<&[u8]>) {
    match nas_bytes {
        Some(bytes) => match nas::decode_nas_5gs_message(bytes) {
            Ok(nas) => info!("NAS in {carrier}: {nas}"),
            Err(e) => warn!("NAS decode failed ({carrier}): {e}"),
        },
        None => warn!("{carrier} without NAS-PDU"),
    }
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
    use nas::{Nas5gmmMessage, Nas5gsMessage};
    use ngap::DownlinkNASTransport;

    // RegistrationRequest sample (TS 24.501) from the oxirush-nas test vectors.
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

    #[test]
    fn initial_ue_message_nas_decodes_to_registration() {
        // Decode an InitialUEMessage off the wire exactly as the AMF does.
        let wire = initial_ue_message(1).encode().expect("APER encode");
        let decoded = NGAP_PDU::decode(&wire).expect("APER decode");
        let nas_bytes = initial_ue_nas_pdu(as_initial_ue(&decoded)).expect("NAS-PDU present");
        let nas = nas::decode_nas_5gs_message(nas_bytes).expect("NAS decode");
        assert!(
            matches!(nas, Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(_))),
            "unexpected NAS: {nas}"
        );
    }

    #[test]
    fn initial_ue_yields_identity_request_downlink() {
        let pdu = initial_ue_message(7);
        let dl = on_initial_ue(as_initial_ue(&pdu), 42).expect("expected a downlink response");

        // Round-trips through APER as a DownlinkNASTransport...
        let back = NGAP_PDU::decode(&dl.encode().expect("encode")).expect("decode");
        assert_eq!(back.procedure_name(), "DownlinkNASTransport");
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = &back else {
            unreachable!()
        };
        let InitiatingMessageValue::Id_DownlinkNASTransport(dl_msg) = value else {
            unreachable!()
        };

        // ...carrying a NAS IdentityRequest.
        let nas_bytes = downlink_nas_pdu(dl_msg).expect("NAS-PDU present");
        let nas = nas::decode_nas_5gs_message(nas_bytes).expect("NAS decode");
        assert!(
            matches!(nas, Nas5gsMessage::Gmm(_, Nas5gmmMessage::IdentityRequest(_))),
            "unexpected NAS: {nas}"
        );
    }

    fn downlink_nas_pdu(msg: &DownlinkNASTransport) -> Option<&[u8]> {
        use ngap::DownlinkNASTransportProtocolIEs_EntryValue as V;
        msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
            V::Id_NAS_PDU(nas) => Some(nas.0.as_slice()),
            _ => None,
        })
    }
}
