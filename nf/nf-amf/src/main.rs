//! AMF — Access and Mobility Management Function: **N2 (NGAP over SCTP) slice**.
//!
//! Terminates the N2 interface (TS 38.412 / 38.413): accepts gNB SCTP
//! associations, decodes NGAP PDUs, answers NG Setup, and decodes the NAS
//! payload carried in `InitialUEMessage` (the UE Registration Request).
//!
//! Scope of this slice: NG Setup + surfacing the UE registration's NAS. The SBI
//! services (Namf, TS 29.518) and the full registration call flow are TODO.

use std::net::SocketAddr;

use anyhow::Context;
use ngap::{
    InitialUEMessage, InitialUEMessageProtocolIEs_EntryValue, InitiatingMessage,
    InitiatingMessageValue, NGAP_PDU,
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
                match send_ngap(conn, &resp).await {
                    Ok(()) => info!("sent NGSetupResponse"),
                    Err(e) => error!("send NGSetupResponse failed: {e:#}"),
                }
            }
            InitiatingMessageValue::Id_InitialUEMessage(msg) => log_registration(msg),
            _ => info!("unhandled initiating message: {}", pdu.procedure_name()),
        },
        _ => info!("unhandled PDU: {}", pdu.procedure_name()),
    }
}

/// Decode and log the NAS payload (Registration Request) from an InitialUEMessage.
fn log_registration(msg: &InitialUEMessage) {
    match first_nas_pdu(msg) {
        Some(nas_bytes) => match nas::decode_nas_5gs_message(nas_bytes) {
            Ok(nas) => info!("NAS in InitialUEMessage: {nas}"),
            Err(e) => warn!("NAS decode failed: {e}"),
        },
        None => warn!("InitialUEMessage without NAS-PDU"),
    }
}

/// Find the first NAS-PDU IE in an InitialUEMessage.
fn first_nas_pdu(msg: &InitialUEMessage) -> Option<&[u8]> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        InitialUEMessageProtocolIEs_EntryValue::Id_NAS_PDU(nas) => Some(nas.0.as_slice()),
        _ => None,
    })
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

    // RegistrationRequest sample (TS 24.501) from the oxirush-nas test vectors.
    const REG_REQUEST_HEX: &str = "7e004179000d0199f9070000000000000010022e08a020000000000000";

    #[test]
    fn initial_ue_message_nas_decodes_to_registration() {
        let reg = hex::decode(REG_REQUEST_HEX).unwrap();
        let pdu = ngap::initial_ue_message_with_nas(1, reg);
        let wire = pdu.encode().expect("APER encode");

        // Decode exactly as the AMF does off the wire.
        let decoded = NGAP_PDU::decode(&wire).expect("APER decode");
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = &decoded else {
            panic!("expected InitiatingMessage");
        };
        let InitiatingMessageValue::Id_InitialUEMessage(msg) = value else {
            panic!("expected InitialUEMessage");
        };
        let nas_bytes = first_nas_pdu(msg).expect("NAS-PDU present");
        let nas = nas::decode_nas_5gs_message(nas_bytes).expect("NAS decode");
        assert!(
            format!("{nas}").contains("RegistrationRequest"),
            "unexpected NAS: {nas}"
        );
    }
}
