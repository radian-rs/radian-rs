//! UPF — User Plane Function. The one NF with **no SBI**: pure binary TLV.
//! Controlled over **N4 (PFCP)** via `pfcp`; forwards user traffic over
//! **N3/N9 (GTP-U)** via `gtpu`.
//!
//! Serves two UDP planes concurrently over a shared session table:
//! - **N4 (:8805)** — PFCP association / heartbeat / session establishment.
//! - **N3 (:2152)** — GTP-U Echo and uplink G-PDU decapsulation, routed to a
//!   known session by its allocated N3 TEID.
//!
//! Forwarding to N6 (a TUN/raw socket) and the downlink path are still TODO.
//!
//! # Security
//!
//! PFCP and GTP-U are both **unauthenticated** (TS 29.244 / 29.281) and rely on
//! trusted/isolated N4 and N3 networks (or IPsec per TS 33.501) — there is no
//! app-layer auth here. The listeners bind all interfaces for dev convenience;
//! deploy only on isolated user-plane segments. Hardening is a deferred slice.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use tracing::{info, warn};

const NODE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("upf");

    let state = Arc::new(Mutex::new(pfcp::UpfState::new()));

    let n4 = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", pfcp::N4_PORT))
        .await
        .context("bind N4 PFCP")?;
    let n3 = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", gtpu::GTPU_PORT))
        .await
        .context("bind N3 GTP-U")?;
    info!(n4_port = pfcp::N4_PORT, n3_port = gtpu::GTPU_PORT, "UPF up: N4 (PFCP) + N3 (GTP-U)");

    let n4_task = tokio::spawn(serve_n4(n4, state.clone()));
    let n3_task = tokio::spawn(serve_n3(n3, state.clone()));
    tokio::try_join!(n4_task, n3_task)?;
    Ok(())
}

/// N4: PFCP control plane (association, heartbeat, session establishment).
async fn serve_n4(socket: tokio::net::UdpSocket, state: Arc<Mutex<pfcp::UpfState>>) {
    let mut buf = vec![0u8; 2048];
    loop {
        // Per-datagram errors must not tear down the UPF: log and keep serving.
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("N4 recv error: {e}");
                continue;
            }
        };
        let resp = {
            let mut g = state.lock().unwrap();
            pfcp::handle_n4(&buf[..n], NODE_IP, &mut g)
        };
        match resp {
            Some(resp) => {
                if let Err(e) = socket.send_to(&resp, peer).await {
                    warn!(%peer, "N4 send error: {e}");
                } else {
                    let sessions = state.lock().unwrap().session_count();
                    info!(%peer, sessions, "handled N4 PFCP message");
                }
            }
            None => warn!(%peer, "unhandled or malformed N4 PFCP message"),
        }
    }
}

/// N3: GTP-U user plane (Echo path management + uplink G-PDU decapsulation).
async fn serve_n3(socket: tokio::net::UdpSocket, state: Arc<Mutex<pfcp::UpfState>>) {
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("N3 recv error: {e}");
                continue;
            }
        };
        match gtpu::parse(&buf[..n]) {
            Some(gtpu::N3Message::EchoRequest { sequence }) => {
                if let Err(e) = socket.send_to(&gtpu::echo_response(sequence), peer).await {
                    warn!(%peer, "N3 echo send error: {e}");
                }
            }
            Some(gtpu::N3Message::GPdu { teid, payload }) => {
                if state.lock().unwrap().knows_teid(teid) {
                    // Decapsulated uplink packet — would be forwarded to N6 (TODO: TUN).
                    info!(teid, bytes = payload.len(), "N3 uplink G-PDU decapped (→ N6, TODO)");
                } else {
                    warn!(teid, "N3 G-PDU for unknown TEID — dropped");
                }
            }
            other => warn!("N3: unhandled GTP-U message {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    /// Ties N4 to N3: a PFCP-established session's N3 TEID is recognized by the
    /// GTP-U datapath, and an uplink G-PDU on that TEID decaps to its inner packet.
    #[test]
    fn n3_uplink_recognizes_session_teid() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = pfcp::UpfState::new();
        let req = pfcp::session_establishment_request(0xCAFE, 1, node_ip);
        pfcp::handle_n4(&req, node_ip, &mut state).expect("session established");
        assert!(state.knows_teid(1), "session owns the first allocated N3 TEID");

        let inner = b"\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x01ping"; // fake IP packet
        let gpdu = gtpu::encap(1, inner);
        match gtpu::parse(&gpdu) {
            Some(gtpu::N3Message::GPdu { teid, payload }) => {
                assert_eq!(teid, 1);
                assert_eq!(payload, inner);
                assert!(state.knows_teid(teid), "UPF routes the uplink to a known session");
            }
            other => panic!("expected G-PDU, got {other:?}"),
        }
    }

    /// Ties N4 Session Modification to the N3 downlink: after the SMF installs the
    /// gNB's F-TEID, the UPF encapsulates a downlink packet toward that TEID.
    #[test]
    fn downlink_path_encaps_to_gnb_teid() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = pfcp::UpfState::new();
        pfcp::handle_n4(
            &pfcp::session_establishment_request(0xCAFE, 1, node_ip),
            node_ip,
            &mut state,
        )
        .expect("session established");
        let up_seid = 1; // first allocation

        // SMF installs the gNB downlink F-TEID via Session Modification.
        let gnb_ip = Ipv4Addr::new(10, 0, 0, 9);
        pfcp::handle_n4(
            &pfcp::session_modification_request(up_seid, 2, 1, 0x5678, gnb_ip),
            node_ip,
            &mut state,
        )
        .expect("session modified");

        let (gnb_teid, _ip) = state.downlink_for(up_seid).expect("downlink installed");
        assert_eq!(gnb_teid, 0x5678);

        // A downlink IP packet is encapsulated toward the gNB's TEID.
        let inner = b"downlink-ip-packet";
        match gtpu::parse(&gtpu::encap(gnb_teid, inner)) {
            Some(gtpu::N3Message::GPdu { teid, payload }) => {
                assert_eq!(teid, 0x5678);
                assert_eq!(payload, inner);
            }
            other => panic!("expected downlink G-PDU, got {other:?}"),
        }
    }
}
