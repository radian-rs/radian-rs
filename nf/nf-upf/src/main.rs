//! UPF — User Plane Function. The one NF with **no SBI**: pure binary TLV.
//! Controlled over **N4 (PFCP)** via `pfcp`; forwards user traffic between
//! **N3/N9 (GTP-U)** via `gtpu` and **N6** (the data network) via `n6`.
//!
//! Serves three planes over a shared session table:
//! - **N4 (:8805)** — PFCP association / heartbeat / session establishment / modification.
//! - **N3 (:2152)** — GTP-U: Echo, and **uplink** G-PDU decapsulation → forward to N6.
//! - **N6 (TUN)** — the data network: **downlink** IP packets routed by UE IP back to the
//!   owning session's gNB tunnel, and the sink for decapsulated uplink packets.
//!
//! The two forwarding decisions live in the `n6` crate as pure functions over the session
//! table; this binary is the I/O loop that drives them. The N6 device is a real Linux TUN,
//! which needs `CAP_NET_ADMIN`: the UPF opens it best-effort and, if it can't, keeps N3/N4
//! serving with user-plane forwarding disabled.
//!
//! # Security
//!
//! PFCP and GTP-U are both **unauthenticated** (TS 29.244 / 29.281) and rely on
//! trusted/isolated N4 and N3 networks (or IPsec per TS 33.501) — there is no
//! app-layer auth here. Uplink packets are anti-spoof checked (source must be the UE's
//! assigned IP) as defense-in-depth; the listeners bind all interfaces for dev
//! convenience — deploy only on isolated user-plane segments. Hardening is a deferred slice.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use n6::tun::N6Tun;
use tracing::{info, trace, warn};

const NODE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

// N6 (data network) TUN configuration. The UPF's own address sits inside the UE IP pool
// (10.45.0.0/16, allocated by the SMF — see nf-smf) so the kernel routes UE return traffic
// to this interface; .1 is the UPF's N6 gateway, UEs get .2 and up.
const N6_TUN_NAME: &str = "n6upf0";
const N6_UPF_ADDR: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 1);
const N6_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 0, 0);
const N6_MTU: u16 = 1400; // headroom under 1500 for the N3 GTP-U/UDP/IP outer headers

type Upf = Arc<Mutex<pfcp::UpfState>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("upf");

    let state: Upf = Arc::new(Mutex::new(pfcp::UpfState::new()));

    let n4 = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", pfcp::N4_PORT))
        .await
        .context("bind N4 PFCP")?;
    let n3 = Arc::new(
        tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", gtpu::GTPU_PORT))
            .await
            .context("bind N3 GTP-U")?,
    );
    info!(n4_port = pfcp::N4_PORT, n3_port = gtpu::GTPU_PORT, "UPF up: N4 (PFCP) + N3 (GTP-U)");

    // N6 is the privileged edge: opening a TUN needs CAP_NET_ADMIN. Degrade gracefully.
    let tun = match N6Tun::open(N6_TUN_NAME, N6_UPF_ADDR, N6_NETMASK, N6_MTU) {
        Ok(t) => {
            info!(tun = t.name(), addr = %N6_UPF_ADDR, "N6 up: TUN open — user-plane forwarding live");
            Some(Arc::new(t))
        }
        Err(e) => {
            warn!(
                "N6 TUN unavailable ({e}); user-plane forwarding disabled. Grant CAP_NET_ADMIN \
                 (run as root or `setcap cap_net_admin+ep <binary>`) to enable the N6 datapath."
            );
            None
        }
    };

    let n4_task = tokio::spawn(serve_n4(n4, state.clone()));
    let n3_task = tokio::spawn(serve_n3(n3.clone(), state.clone(), tun.clone()));
    // Downlink only runs when N6 is live: it reads packets from the data network.
    if let Some(tun) = tun {
        tokio::spawn(serve_n6_downlink(tun, n3, state));
    }
    tokio::try_join!(n4_task, n3_task)?;
    Ok(())
}

/// N4: PFCP control plane (association, heartbeat, session establishment/modification).
async fn serve_n4(socket: tokio::net::UdpSocket, state: Upf) {
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

/// N3: GTP-U user plane. Echo path management, plus **uplink** — decapsulate a G-PDU and,
/// after an anti-spoof check, forward the inner packet to N6 (the data network).
async fn serve_n3(socket: Arc<tokio::net::UdpSocket>, state: Upf, tun: Option<Arc<N6Tun>>) {
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
                // Decide against the session table, then release the lock before any await.
                let action = {
                    let s = state.lock().unwrap();
                    n6::uplink(&s, teid, payload)
                };
                match action {
                    n6::Uplink::ToN6(inner) => match &tun {
                        Some(tun) => match tun.send(inner).await {
                            Ok(()) => info!(teid, bytes = inner.len(), "N3→N6 uplink forwarded"),
                            Err(e) => warn!(teid, "N6 send error: {e}"),
                        },
                        None => info!(teid, bytes = inner.len(), "N3 uplink decapped (N6 disabled)"),
                    },
                    n6::Uplink::UnknownTeid => warn!(teid, "N3 G-PDU for unknown TEID — dropped"),
                    n6::Uplink::Spoofed { claimed, assigned } => {
                        warn!(teid, %claimed, %assigned, "N3 uplink source spoofing — dropped")
                    }
                }
            }
            other => warn!("N3: unhandled GTP-U message {other:?}"),
        }
    }
}

/// N6: read downlink IP packets from the data network, route each by destination UE IP to
/// the owning session, and encapsulate it toward that session's gNB tunnel on N3.
async fn serve_n6_downlink(tun: Arc<N6Tun>, n3: Arc<tokio::net::UdpSocket>, state: Upf) {
    let mut buf = vec![0u8; 2048];
    loop {
        let n = match tun.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!("N6 recv error: {e}");
                continue;
            }
        };
        let action = {
            let s = state.lock().unwrap();
            n6::downlink(&s, &buf[..n])
        };
        match action {
            n6::Downlink::ToN3 { gnb_ip, gpdu } => {
                let dst = SocketAddrV4::new(gnb_ip, gtpu::GTPU_PORT);
                match n3.send_to(&gpdu, dst).await {
                    Ok(_) => info!(%gnb_ip, bytes = n, "N6→N3 downlink forwarded"),
                    Err(e) => warn!(%gnb_ip, "N3 downlink send error: {e}"),
                }
            }
            // No session owns this destination / not IPv4 — background DN noise; don't spam.
            n6::Downlink::NoRoute => trace!("N6 downlink with no matching session — dropped"),
            n6::Downlink::NotIpv4 => trace!("N6 downlink not IPv4 — dropped"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    const UE_IP: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);

    /// Establish a session through the real N4 path (UPF allocates the N3 TEID) and, if
    /// `gnb` is given, install the downlink target via Session Modification.
    fn upf_with_session(gnb: Option<(u32, Ipv4Addr)>) -> pfcp::UpfState {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = pfcp::UpfState::new();
        pfcp::handle_n4(
            &pfcp::session_establishment_request(0xCAFE, 1, node_ip, UE_IP),
            node_ip,
            &mut state,
        )
        .expect("session established");
        if let Some((teid, ip)) = gnb {
            pfcp::handle_n4(
                &pfcp::session_modification_request(1, 2, 2, teid, ip),
                node_ip,
                &mut state,
            )
            .expect("session modified");
        }
        state
    }

    /// Uplink: a PFCP-established session's N3 TEID is recognized, and an uplink G-PDU on
    /// that TEID sourced from the UE's IP decaps and is forwarded to N6.
    #[test]
    fn n3_uplink_from_ue_forwards_to_n6() {
        let state = upf_with_session(None);
        assert!(state.knows_teid(1), "session owns the first allocated N3 TEID");

        // A UE-sourced IPv4 packet, GTP-U encapsulated on the uplink TEID.
        let mut inner = vec![0u8; 20];
        inner[0] = 0x45;
        inner[12..16].copy_from_slice(&UE_IP.octets()); // source = the UE
        let gpdu = gtpu::encap(1, &inner);
        let (teid, payload) = gtpu::decap(&gpdu).expect("uplink G-PDU");
        assert_eq!(n6::uplink(&state, teid, payload), n6::Uplink::ToN6(&inner[..]));
    }

    /// Downlink: after the SMF installs the gNB F-TEID, a packet from N6 destined to the
    /// UE's IP is routed to that session and encapsulated toward the gNB tunnel.
    #[test]
    fn n6_downlink_routes_to_gnb_teid() {
        let gnb = (0x5678, Ipv4Addr::new(10, 0, 0, 9));
        let state = upf_with_session(Some(gnb));

        // A downlink IPv4 packet from the data network addressed to the UE.
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[16..20].copy_from_slice(&UE_IP.octets()); // destination = the UE
        match n6::downlink(&state, &pkt) {
            n6::Downlink::ToN3 { gnb_ip, gpdu } => {
                assert_eq!(gnb_ip, gnb.1, "routed toward the session's gNB");
                assert_eq!(gtpu::decap(&gpdu), Some((gnb.0, &pkt[..])), "encapped to gNB TEID");
            }
            other => panic!("expected ToN3, got {other:?}"),
        }
    }
}
