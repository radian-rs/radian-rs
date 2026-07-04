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
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use anyhow::Context;
use n6::tun::N6Tun;
use tracing::{info, trace, warn};

/// Process-start reference for the UPF's monotonic clock. Session-AMBR policers
/// (in `pfcp`/`n6`) are metered against `now_nanos()`, which both the N4 control
/// path (bucket rebasing) and the N3/N6 datapath share.
static START: LazyLock<Instant> = LazyLock::new(Instant::now);
fn now_nanos() -> u64 {
    START.elapsed().as_nanos() as u64
}

/// The UPF's N3/N4 address advertised to peers (the F-TEID address the gNB sends uplink
/// G-PDUs to). From `RADIAN_UPF_N3_ADDR`, default loopback.
const N3_ADDR_ENV: &str = "RADIAN_UPF_N3_ADDR";
/// The local address the N3/N4 sockets bind to. From `RADIAN_UPF_BIND`, default all
/// interfaces. Set to a specific loopback alias (e.g. 127.0.0.1) to coexist with a gNB
/// that also uses GTP-U port 2152 on the same host (bind it to a different alias).
const BIND_ENV: &str = "RADIAN_UPF_BIND";

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

    let node_ip: Ipv4Addr = std::env::var(N3_ADDR_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(Ipv4Addr::LOCALHOST);
    let bind = std::env::var(BIND_ENV).unwrap_or_else(|_| "0.0.0.0".to_string());

    let n4 = Arc::new(
        tokio::net::UdpSocket::bind(format!("{bind}:{}", pfcp::N4_PORT))
            .await
            .context("bind N4 PFCP")?,
    );
    let n3 = Arc::new(
        tokio::net::UdpSocket::bind(format!("{bind}:{}", gtpu::GTPU_PORT))
            .await
            .context("bind N3 GTP-U")?,
    );
    info!(%bind, %node_ip, n4_port = pfcp::N4_PORT, n3_port = gtpu::GTPU_PORT, "UPF up: N4 (PFCP) + N3 (GTP-U)");

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

    // The SMF's N4 address, learned from its PFCP requests — where UPF-initiated
    // Session Report Requests (threshold usage reports) are sent.
    let smf_addr: Arc<Mutex<Option<std::net::SocketAddr>>> = Arc::new(Mutex::new(None));

    let n4_task = tokio::spawn(serve_n4(n4.clone(), n3.clone(), node_ip, state.clone(), smf_addr.clone()));
    let n3_task = tokio::spawn(serve_n3(n3.clone(), state.clone(), tun.clone()));
    tokio::spawn(report_usage(n4, state.clone(), smf_addr));
    // Downlink only runs when N6 is live: it reads packets from the data network.
    if let Some(tun) = tun {
        tokio::spawn(serve_n6_downlink(tun, n3, state));
    }
    tokio::try_join!(n4_task, n3_task)?;
    Ok(())
}

/// N4: PFCP control plane (association, heartbeat, session establishment/modification).
async fn serve_n4(
    socket: Arc<tokio::net::UdpSocket>,
    n3: Arc<tokio::net::UdpSocket>,
    node_ip: Ipv4Addr,
    state: Upf,
    smf_addr: Arc<Mutex<Option<std::net::SocketAddr>>>,
) {
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
        // Remember the control plane's address for UPF-initiated reports.
        *smf_addr.lock().unwrap() = Some(peer);
        let (resp, flush) = {
            let mut g = state.lock().unwrap();
            let resp = pfcp::handle_n4(&buf[..n], node_ip, &mut g, now_nanos());
            (resp, g.take_flush())
        };
        // A re-activation (Service Request resume) flushes the packets buffered while
        // the UE was CM-IDLE onto its restored gNB tunnel.
        for (gnb_teid, gnb_ip, pkt) in flush {
            let dst = SocketAddrV4::new(gnb_ip, gtpu::GTPU_PORT);
            if let Err(e) = n3.send_to(&gtpu::encap(gnb_teid, &pkt), dst).await {
                warn!(%gnb_ip, "buffered-downlink flush send error: {e}");
            } else {
                info!(%gnb_ip, "flushed a buffered downlink packet to the resumed UE");
            }
        }
        match resp {
            Some(resp) => {
                if let Err(e) = socket.send_to(&resp, peer).await {
                    warn!(%peer, "N4 send error: {e}");
                } else {
                    let sessions = state.lock().unwrap().session_count();
                    info!(%peer, sessions, "handled N4 PFCP message");
                }
            }
            // The SMF's ack to a usage report we sent — nothing to answer.
            None if pfcp::is_session_report_ack(&buf[..n]) => {
                trace!(%peer, "usage report acknowledged by the SMF");
            }
            None => warn!(%peer, "unhandled or malformed N4 PFCP message"),
        }
    }
}

/// Threshold-triggered usage reporting (TS 29.244 §7.5.8): poll the session table
/// for crossed volume thresholds and send each due report to the SMF as a
/// **Session Report Request** — the quota-style charging trigger. Best-effort: the
/// report is sent once (the counters advance regardless); the SMF's ack lands in
/// the N4 loop.
async fn report_usage(
    socket: Arc<tokio::net::UdpSocket>,
    state: Upf,
    smf_addr: Arc<Mutex<Option<std::net::SocketAddr>>>,
) {
    let mut seq: u32 = 1;
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        tick.tick().await;
        loop {
            let due = { state.lock().unwrap().take_due_report() };
            let Some(due) = due else { break };
            let Some(smf) = *smf_addr.lock().unwrap() else {
                warn!("usage threshold crossed but no SMF address known — report dropped");
                break;
            };
            seq = seq.wrapping_add(1);
            let req = pfcp::session_report_request(&due, seq);
            match socket.send_to(&req, smf).await {
                Ok(_) => info!(
                    cp_seid = due.cp_seid,
                    total = due.usage.total,
                    ul = due.usage.uplink,
                    dl = due.usage.downlink,
                    "usage threshold crossed — Session Report Request sent to the SMF"
                ),
                Err(e) => warn!(%smf, "usage report send error: {e}"),
            }
        }
        // Downlink Data Reports: a buffering (CM-IDLE) session got downlink data →
        // tell the SMF to page the UE (TS 23.502 §4.2.3.3).
        loop {
            let cp_seid = { state.lock().unwrap().take_dl_data_report() };
            let Some(cp_seid) = cp_seid else { break };
            let Some(smf) = *smf_addr.lock().unwrap() else {
                warn!("downlink data for an idle UE but no SMF address known");
                break;
            };
            seq = seq.wrapping_add(1);
            let req = pfcp::session_report_request_dldr(cp_seid, seq);
            match socket.send_to(&req, smf).await {
                Ok(_) => info!(cp_seid, "downlink data for a CM-IDLE UE — Downlink Data Report sent (paging)"),
                Err(e) => warn!(%smf, "downlink data report send error: {e}"),
            }
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
                    let mut s = state.lock().unwrap();
                    n6::uplink(&mut s, teid, payload, now_nanos())
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
                    n6::Uplink::RateLimited => {
                        trace!(teid, "N3 uplink over session AMBR — policed (dropped)")
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
            let mut s = state.lock().unwrap();
            n6::downlink(&mut s, &buf[..n], now_nanos())
        };
        match action {
            n6::Downlink::ToN3 { gnb_ip, gpdu } => {
                let dst = SocketAddrV4::new(gnb_ip, gtpu::GTPU_PORT);
                match n3.send_to(&gpdu, dst).await {
                    Ok(_) => info!(%gnb_ip, bytes = n, "N6→N3 downlink forwarded"),
                    Err(e) => warn!(%gnb_ip, "N3 downlink send error: {e}"),
                }
            }
            // A CM-IDLE session buffered the packet; the reporter task pages the UE.
            n6::Downlink::Buffered => info!(bytes = n, "N6 downlink buffered for a CM-IDLE UE (paging triggered)"),
            // No session owns this destination / not IPv4 — background DN noise; don't spam.
            n6::Downlink::NoRoute => trace!("N6 downlink with no matching session — dropped"),
            n6::Downlink::NotIpv4 => trace!("N6 downlink not IPv4 — dropped"),
            n6::Downlink::RateLimited => trace!("N6 downlink over session AMBR — policed (dropped)"),
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
            &pfcp::session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("session established");
        if let Some((teid, ip)) = gnb {
            pfcp::handle_n4(
                &pfcp::session_modification_request(1, 2, 2, teid, ip, "internet", false),
                node_ip,
                &mut state,
                0,
            )
            .expect("session modified");
        }
        state
    }

    /// Uplink: a PFCP-established session's N3 TEID is recognized, and an uplink G-PDU on
    /// that TEID sourced from the UE's IP decaps and is forwarded to N6.
    #[test]
    fn n3_uplink_from_ue_forwards_to_n6() {
        let mut state = upf_with_session(None);
        assert!(state.knows_teid(1), "session owns the first allocated N3 TEID");

        // A UE-sourced IPv4 packet, GTP-U encapsulated on the uplink TEID.
        let mut inner = vec![0u8; 20];
        inner[0] = 0x45;
        inner[12..16].copy_from_slice(&UE_IP.octets()); // source = the UE
        let gpdu = gtpu::encap(1, &inner);
        let (teid, payload) = gtpu::decap(&gpdu).expect("uplink G-PDU");
        assert_eq!(n6::uplink(&mut state, teid, payload, 0), n6::Uplink::ToN6(&inner[..]));
    }

    /// Downlink: after the SMF installs the gNB F-TEID, a packet from N6 destined to the
    /// UE's IP is routed to that session and encapsulated toward the gNB tunnel.
    #[test]
    fn n6_downlink_routes_to_gnb_teid() {
        let gnb = (0x5678, Ipv4Addr::new(10, 0, 0, 9));
        let mut state = upf_with_session(Some(gnb));

        // A downlink IPv4 packet from the data network addressed to the UE.
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[16..20].copy_from_slice(&UE_IP.octets()); // destination = the UE
        match n6::downlink(&mut state, &pkt, 0) {
            n6::Downlink::ToN3 { gnb_ip, gpdu } => {
                assert_eq!(gnb_ip, gnb.1, "routed toward the session's gNB");
                assert_eq!(gtpu::decap(&gpdu), Some((gnb.0, &pkt[..])), "encapped to gNB TEID");
            }
            other => panic!("expected ToN3, got {other:?}"),
        }
    }
}
