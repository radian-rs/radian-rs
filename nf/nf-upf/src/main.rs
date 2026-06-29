//! UPF — User Plane Function. The one NF with **no SBI**: pure binary TLV.
//! Controlled over **N4 (PFCP)** via `pfcp`; forwards user traffic over
//! **N3/N9 (GTP-U)** via `gtpu`.
//!
//! This slice serves N4 PFCP: node-level Association/Heartbeat and **session
//! establishment** (allocating an N3 F-TEID). The GTP-U datapath is still TODO.
//!
//! # Security
//!
//! PFCP is **unauthenticated** (TS 29.244) and relies on a trusted/isolated N4
//! network (or IPsec per TS 33.501) — there is no app-layer auth here. The listener
//! binds all interfaces for dev convenience; deploy it only on an isolated N4
//! segment. Hardening (IPsec / bind to the N4 address) is a deferred slice.

use std::net::Ipv4Addr;

use anyhow::Context;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("upf");

    // TODO: GTP-U (N3/N9) datapath; PFCP session modification/deletion.
    let node_ip = Ipv4Addr::new(127, 0, 0, 1);
    let addr = format!("0.0.0.0:{}", pfcp::N4_PORT);
    let socket = tokio::net::UdpSocket::bind(&addr)
        .await
        .with_context(|| format!("bind N4 PFCP on {addr}"))?;
    info!(%addr, "N4 (PFCP/UDP) listener up");

    let mut state = pfcp::UpfState::new();
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
        match pfcp::handle_n4(&buf[..n], node_ip, &mut state) {
            Some(resp) => {
                if let Err(e) = socket.send_to(&resp, peer).await {
                    warn!(%peer, "N4 send error: {e}");
                } else {
                    info!(%peer, sessions = state.session_count(), "handled N4 PFCP message");
                }
            }
            None => warn!(%peer, "unhandled or malformed N4 PFCP message"),
        }
    }
}
