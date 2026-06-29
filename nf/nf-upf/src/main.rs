//! UPF — User Plane Function. The one NF with **no SBI**: pure binary TLV.
//! Controlled over **N4 (PFCP)** via `pfcp`; forwards user traffic over
//! **N3/N9 (GTP-U)** via `gtpu`.
//!
//! This slice brings up the N4 PFCP endpoint: it answers node-level Association
//! Setup and Heartbeat. PFCP session establishment and the GTP-U datapath are TODO.

use std::net::Ipv4Addr;

use anyhow::Context;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("upf");

    // TODO: PFCP session establishment (PDRs/FARs/F-TEID); GTP-U (N3/N9) datapath.
    let node_ip = Ipv4Addr::new(127, 0, 0, 1);
    let addr = format!("0.0.0.0:{}", pfcp::N4_PORT);
    let socket = tokio::net::UdpSocket::bind(&addr)
        .await
        .with_context(|| format!("bind N4 PFCP on {addr}"))?;
    info!(%addr, "N4 (PFCP/UDP) listener up");

    let mut buf = vec![0u8; 2048];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await.context("recv N4")?;
        match pfcp::handle_n4(&buf[..n], node_ip) {
            Some(resp) => {
                socket.send_to(&resp, peer).await.context("send N4 response")?;
                info!(%peer, "handled N4 PFCP message");
            }
            None => warn!(%peer, "unhandled N4 PFCP message"),
        }
    }
}
