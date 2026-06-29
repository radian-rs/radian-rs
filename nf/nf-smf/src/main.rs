//! SMF — Session Management Function (Nsmf, TS 29.502 / 29.508).
//!
//! Drives the UPF over **N4 (PFCP)** via the `pfcp` crate, builds **NAS-SM**
//! (`nas`), and produces the **N2 SM information** transfer-IEs which are
//! NGAP-encoded (`ngap`) — even though the SMF never terminates N2.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("smf");

    // TODO: N4 PFCP association/session toward the UPF via `pfcp`.
    // TODO: NAS-SM via `nas`; N2 SM info (PDUSessionResource*Transfer) via `ngap`.
    // TODO: implement Nsmf_PDUSession + Nsmf_EventExposure.
    let sbi: SocketAddr = "0.0.0.0:8002".parse()?;
    sbi_core::serve(sbi).await?;
    Ok(())
}
