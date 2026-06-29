//! UDM — Unified Data Management (Nudm, TS 29.503). SBI-only (JSON).
//! Subscriber data, authentication vectors, registration; persists via UDR.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("udm");

    // TODO: implement Nudm_SDM / _UEContextManagement / _UEAuthentication (TS 29.503).
    let sbi: SocketAddr = "0.0.0.0:8004".parse()?;
    sbi_core::serve(sbi).await?;
    Ok(())
}
