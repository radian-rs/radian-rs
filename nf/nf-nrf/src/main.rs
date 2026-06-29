//! NRF — Network Repository Function (Nnrf, TS 29.510). SBI-only (JSON).
//! Service registration/discovery; the foundational NF every other NF talks to.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("nrf");

    // Nnrf_NFManagement + Nnrf_NFDiscovery (TS 29.510) over the SBI.
    let store = sbi_core::nnrf::NrfStore::default();
    let sbi: SocketAddr = "0.0.0.0:8000".parse()?;
    sbi_core::run(sbi, sbi_core::nnrf::router(store)).await?;
    Ok(())
}
