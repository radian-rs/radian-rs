//! NRF — Network Repository Function (Nnrf, TS 29.510). SBI-only (JSON).
//! Service registration/discovery; the foundational NF every other NF talks to.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("nrf");

    // TODO: implement Nnrf_NFManagement + Nnrf_NFDiscovery (TS 29.510).
    let sbi: SocketAddr = "0.0.0.0:8000".parse()?;
    sbi_core::serve(sbi).await?;
    Ok(())
}
