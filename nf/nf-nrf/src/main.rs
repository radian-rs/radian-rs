//! NRF — Network Repository Function (Nnrf, TS 29.510). SBI-only (JSON).
//! Service registration/discovery; the foundational NF every other NF talks to.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("nrf");

    // Nnrf_NFManagement + Nnrf_NFDiscovery (TS 29.510) over the SBI. Registrations
    // are soft state: NFs heartbeat at the assigned interval or get evicted.
    let store = match std::env::var("RADIAN_NRF_HEARTBEAT_SECS") {
        Ok(v) => {
            let secs: u64 = v.parse().map_err(|e| anyhow::anyhow!("RADIAN_NRF_HEARTBEAT_SECS: {e}"))?;
            sbi_core::nnrf::NrfStore::with_heartbeat_timer(std::time::Duration::from_secs(secs.max(1)))
        }
        Err(_) => sbi_core::nnrf::NrfStore::default(),
    };
    let sbi: SocketAddr = "0.0.0.0:8000".parse()?;
    sbi_core::run(sbi, sbi_core::nnrf::router(store)).await?;
    Ok(())
}
