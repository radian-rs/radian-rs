//! UDR — Unified Data Repository (Nudr, TS 29.504). SBI-only (JSON).
//! Backing store for UDM/PCF/NEF subscription, policy and exposure data.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("udr");

    // TODO: implement Nudr_DataRepository (TS 29.504).
    let sbi: SocketAddr = "0.0.0.0:8005".parse()?;
    sbi_core::serve(sbi).await?;
    Ok(())
}
