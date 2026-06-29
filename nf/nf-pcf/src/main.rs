//! PCF — Policy Control Function (Npcf, TS 29.507 / 512 / 514 / 525). SBI-only (JSON).
//! AM/SM policy, policy authorization, UE policy.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("pcf");

    // TODO: implement Npcf_AMPolicyControl / _SMPolicyControl / _PolicyAuthorization.
    let sbi: SocketAddr = "0.0.0.0:8006".parse()?;
    sbi_core::serve(sbi).await?;
    Ok(())
}
