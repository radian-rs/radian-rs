//! AUSF — Authentication Server Function (Nausf, TS 29.509). SBI-only (JSON).
//! 5G-AKA / EAP-AKA' authentication; EAP payloads are opaque (not ASN.1).

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("ausf");

    // TODO: implement Nausf_UEAuthentication (TS 29.509).
    let sbi: SocketAddr = "0.0.0.0:8003".parse()?;
    sbi_core::serve(sbi).await?;
    Ok(())
}
