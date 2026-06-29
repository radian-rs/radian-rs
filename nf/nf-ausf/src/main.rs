//! AUSF — Authentication Server Function (Nausf, TS 29.509). SBI-only (JSON).
//! 5G-AKA / EAP-AKA' authentication; EAP payloads are opaque (not ASN.1).

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("ausf");

    // Nausf_UEAuthentication (TS 29.509). UDM target is fixed for now; NRF-based
    // discovery of the UDM is a follow-up.
    let udm_base = "http://127.0.0.1:8004";
    let state = sbi_core::nausf::AusfState::new(udm_base);
    let sbi: SocketAddr = "0.0.0.0:8003".parse()?;
    sbi_core::run(sbi, sbi_core::nausf::router(state)).await?;
    Ok(())
}
