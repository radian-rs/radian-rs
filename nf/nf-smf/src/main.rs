//! SMF — Session Management Function (Nsmf, TS 29.502 / 29.508).
//!
//! Serves `Nsmf_PDUSession` (called by the AMF) and drives the UPF over **N4 (PFCP)**
//! via the `pfcp` crate. NAS-SM (`nas`) and the N2 SM information transfer-IEs
//! (NGAP-encoded via `ngap`) arrive in later slices.

mod pdu_session;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use pdu_session::SmfState;

const UPF_N4_ENV: &str = "RADIANT_SMF_UPF_N4";
const DEFAULT_UPF_N4: &str = "127.0.0.1:8805";
const NRF_ENV: &str = "RADIANT_SMF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";
const SBI_PORT: u16 = 8002;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("smf");

    let upf_n4: SocketAddr = std::env::var(UPF_N4_ENV)
        .unwrap_or_else(|_| DEFAULT_UPF_N4.to_string())
        .parse()?;
    let smf_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real N4 source address / config
    let nrf_base = std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string());

    // The NRF base is also how the SMF finds the UDM for Nudm_SDM subscription checks.
    let smf = Arc::new(SmfState::connect(upf_n4, smf_ip, nrf_base.clone()).await?);
    smf.associate().await?;
    tracing::info!(%upf_n4, "PFCP association established with UPF");

    // Register with the NRF so the AMF can discover the Nsmf_PDUSession service.
    match pdu_session::register_with_nrf(&nrf_base, smf_ip, SBI_PORT).await {
        Ok(()) => tracing::info!(%nrf_base, "registered SMF with NRF"),
        Err(e) => tracing::warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    sbi_core::run(sbi, pdu_session::router(smf)).await?;
    Ok(())
}
