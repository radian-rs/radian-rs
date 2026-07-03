//! PCF — Policy Control Function (Npcf, TS 29.507 / 512 / 514 / 525). SBI-only (JSON).
//!
//! Serves **Npcf_SMPolicyControl** (TS 29.512): the SMF creates an SM policy
//! association at PDU-session establishment and the PCF returns the authorized
//! session AMBR + QoS flows (`sbi_core::npcf`). Policy is a local per-DNN default
//! ([`PolicyConfig::demo`]); a real PCF also reads `Nudr` policy-data + PCC rules.
//!
//! Registers with the NRF (nf-type `PCF`) so the SMF can discover it.

use std::net::{Ipv4Addr, SocketAddr};

use tracing::{info, warn};

const SBI_PORT: u16 = 8006;
const NRF_ENV: &str = "RADIAN_PCF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("pcf");

    let pcf_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real advertise address / config
    let nrf_base = std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string());
    match register_with_nrf(&nrf_base, pcf_ip, SBI_PORT).await {
        Ok(()) => info!(%nrf_base, "registered PCF with NRF"),
        Err(e) => warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    let state = sbi_core::npcf::PcfState::new(sbi_core::npcf::PolicyConfig::demo());
    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    sbi_core::run(sbi, sbi_core::npcf::router(state)).await?;
    Ok(())
}

async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(sbi_core::new_nf_instance_id(), "PCF", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "npcf-smpolicycontrol-1".into(),
        service_name: "npcf-smpolicycontrol".into(),
        scheme: "http".into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}
