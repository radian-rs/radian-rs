//! CHF — Charging Function (Nchf, TS 32.290/32.291). SBI-only (JSON).
//!
//! Serves **Nchf_ConvergedCharging** (`sbi_core::nchf`): the SMF (as CTF) opens a
//! charging data session per PDU session, reports mid-session usage (relayed UPF
//! volume-threshold reports), and closes it with the final usage — the CHF keeps
//! the CDRs. Registers with the NRF (nf-type `CHF`) so the SMF can discover it.

use std::net::{Ipv4Addr, SocketAddr};

use tracing::{info, warn};

const SBI_PORT: u16 = 8007;
const NRF_ENV: &str = "RADIAN_CHF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("chf");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial the NRF over mTLS
    // and serve Nchf over mTLS; the NRF base is then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("chf")?;
    sbi_core::configure_transport(tls.as_ref());

    let chf_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real advertise address / config
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));
    match register_with_nrf(&nrf_base, chf_ip, SBI_PORT).await {
        Ok(()) => info!(%nrf_base, "registered CHF with NRF"),
        Err(e) => warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    let state = sbi_core::nchf::ChfState::new();
    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    match tls {
        Some(id) => sbi_core::tls::serve(sbi, sbi_core::nchf::router(state), id).await?,
        None => sbi_core::run(sbi, sbi_core::nchf::router(state)).await?,
    }
    Ok(())
}

async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(sbi_core::new_nf_instance_id(), "CHF", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "nchf-convergedcharging-1".into(),
        service_name: "nchf-convergedcharging".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}
