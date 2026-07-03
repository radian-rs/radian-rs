//! AUSF — Authentication Server Function (Nausf, TS 29.509). SBI-only (JSON).
//! 5G-AKA / EAP-AKA' authentication; EAP payloads are opaque (not ASN.1).

use std::net::{Ipv4Addr, SocketAddr};

const SBI_PORT: u16 = 8003;
/// NRF the AUSF registers with so the AMF can discover it. Override with `RADIAN_AUSF_NRF`.
const NRF_ENV: &str = "RADIAN_AUSF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("ausf");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial the UDM/NRF over mTLS
    // and serve Nausf over mTLS; the NRF and UDM bases are then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("ausf")?;
    sbi_core::configure_transport(tls.as_ref());

    // Register with the NRF so the AMF can discover the Nausf_UEAuthentication service.
    let ausf_ip = Ipv4Addr::LOCALHOST;
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));
    match register_with_nrf(&nrf_base, ausf_ip, SBI_PORT).await {
        Ok(()) => tracing::info!(%nrf_base, "registered AUSF with NRF"),
        Err(e) => tracing::warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    // Nausf_UEAuthentication (TS 29.509). UDM target is fixed for now; NRF-based
    // discovery of the UDM is a follow-up.
    let udm_base = sbi_core::sbi_base("http://127.0.0.1:8004");
    let state = sbi_core::nausf::AusfState::new(udm_base);
    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    match &tls {
        Some(id) => sbi_core::tls::run_tls(sbi, sbi_core::nausf::router(state), id.server_config()?).await?,
        None => sbi_core::run(sbi, sbi_core::nausf::router(state)).await?,
    }
    Ok(())
}

/// Register this AUSF's `nausf-auth` service with the NRF (mirrors the SMF's
/// registration) and keep it alive via the NRF-assigned heartbeat.
async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(sbi_core::new_nf_instance_id(), "AUSF", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "nausf-auth-1".into(),
        service_name: "nausf-auth".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}
