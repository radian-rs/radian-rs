//! AUSF — Authentication Server Function (Nausf, TS 29.509). SBI-only (JSON).
//! 5G-AKA / EAP-AKA' authentication; EAP payloads are opaque (not ASN.1).

use std::net::{Ipv4Addr, SocketAddr};

const SBI_PORT: u16 = 8003;
/// NRF the AUSF registers with so the AMF can discover it. Override with `RADIAN_AUSF_NRF`.
const NRF_ENV: &str = "RADIAN_AUSF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_telemetry("ausf");
    common::banner("ausf");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial the UDM/NRF over mTLS
    // and serve Nausf over mTLS; the NRF and UDM bases are then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("ausf")?;
    sbi_core::configure_transport(tls.as_ref());

    // Register with the NRF so the AMF can discover the Nausf_UEAuthentication service.
    // The instance id is generated once and reused as this AUSF's OAuth client id.
    let ausf_ip = Ipv4Addr::LOCALHOST;
    let ausf_id = sbi_core::new_nf_instance_id();
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));
    match register_with_nrf(&nrf_base, ausf_ip, SBI_PORT, &ausf_id).await {
        Ok(()) => tracing::info!(%nrf_base, "registered AUSF with NRF"),
        Err(e) => tracing::warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    // Nausf_UEAuthentication (TS 29.509). UDM target is fixed for now; NRF-based
    // discovery of the UDM is a follow-up. With SBI security on, attach an NRF-issued
    // `UDM` access token to each Nudm call (the UDM is protected, design/137 F3).
    let udm_base = sbi_core::sbi_base("http://127.0.0.1:8004");
    let tokens = sbi_core::oauth::client_tokens_enabled().then(|| {
        std::sync::Arc::new(sbi_core::oauth::TokenSource::new(nrf_base.clone(), ausf_id.clone()))
    });
    let state = match tokens {
        Some(t) => sbi_core::nausf::AusfState::with_tokens(udm_base, t),
        None => sbi_core::nausf::AusfState::new(udm_base),
    };
    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    match tls {
        Some(id) => sbi_core::tls::serve(sbi, sbi_core::nausf::router(state), id).await?,
        None => sbi_core::run(sbi, sbi_core::nausf::router(state)).await?,
    }
    Ok(())
}

/// Register this AUSF's `nausf-auth` service with the NRF (mirrors the SMF's
/// registration) and keep it alive via the NRF-assigned heartbeat.
async fn register_with_nrf(
    nrf_base: &str,
    ip: Ipv4Addr,
    sbi_port: u16,
    instance_id: &str,
) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(instance_id.to_string(), "AUSF", ip.to_string());
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
