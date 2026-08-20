//! AUSF — Authentication Server Function (Nausf, TS 29.509). SBI-only (JSON).
//! 5G-AKA / EAP-AKA' authentication; EAP payloads are opaque (not ASN.1).

use std::net::{Ipv4Addr, SocketAddr};

/// NRF the AUSF registers with so the AMF can discover it. Override with `RADIAN_AUSF_NRF`.
const NRF_ENV: &str = "RADIAN_AUSF_NRF";
const SBI_PORT_ENV: &str = "RADIAN_AUSF_SBI_PORT";
const UDM_ENV: &str = "RADIAN_AUSF_UDM";
/// Path to this AUSF's YAML config file (design/147 G5, extended in design/148).
const CONFIG_ENV: &str = "RADIAN_AUSF_CONFIG";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";
const DEFAULT_UDM: &str = "http://127.0.0.1:8004";
const DEFAULT_SBI_PORT: u16 = 8003;

/// The AUSF's YAML config (design/147 G5 foundation, extended to the AUSF in
/// design/148). Every field is optional: absent ⇒ its env var (which overrides) or the
/// built-in default. Keys are kebab-case.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct AusfConfig {
    /// SBI listen port.
    sbi_port: Option<u16>,
    /// NRF base URL (registration + peer discovery).
    nrf: Option<String>,
    /// UDM base URL for Nudm_UEAuthentication.
    udm: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_telemetry("ausf");
    common::banner("ausf");

    // Per-NF config (design/147 G5): load the YAML file if RADIAN_AUSF_CONFIG points at
    // one, then read each setting as env > file > default via `config::resolve`.
    let cfg: AusfConfig = common::config::load(CONFIG_ENV)?;
    use common::config::resolve;
    let sbi_port = resolve(SBI_PORT_ENV, cfg.sbi_port, DEFAULT_SBI_PORT);

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial the UDM/NRF over mTLS
    // and serve Nausf over mTLS; the NRF and UDM bases are then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("ausf")?;
    sbi_core::configure_transport(tls.as_ref());

    // Register with the NRF so the AMF can discover the Nausf_UEAuthentication service.
    // The instance id is generated once and reused as this AUSF's OAuth client id.
    let ausf_ip = Ipv4Addr::LOCALHOST;
    let ausf_id = sbi_core::new_nf_instance_id();
    let nrf_base = sbi_core::sbi_base(resolve(NRF_ENV, cfg.nrf, DEFAULT_NRF.to_string()));
    match register_with_nrf(&nrf_base, ausf_ip, sbi_port, &ausf_id).await {
        Ok(()) => tracing::info!(%nrf_base, "registered AUSF with NRF"),
        Err(e) => tracing::warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    // Nausf_UEAuthentication (TS 29.509). With SBI security on, attach an NRF-issued
    // `UDM` access token to each Nudm call (the UDM is protected, design/137 F3).
    let udm_base = sbi_core::sbi_base(resolve(UDM_ENV, cfg.udm, DEFAULT_UDM.to_string()));
    let tokens = sbi_core::oauth::client_tokens_enabled().then(|| {
        std::sync::Arc::new(sbi_core::oauth::TokenSource::new(nrf_base.clone(), ausf_id.clone()))
    });
    let state = match tokens {
        Some(t) => sbi_core::nausf::AusfState::with_tokens(udm_base, t),
        None => sbi_core::nausf::AusfState::new(udm_base),
    };
    let sbi: SocketAddr = format!("0.0.0.0:{sbi_port}").parse()?;
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

#[cfg(test)]
mod config_tests {
    /// The shipped sample config parses into `AusfConfig` — `deny_unknown_fields` keeps
    /// `configs/ausf.yaml` and the struct from drifting apart (design/148).
    #[test]
    fn sample_config_matches_struct() {
        let text = include_str!("../../../configs/ausf.yaml");
        let cfg: super::AusfConfig = serde_yml::from_str(text).expect("configs/ausf.yaml parses");
        assert_eq!(cfg.sbi_port, Some(8003));
        assert_eq!(cfg.nrf.as_deref(), Some("http://127.0.0.1:8000"));
        assert_eq!(cfg.udm.as_deref(), Some("http://127.0.0.1:8004"));
    }
}
