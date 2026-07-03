//! UDM — Unified Data Management (Nudm, TS 29.503). SBI-only (JSON).
//!
//! Stateless front-end over the **UDR** (Nudr, design/24 step 1): the subscriber
//! store lives behind `nf-udr`; this NF holds no persistent state and never sees
//! the long-term key K — only derived authentication vectors cross the UDM↔UDR
//! wire (`sbi_core::nudr`).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};

use tracing::{info, warn};

const SBI_PORT: u16 = 8004;
/// UDR the UDM fronts. Override with `RADIAN_UDM_UDR`.
const UDR_ENV: &str = "RADIAN_UDM_UDR";
const DEFAULT_UDR: &str = "http://127.0.0.1:8005";
const NRF_ENV: &str = "RADIAN_UDM_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";

/// Stable NF instance id — the same value in the NRF profile and in every SBI
/// access-token request (the NRF issues tokens only to registered NFs).
static UDM_INSTANCE_ID: LazyLock<String> = LazyLock::new(sbi_core::new_nf_instance_id);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("udm");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial the UDR/NRF over mTLS
    // and serve Nudm over mTLS; the UDR and NRF bases are then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("udm")?;
    sbi_core::configure_transport(tls.as_ref());

    let udr_base =
        sbi_core::sbi_base(std::env::var(UDR_ENV).unwrap_or_else(|_| DEFAULT_UDR.to_string()));
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));
    // With SBI security on (shared secret or asymmetric), obtain a `UDR` access
    // token from the NRF for each Nudr call; otherwise call the UDR openly.
    let tokens = sbi_core::oauth::client_tokens_enabled().then(|| {
        Arc::new(sbi_core::oauth::TokenSource::new(nrf_base.clone(), UDM_INSTANCE_ID.clone()))
    });
    info!(%udr_base, "UDM fronting UDR over Nudr");
    let udr = Arc::new(match tokens {
        Some(t) => sbi_core::nudr::UdrClient::with_tokens(udr_base, t),
        None => sbi_core::nudr::UdrClient::new(udr_base),
    });

    // Register with the NRF so the AUSF can discover the Nudm service.
    match register_with_nrf(&nrf_base, Ipv4Addr::LOCALHOST, SBI_PORT).await {
        Ok(()) => info!(%nrf_base, "registered UDM with NRF"),
        Err(e) => warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    match tls {
        Some(id) => sbi_core::tls::serve(sbi, sbi_core::nudm::router(udr), id).await?,
        None => sbi_core::run(sbi, sbi_core::nudm::router(udr)).await?,
    }
    Ok(())
}

async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(UDM_INSTANCE_ID.clone(), "UDM", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "nudm-ueau-1".into(),
        service_name: "nudm-ueau".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}
