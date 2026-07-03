//! PCF — Policy Control Function (Npcf, TS 29.507 / 512 / 514 / 525). SBI-only (JSON).
//!
//! Serves **Npcf_SMPolicyControl** (TS 29.512): the SMF creates an SM policy
//! association at PDU-session establishment and the PCF returns the authorized
//! session AMBR + QoS flows (`sbi_core::npcf`), re-authorizing them on Update.
//!
//! Policy source is the **UDR** (`Nudr` policy-data, TS 29.519) per subscriber,
//! falling back to a local per-DNN default ([`PolicyConfig::demo`]) when a
//! subscriber has no provisioned policy-data. Registers with the NRF (nf-type
//! `PCF`) so the SMF can discover it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};

use tracing::{info, warn};

const SBI_PORT: u16 = 8006;
const NRF_ENV: &str = "RADIAN_PCF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";
/// UDR the PCF reads policy-data from. Override with `RADIAN_PCF_UDR`.
const UDR_ENV: &str = "RADIAN_PCF_UDR";
const DEFAULT_UDR: &str = "http://127.0.0.1:8005";

/// Stable NF instance id — the same value in the NRF profile and in every SBI
/// access-token request (the NRF issues tokens only to registered NFs).
static PCF_INSTANCE_ID: LazyLock<String> = LazyLock::new(sbi_core::new_nf_instance_id);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("pcf");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial the UDR/NRF over mTLS
    // and serve Npcf over mTLS; the NRF and UDR bases are then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("pcf")?;
    sbi_core::configure_transport(tls.as_ref());

    let pcf_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real advertise address / config
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));
    let udr_base =
        sbi_core::sbi_base(std::env::var(UDR_ENV).unwrap_or_else(|_| DEFAULT_UDR.to_string()));
    match register_with_nrf(&nrf_base, pcf_ip, SBI_PORT).await {
        Ok(()) => info!(%nrf_base, "registered PCF with NRF"),
        Err(e) => warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    // Policy from the UDR (Nudr policy-data). With SBI security on, present a `UDR`
    // access token on each call; otherwise call it openly.
    info!(%udr_base, "PCF sourcing policy from the UDR over Nudr policy-data");
    let udr = if sbi_core::oauth::sbi_secret().is_some() {
        let tokens =
            Arc::new(sbi_core::oauth::TokenSource::new(nrf_base.clone(), PCF_INSTANCE_ID.clone()));
        sbi_core::nudr::UdrClient::with_tokens(udr_base, tokens)
    } else {
        sbi_core::nudr::UdrClient::new(udr_base)
    };

    let state = sbi_core::npcf::PcfState::new(sbi_core::npcf::PolicyConfig::demo())
        .with_udr(Arc::new(udr));
    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    match tls {
        Some(id) => sbi_core::tls::serve(sbi, sbi_core::npcf::router(state), id).await?,
        None => sbi_core::run(sbi, sbi_core::npcf::router(state)).await?,
    }
    Ok(())
}

async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(PCF_INSTANCE_ID.clone(), "PCF", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "npcf-smpolicycontrol-1".into(),
        service_name: "npcf-smpolicycontrol".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}
