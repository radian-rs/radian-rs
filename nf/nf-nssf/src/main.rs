//! NSSF — Network Slice Selection Function (Nnssf, TS 29.531). SBI-only (JSON).
//!
//! Serves **Nnssf_NSSelection** — the AMF asks which of a UE's requested slices it may
//! grant, given the subscription *and the UE's tracking area* — and
//! **Nnssf_NSSAIAvailability**, which publishes the slices each tracking area deploys.
//!
//! The reason this is a network function rather than AMF-local logic is **per-TA
//! availability**: the AMF's intersection is PLMN-global, so a slice that is subscribed
//! but not deployed in the UE's current tracking area would be wrongly allowed
//! (design/133). Registers with the NRF (nf-type `NSSF`) so the AMF can discover it;
//! an unreachable NSSF makes the AMF fall back to its local intersection (fail-open).

use std::net::{Ipv4Addr, SocketAddr};

use tracing::{info, warn};

const SBI_PORT: u16 = 8008;
const NRF_ENV: &str = "RADIAN_NSSF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("nssf");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial the NRF over mTLS and
    // serve Nnssf over mTLS; the NRF base is then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("nssf")?;
    sbi_core::configure_transport(tls.as_ref());

    let nssf_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real advertise address / config
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));
    match register_with_nrf(&nrf_base, nssf_ip, SBI_PORT).await {
        Ok(()) => info!(%nrf_base, "registered NSSF with NRF"),
        Err(e) => warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    let state = sbi_core::nnssf::NssfState::new(sbi_core::nnssf::NssfConfig::demo());
    info!(
        tracking_areas = state.availability().len(),
        "NSSF up: per-TA slice availability provisioned"
    );
    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    match tls {
        Some(id) => sbi_core::tls::serve(sbi, sbi_core::nnssf::router(state), id).await?,
        None => sbi_core::run(sbi, sbi_core::nnssf::router(state)).await?,
    }
    Ok(())
}

async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(sbi_core::new_nf_instance_id(), "NSSF", ip.to_string());
    let endpoint = vec![IpEndPoint { ipv4_address: Some(ip.to_string()), port: Some(sbi_port) }];
    profile.nf_services = Some(vec![
        NfService {
            service_instance_id: "nnssf-nsselection-1".into(),
            service_name: "nnssf-nsselection".into(),
            scheme: sbi_core::sbi_scheme().into(),
            ip_end_points: endpoint.clone(),
        },
        NfService {
            service_instance_id: "nnssf-nssaiavailability-1".into(),
            service_name: "nnssf-nssaiavailability".into(),
            scheme: sbi_core::sbi_scheme().into(),
            ip_end_points: endpoint,
        },
    ]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}
