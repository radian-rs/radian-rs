//! NEF — Network Exposure Function, `Nnef_TrafficInfluence` (TS 29.522). SBI-only (JSON).
//!
//! The northbound front door for an **AF traffic-influence** request (design/135): an AF
//! asks to route a UE's traffic for an app/flow to a local edge (DNAI). The NEF translates
//! that into the SMF's uplink-classifier breakout (design/134 Phase 3e) and tracks the
//! subscription so a delete undoes it. DNAI→UPF resolution stays in the SMF's topology, so
//! the NEF never learns the user-plane graph — it is a thin, stateless-but-for-subscriptions
//! translator. Registers with the NRF (nf-type `NEF`) and discovers the SMF through it.

use std::net::{Ipv4Addr, SocketAddr};

use tracing::{info, warn};

const SBI_PORT: u16 = 8009;
const NRF_ENV: &str = "RADIAN_NEF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";
/// Reach the SMF at an explicit base URL instead of via NRF discovery (a deployment
/// without an NRF, or a test rig).
const SMF_ENV: &str = "RADIAN_NEF_SMF";
/// Authorize influences through this PCF instead of discovering one. Set to `none` to
/// force the PCF-less path (drive the SMF directly, design/135 Phase 1).
const PCF_ENV: &str = "RADIAN_NEF_PCF";
/// Store group / any-UE influences at this UDR instead of discovering one (design/135
/// Phase 3).
const UDR_ENV: &str = "RADIAN_NEF_UDR";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_telemetry("nef");
    common::banner("nef");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial the NRF/SMF over mTLS and
    // serve Nnef over mTLS; the NRF base is then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("nef")?;
    sbi_core::configure_transport(tls.as_ref());

    let nef_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real advertise address / config
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));
    match register_with_nrf(&nrf_base, nef_ip, SBI_PORT).await {
        Ok(()) => info!(%nrf_base, "registered NEF with NRF"),
        Err(e) => warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    // Prefer an explicit SMF base if set; otherwise discover peers via the NRF.
    let mut state = match std::env::var(SMF_ENV) {
        Ok(smf) => {
            let smf = sbi_core::sbi_base(smf);
            info!(%smf, "NEF up: AF traffic influence (explicit SMF base)");
            sbi_core::nnef::NefState::with_smf_base(smf)
        }
        Err(_) => {
            info!("NEF up: AF traffic influence (peers via NRF discovery)");
            sbi_core::nnef::NefState::new(nrf_base)
        }
    };
    // With a PCF, an influence is authorized through it (Npcf_PolicyAuthorization) so the
    // route lands in the SM policy and composes with QoS (design/135 Phase 2b).
    match std::env::var(PCF_ENV).as_deref() {
        Ok("none") => info!("PCF path disabled — influences drive the SMF directly"),
        Ok(pcf) => {
            let pcf = sbi_core::sbi_base(pcf);
            info!(%pcf, "influences authorized through the PCF");
            state = state.with_pcf_base(pcf);
        }
        Err(_) => {}
    }
    // A group / any-UE influence is stored as UDR application influence data, so every PCF
    // applies it — including to sessions established later (design/135 Phase 3).
    if let Ok(udr) = std::env::var(UDR_ENV) {
        let udr = sbi_core::sbi_base(udr);
        info!(%udr, "group influences stored as UDR influence data");
        state = state.with_udr_base(udr);
    }

    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    match tls {
        Some(id) => sbi_core::tls::serve(sbi, sbi_core::nnef::router(state), id).await?,
        None => sbi_core::run(sbi, sbi_core::nnef::router(state)).await?,
    }
    Ok(())
}

async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(sbi_core::new_nf_instance_id(), "NEF", ip.to_string());
    let endpoint = vec![IpEndPoint { ipv4_address: Some(ip.to_string()), port: Some(sbi_port) }];
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "nnef-trafficinfluence-1".into(),
        service_name: "nnef-trafficinfluence".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: endpoint,
    }]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}
