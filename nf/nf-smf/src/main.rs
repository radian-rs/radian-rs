//! SMF — Session Management Function (Nsmf, TS 29.502 / 29.508).
//!
//! Serves `Nsmf_PDUSession` (called by the AMF) and drives the UPF over **N4 (PFCP)**
//! via the `pfcp` crate. NAS-SM (`nas`) and the N2 SM information transfer-IEs
//! (NGAP-encoded via `ngap`) arrive in later slices.

mod pdu_session;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use pdu_session::{SmfState, UserPlane};

const UPF_N4_ENV: &str = "RADIAN_SMF_UPF_N4";
const DEFAULT_UPF_N4: &str = "127.0.0.1:8805";
/// N4 address of an **intermediate UPF** (I-UPF). When set, every PDU session is
/// chained gNB → I-UPF → N9 → anchor → N6 (design/134); the anchor stays
/// `RADIAN_SMF_UPF_N4`. Absent ⇒ single-UPF operation.
const IUPF_N4_ENV: &str = "RADIAN_SMF_IUPF_N4";
/// N4 address of a **second anchor**, plus the destination prefix steered to it — the
/// uplink classifier (design/134 Phase 2). Both are required together, and both need
/// `RADIAN_SMF_IUPF_N4`: the classifier runs on the intermediate UPF.
const PSA2_N4_ENV: &str = "RADIAN_SMF_PSA2_N4";
const ULCL_PREFIX_ENV: &str = "RADIAN_SMF_ULCL_PREFIX";
const NRF_ENV: &str = "RADIAN_SMF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";
/// GFBR admission-control budget (Mbps, each direction). Absent ⇒ unlimited.
const GFBR_BUDGET_ENV: &str = "RADIAN_SMF_GFBR_BUDGET_MBPS";
/// Usage-reporting volume threshold (bytes): the UPF then reports each session's
/// usage mid-session whenever it crosses the threshold (the charging trigger
/// toward the CHF). Absent ⇒ usage is only reported at session deletion.
const USAGE_THRESHOLD_ENV: &str = "RADIAN_SMF_USAGE_THRESHOLD_BYTES";
const SBI_PORT: u16 = 8002;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("smf");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial every NF (NRF/UDM/AMF)
    // over mTLS and serve Nsmf over mTLS; the NRF base is then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("smf")?;
    sbi_core::configure_transport(tls.as_ref());

    let upf_n4: SocketAddr = std::env::var(UPF_N4_ENV)
        .unwrap_or_else(|_| DEFAULT_UPF_N4.to_string())
        .parse()?;
    let iupf_n4: Option<SocketAddr> =
        std::env::var(IUPF_N4_ENV).ok().map(|v| v.parse()).transpose()?;
    let mut user_plane = match iupf_n4 {
        Some(iupf) => UserPlane::chained(upf_n4, iupf),
        None => UserPlane::single(upf_n4),
    };
    // A second anchor + the prefix classified to it (both or neither).
    match (std::env::var(PSA2_N4_ENV).ok(), std::env::var(ULCL_PREFIX_ENV).ok()) {
        (Some(psa2), Some(prefix)) => {
            let prefix: pfcp::IpPrefix = prefix
                .parse()
                .map_err(|_| anyhow::anyhow!("{ULCL_PREFIX_ENV} is not an IP prefix"))?;
            user_plane = user_plane.with_breakout(psa2.parse()?, prefix);
        }
        (None, None) => {}
        _ => anyhow::bail!("{PSA2_N4_ENV} and {ULCL_PREFIX_ENV} must be set together"),
    }
    let smf_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real N4 source address / config
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));

    // The NRF base is also how the SMF finds the UDM for Nudm_SDM subscription checks.
    let mut smf = SmfState::connect(user_plane, smf_ip, nrf_base.clone()).await?;
    // Optional GFBR admission-control budget (else unlimited).
    if let Some(mbps) = std::env::var(GFBR_BUDGET_ENV).ok().and_then(|v| v.parse::<u64>().ok()) {
        let bps = mbps.saturating_mul(1_000_000);
        smf = smf.with_gfbr_budget(bps, bps);
        tracing::info!(gfbr_budget_mbps = mbps, "GFBR admission control enabled");
    }
    // Optional mid-session usage reporting (the charging trigger, design/59).
    if let Some(bytes) = std::env::var(USAGE_THRESHOLD_ENV).ok().and_then(|v| v.parse::<u64>().ok())
    {
        smf = smf.with_usage_threshold(bytes);
        tracing::info!(usage_threshold_bytes = bytes, "mid-session usage reporting enabled");
    }
    let smf = Arc::new(smf);
    smf.associate().await?;
    match (user_plane.intermediate, user_plane.breakout) {
        (Some(iupf), Some((psa2, prefix))) => tracing::info!(
            anchor = %upf_n4,
            classifier = %iupf,
            breakout_anchor = %psa2,
            breakout_prefix = %prefix,
            "PFCP associations established; the intermediate UPF classifies uplink to two anchors (design/134)"
        ),
        (Some(iupf), None) => tracing::info!(
            anchor = %upf_n4,
            intermediate = %iupf,
            "PFCP associations established; sessions run chained over N9 (design/134)"
        ),
        _ => tracing::info!(%upf_n4, "PFCP association established with UPF"),
    }
    // Consume UPF-initiated usage reports: ack + relay to the CHF (Nchf update).
    tokio::spawn(pdu_session::handle_usage_reports(smf.clone()));

    // Register with the NRF so the AMF can discover the Nsmf_PDUSession service.
    match pdu_session::register_with_nrf(&nrf_base, smf_ip, SBI_PORT).await {
        Ok(()) => tracing::info!(%nrf_base, "registered SMF with NRF"),
        Err(e) => tracing::warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    match tls {
        Some(id) => sbi_core::tls::serve(sbi, pdu_session::router(smf), id).await?,
        None => sbi_core::run(sbi, pdu_session::router(smf)).await?,
    }
    Ok(())
}
