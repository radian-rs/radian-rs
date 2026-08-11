//! SMF — Session Management Function (Nsmf, TS 29.502 / 29.508).
//!
//! Serves `Nsmf_PDUSession` (called by the AMF) and drives the UPF over **N4 (PFCP)**
//! via the `pfcp` crate. NAS-SM (`nas`) and the N2 SM information transfer-IEs
//! (NGAP-encoded via `ngap`) arrive in later slices.

mod pdu_session;
mod topology;

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
/// Path to a **JSON UP-topology config** (design/134 Phase 3b). When set it supersedes the
/// scalar `RADIAN_SMF_{UPF,IUPF,PSA2}_N4` vars: the SMF loads a named-node `upNodes`/`links`
/// graph and selects a path **per DNN**. Absent ⇒ the fixed env-var user plane above.
const TOPOLOGY_ENV: &str = "RADIAN_SMF_TOPOLOGY";
/// Address other NFs use to reach this SMF's SBI — baked into the SM policy
/// `notificationUri` so a PCF-initiated re-authorization (an AF influence landing,
/// design/135 Phase 2b) reaches the right SM context.
const ADVERTISE_ENV: &str = "RADIAN_SMF_ADVERTISE_ADDR";
const DEFAULT_ADVERTISE_ADDR: &str = "127.0.0.1";
const NRF_ENV: &str = "RADIAN_SMF_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";
/// GFBR admission-control budget (Mbps, each direction). Absent ⇒ unlimited.
const GFBR_BUDGET_ENV: &str = "RADIAN_SMF_GFBR_BUDGET_MBPS";
/// Usage-reporting volume threshold (bytes): the UPF then reports each session's
/// usage mid-session whenever it crosses the threshold (the charging trigger
/// toward the CHF). Absent ⇒ usage is only reported at session deletion.
const USAGE_THRESHOLD_ENV: &str = "RADIAN_SMF_USAGE_THRESHOLD_BYTES";
/// N4 heartbeat interval (seconds): how often the SMF pings each UPF to detect a
/// restart (design/137 G4). Absent ⇒ 10s.
const HEARTBEAT_SECS_ENV: &str = "RADIAN_SMF_HEARTBEAT_SECS";
const DEFAULT_HEARTBEAT_SECS: u64 = 10;
const SBI_PORT: u16 = 8002;
/// Path to this SMF's YAML config file (design/147, G5). Every setting below can
/// come from it; each `RADIAN_SMF_*` env var still **overrides** the file value.
const CONFIG_ENV: &str = "RADIAN_SMF_CONFIG";

/// The SMF's YAML config (design/147, G5) — one file replacing the scattered
/// `RADIAN_SMF_*` env reads. Every field is optional: an absent field falls through
/// to its env var (which always overrides) or the built-in default. Keys are
/// kebab-case (`upf-n4`, `gfbr-budget-mbps`, …).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct SmfConfig {
    nrf: Option<String>,
    upf_n4: Option<String>,
    iupf_n4: Option<String>,
    psa2_n4: Option<String>,
    ulcl_prefix: Option<String>,
    topology: Option<String>,
    advertise_addr: Option<String>,
    gfbr_budget_mbps: Option<u64>,
    usage_threshold_bytes: Option<u64>,
    heartbeat_secs: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_telemetry("smf");
    common::banner("smf");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial every NF (NRF/UDM/AMF)
    // over mTLS and serve Nsmf over mTLS; the NRF base is then https.
    let tls = sbi_core::tls::TlsIdentity::from_env("smf")?;
    sbi_core::configure_transport(tls.as_ref());

    // Per-NF config (design/147, G5): load the YAML file if RADIAN_SMF_CONFIG points
    // at one, then read each setting as env > file > default via `config::resolve`.
    let cfg: SmfConfig = common::config::load(CONFIG_ENV)?;
    use common::config::{resolve, resolve_opt};

    let smf_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real N4 source address / config
    let nrf_base = sbi_core::sbi_base(resolve(NRF_ENV, cfg.nrf, DEFAULT_NRF.to_string()));

    // A config-file UP topology (design/134 Phase 3b) takes precedence over the scalar
    // user plane: it expresses a named-node graph and the SMF selects a path per DNN.
    // Absent ⇒ the anchor / optional I-UPF / optional breakout come from the scalar
    // settings. The NRF base is also how the SMF finds the UDM for Nudm_SDM checks.
    let mut smf = match resolve_opt::<String>(TOPOLOGY_ENV, cfg.topology) {
        Some(path) => {
            let json = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("read UP topology config {path}: {e}"))?;
            let topo = topology::Topology::parse(&json)?;
            tracing::info!(
                %path,
                up_nodes = topo.up_nodes.len(),
                "loaded UP topology config; sessions are routed per DNN (design/134 Phase 3b)"
            );
            SmfState::connect_with_topology(topo, smf_ip, nrf_base.clone()).await?
        }
        None => {
            let upf_n4: SocketAddr =
                resolve(UPF_N4_ENV, cfg.upf_n4, DEFAULT_UPF_N4.to_string()).parse()?;
            let iupf_n4: Option<SocketAddr> =
                resolve_opt::<String>(IUPF_N4_ENV, cfg.iupf_n4).map(|v| v.parse()).transpose()?;
            let mut user_plane = match iupf_n4 {
                Some(iupf) => UserPlane::chained(upf_n4, iupf),
                None => UserPlane::single(upf_n4),
            };
            // A second anchor + the prefix classified to it (both or neither).
            match (
                resolve_opt::<String>(PSA2_N4_ENV, cfg.psa2_n4),
                resolve_opt::<String>(ULCL_PREFIX_ENV, cfg.ulcl_prefix),
            ) {
                (Some(psa2), Some(prefix)) => {
                    let prefix: pfcp::IpPrefix = prefix
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{ULCL_PREFIX_ENV} is not an IP prefix"))?;
                    user_plane = user_plane.with_breakout(psa2.parse()?, prefix);
                }
                (None, None) => {}
                _ => anyhow::bail!("{PSA2_N4_ENV} and {ULCL_PREFIX_ENV} must be set together"),
            }
            match (user_plane.intermediate, user_plane.breakout) {
                (Some(iupf), Some((psa2, prefix))) => tracing::info!(
                    anchor = %upf_n4, classifier = %iupf, breakout_anchor = %psa2, breakout_prefix = %prefix,
                    "user plane: the intermediate UPF classifies uplink to two anchors (design/134)"
                ),
                (Some(iupf), None) => tracing::info!(
                    anchor = %upf_n4, intermediate = %iupf,
                    "user plane: every session runs chained over N9 (design/134)"
                ),
                _ => tracing::info!(%upf_n4, "user plane: single UPF"),
            }
            SmfState::connect(user_plane, smf_ip, nrf_base.clone()).await?
        }
    };
    // How the PCF reaches us for a policy-update notification (design/135 Phase 2b).
    let advertise = resolve(ADVERTISE_ENV, cfg.advertise_addr, DEFAULT_ADVERTISE_ADDR.to_string());
    smf = smf.with_callback_base(format!(
        "{}://{advertise}:{SBI_PORT}",
        sbi_core::sbi_scheme()
    ));
    // Optional GFBR admission-control budget (else unlimited).
    if let Some(mbps) = resolve_opt::<u64>(GFBR_BUDGET_ENV, cfg.gfbr_budget_mbps) {
        let bps = mbps.saturating_mul(1_000_000);
        smf = smf.with_gfbr_budget(bps, bps);
        tracing::info!(gfbr_budget_mbps = mbps, "GFBR admission control enabled");
    }
    // Optional mid-session usage reporting (the charging trigger, design/59).
    if let Some(bytes) = resolve_opt::<u64>(USAGE_THRESHOLD_ENV, cfg.usage_threshold_bytes) {
        smf = smf.with_usage_threshold(bytes);
        tracing::info!(usage_threshold_bytes = bytes, "mid-session usage reporting enabled");
    }
    let smf = Arc::new(smf);
    smf.associate().await?;
    tracing::info!("PFCP associations established with the user plane");
    // Consume UPF-initiated usage reports: ack + relay to the CHF (Nchf update).
    tokio::spawn(pdu_session::handle_usage_reports(smf.clone()));
    // N4 liveness (design/137 G4): heartbeat every UPF and, on a restart (a newer
    // recovery timestamp), re-associate it and drop its now-stranded sessions.
    let heartbeat_secs = resolve(HEARTBEAT_SECS_ENV, cfg.heartbeat_secs, DEFAULT_HEARTBEAT_SECS);
    tokio::spawn(pdu_session::run_heartbeats(
        smf.clone(),
        std::time::Duration::from_secs(heartbeat_secs),
    ));

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

#[cfg(test)]
mod config_tests {
    use super::*;

    /// The shipped sample config must parse into `SmfConfig` — `deny_unknown_fields`
    /// makes this fail if `configs/smf.yaml` grows a key the struct doesn't have (or a
    /// field is renamed), keeping the sample and the code from drifting apart.
    #[test]
    fn sample_config_matches_struct() {
        let text = include_str!("../../../configs/smf.yaml");
        let cfg: SmfConfig = serde_yml::from_str(text).expect("configs/smf.yaml parses");
        // The keys left uncommented in the sample are the always-present ones.
        assert_eq!(cfg.nrf.as_deref(), Some("http://127.0.0.1:8000"));
        assert_eq!(cfg.upf_n4.as_deref(), Some("127.0.0.1:8805"));
        assert_eq!(cfg.advertise_addr.as_deref(), Some("127.0.0.1"));
        assert_eq!(cfg.heartbeat_secs, Some(10));
        // The optional multi-UPF / charging keys are commented out in the sample.
        assert!(cfg.iupf_n4.is_none() && cfg.gfbr_budget_mbps.is_none());
    }

    /// An env var overrides the file value, and the file value is used when the env
    /// var is unset — the G5 precedence, exercised through the SMF's own settings.
    #[test]
    fn env_overrides_file_value() {
        use common::config::resolve;
        let cfg = SmfConfig { heartbeat_secs: Some(30), ..Default::default() };
        // File value used when the env var is unset.
        assert_eq!(resolve(HEARTBEAT_SECS_ENV, cfg.heartbeat_secs, DEFAULT_HEARTBEAT_SECS), 30);
        // env wins over the file value.
        // SAFETY: single-threaded test, key is unique to the SMF.
        unsafe { std::env::set_var(HEARTBEAT_SECS_ENV, "5") };
        let cfg = SmfConfig { heartbeat_secs: Some(30), ..Default::default() };
        assert_eq!(resolve(HEARTBEAT_SECS_ENV, cfg.heartbeat_secs, DEFAULT_HEARTBEAT_SECS), 5);
        unsafe { std::env::remove_var(HEARTBEAT_SECS_ENV) };
    }
}
