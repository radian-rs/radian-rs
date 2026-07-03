//! UDR — Unified Data Repository (Nudr, TS 29.504). SBI-only (JSON).
//!
//! Owns the subscriber store (`subscriber-db`, redb backend, owner-only file,
//! credentials AEAD-encrypted under an injected KEK). The UDM consumes it over
//! Nudr; the ARPF compute is co-hosted here so K never crosses the SBI
//! (design/24 step 1, deviation documented in `sbi_core::nudr`).
//!
//! The demo subscriber uses a **public** test key (TS 35.208) and is provisioned
//! only when `RADIAN_UDR_PROVISION_DEMO=1` — never auto-created — so a production
//! build never ships a known-key (backdoor) account.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use subscriber_db::{DataSet, ProvisionedDataStore, RedbStore, SubscriberDb, SubscriberStore};
use tracing::{info, warn};

const SBI_PORT: u16 = 8005;
const DEMO_SUPI: &str = "imsi-999700000000001";
const DEMO_PLMN: &str = "99970";
const DEFAULT_DB_PATH: &str = "radian-udr.redb";
const DEMO_ENV: &str = "RADIAN_UDR_PROVISION_DEMO";
const DB_ENV: &str = "RADIAN_UDR_DB";
const KEK_ENV: &str = "RADIAN_UDR_MASTER_KEY";
const NRF_ENV: &str = "RADIAN_UDR_NRF";
const DEFAULT_NRF: &str = "http://127.0.0.1:8000";
/// How often to sweep UECM registrations for NFs that have left the NRF.
const SWEEP_ENV: &str = "RADIAN_UDR_UECM_SWEEP_SECS";
const DEFAULT_SWEEP_SECS: u64 = 30;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("udr");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, serve Nudr over mTLS (every
    // client must present a core-CA-signed cert) and dial the NRF / AMF-callback over
    // mTLS; `sbi_scheme()` then yields `https`.
    let tls = sbi_core::tls::TlsIdentity::from_env("udr")?;
    sbi_core::configure_transport(tls.as_ref());

    let db_path = std::env::var(DB_ENV).unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());
    let store = RedbStore::open(&db_path, master_key()?)
        .map_err(|e| anyhow::anyhow!("open UDR store {db_path}: {e}"))?;

    if demo_enabled() {
        provision_demo(&store)?;
        warn!(
            supi = DEMO_SUPI,
            "DEMO subscriber enabled (PUBLIC TS 35.208 test key) — do NOT use in production"
        );
    } else {
        info!("demo subscriber disabled (set {DEMO_ENV}=1 to provision the TS 35.208 test subscriber)");
    }

    // Register with the NRF so front-ends can discover the Nudr service.
    let nrf_base =
        sbi_core::sbi_base(std::env::var(NRF_ENV).unwrap_or_else(|_| DEFAULT_NRF.to_string()));
    match register_with_nrf(&nrf_base, Ipv4Addr::LOCALHOST, SBI_PORT).await {
        Ok(()) => info!(%nrf_base, "registered UDR with NRF"),
        Err(e) => warn!("NRF registration failed (continuing without discovery): {e}"),
    }

    let store: Arc<dyn SubscriberStore> = Arc::new(store);

    // Periodically evict UECM registrations whose serving NF has vanished from
    // the NRF (design/42) — the UECM analogue of the NRF's heartbeat expiry.
    let sweep_secs: u64 = std::env::var(SWEEP_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SWEEP_SECS);
    {
        let store = store.clone();
        let nrf_base = nrf_base.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(sweep_secs));
            loop {
                tick.tick().await;
                let n = sbi_core::nudr::sweep_stale_registrations(&store, &nrf_base).await;
                if n > 0 {
                    info!(evicted = n, "UECM sweep evicted stale registrations");
                }
            }
        });
    }

    let sbi: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    // SBI security (design/46/55): require a valid `UDR` access token — HS256 (shared
    // secret) or ES256 (verified against the NRF's JWKS) — when configured, else open.
    let router = sbi_core::oauth::protect(
        sbi_core::nudr::router(store),
        "UDR",
        sbi_core::oauth::verifier(&nrf_base),
    );
    if sbi_core::oauth::verifier(&nrf_base).is_some() {
        info!("Nudr protected by OAuth2 (audience UDR)");
    }
    // Subscription withdrawals notify the serving AMF recorded in the UECM
    // context data (its deregCallbackUri) — over the same transport (mTLS when on).
    match &tls {
        Some(id) => {
            info!("Nudr served over mutual TLS");
            sbi_core::tls::run_tls(sbi, router, id.server_config()?).await?;
        }
        None => sbi_core::run(sbi, router).await?,
    }
    Ok(())
}

/// Provision the TS 35.208 test subscriber: credentials (idempotent — never resets
/// a live SQN) plus TS 29.505-shaped AM/SM demo documents matching the BDD UE.
fn provision_demo(store: &RedbStore) -> anyhow::Result<()> {
    if !store.exists(DEMO_SUPI) {
        store
            .provision_hex(
                DEMO_SUPI,
                "465b5ce8b199b49faa5f0a2ee238a6bc",
                "cd63cb71954a9f4e48a5994e37a02baf",
                "8000",
            )
            .map_err(|e| anyhow::anyhow!("provision demo subscriber: {e}"))?;
    }
    let am = serde_json::json!({
        "nssai": { "defaultSingleNssais": [{ "sst": 1, "sd": "010203" }] },
        "subscribedUeAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" }
    });
    let sm = serde_json::json!([{
        "singleNssai": { "sst": 1, "sd": "010203" },
        "dnnConfigurations": {
            "internet": {
                "pduSessionTypes": { "defaultSessionType": "IPV4" },
                "sessionAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" },
                // Default QoS flow: non-GBR, 5QI 9. (ARP defaults to priority 8.)
                "5gQosProfile": { "5qi": 9, "arp": { "priorityLevel": 8 } },
                // A demo GBR flow (5QI 1, conversational voice) to exercise per-flow
                // QoS end to end. Real GBR flows are PCF-driven; provisioned here for
                // lack of a PCF.
                "qosFlows": [{
                    "qfi": 2, "fiveQi": 1, "arpPriority": 5, "preEmptCap": true,
                    "gbr": {
                        "gfbrDl": "100 Mbps", "gfbrUl": "100 Mbps",
                        "mfbrDl": "200 Mbps", "mfbrUl": "200 Mbps"
                    }
                }]
            }
        }
    }]);
    // Which DNNs the subscriber may use per subscribed S-NSSAI — the SMF's
    // authorization gate for CreateSMContext.
    let smf_sel = serde_json::json!({
        "subscribedSnssaiInfos": {
            "1-010203": { "dnnInfos": [ { "dnn": "internet" } ] }
        }
    });
    // SM policy data (TS 29.519) — the PCF's per-subscriber policy source. Shaped
    // as `sbi_core::npcf::PolicyConfig` (default decision + optional per-DNN
    // overrides). The default here matches the sm-data QoS so the PCF-driven
    // session is identical to the SMF's sm-data fallback. Not PLMN-scoped (key "").
    let policy = serde_json::json!({
        "default": {
            "sessionAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" },
            "qosFlows": [
                { "qfi": 1, "fiveQi": 9, "arpPriority": 8 },
                { "qfi": 2, "fiveQi": 1, "arpPriority": 5, "preEmptCap": true,
                  "gbr": { "gfbrDl": "100 Mbps", "gfbrUl": "100 Mbps",
                           "mfbrDl": "200 Mbps", "mfbrUl": "200 Mbps" },
                  // Classifier: UDP ports 5000–5010 steer to this GBR flow (the UPF
                  // then polices it against the 200 Mbps MFBR).
                  "filter": { "protocol": 17, "portLow": 5000, "portHigh": 5010 } }
            ]
        }
    });
    store
        .put_provisioned(DataSet::Am, DEMO_SUPI, DEMO_PLMN, &am)
        .and_then(|()| store.put_provisioned(DataSet::Sm, DEMO_SUPI, DEMO_PLMN, &sm))
        .and_then(|()| store.put_provisioned(DataSet::SmfSelection, DEMO_SUPI, DEMO_PLMN, &smf_sel))
        .and_then(|()| store.put_provisioned(DataSet::Policy, DEMO_SUPI, "", &policy))
        .map_err(|e| anyhow::anyhow!("provision demo documents: {e}"))
}

async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(sbi_core::new_nf_instance_id(), "UDR", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "nudr-dr-1".into(),
        service_name: "nudr-dr".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}

fn demo_enabled() -> bool {
    std::env::var(DEMO_ENV).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// The credential-store master key (KEK). From `RADIAN_UDR_MASTER_KEY` (64 hex
/// chars), else an ephemeral key (persisted records become unreadable after restart).
/// In production this should come from an HSM / KMS.
fn master_key() -> anyhow::Result<[u8; 32]> {
    match std::env::var(KEK_ENV) {
        Ok(hex) => {
            subscriber_db::parse_kek_hex(&hex).map_err(|e| anyhow::anyhow!("{KEK_ENV}: {e}"))
        }
        Err(_) => {
            warn!("{KEK_ENV} not set — using an EPHEMERAL master key; persisted credentials become unreadable after restart. Set {KEK_ENV} (64 hex chars) for persistence.");
            Ok(subscriber_db::random_kek())
        }
    }
}
