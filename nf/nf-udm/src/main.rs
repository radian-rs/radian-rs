//! UDM — Unified Data Management (Nudm, TS 29.503). SBI-only (JSON).
//!
//! Stateless front-end over a persistent subscriber store (`subscriber-db`, redb
//! backend, owner-only file). Architecturally the data belongs in the UDR (Nudr) —
//! relocating it behind `nf-udr` is a later slice.
//!
//! The demo subscriber uses a **public** test key (TS 35.208) and is provisioned
//! only when `RADIANT_UDM_PROVISION_DEMO=1` — never auto-created — so a production
//! build never ships a known-key (backdoor) account.

use std::net::SocketAddr;
use std::sync::Arc;

use subscriber_db::{RedbStore, SubscriberDb, SubscriberStore};
use tracing::{info, warn};

const DEMO_SUPI: &str = "imsi-999700000000001";
const DEFAULT_DB_PATH: &str = "radiant-udm.redb";
const DEMO_ENV: &str = "RADIANT_UDM_PROVISION_DEMO";
const DB_ENV: &str = "RADIANT_UDM_DB";
const KEK_ENV: &str = "RADIANT_UDM_MASTER_KEY";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("udm");

    let db_path = std::env::var(DB_ENV).unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());
    let store = RedbStore::open(&db_path, master_key()?)
        .map_err(|e| anyhow::anyhow!("open UDM store {db_path}: {e}"))?;

    if demo_enabled() {
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
        warn!(
            supi = DEMO_SUPI,
            "DEMO subscriber enabled (PUBLIC TS 35.208 test key) — do NOT use in production"
        );
    } else {
        info!("demo subscriber disabled (set {DEMO_ENV}=1 to provision the TS 35.208 test subscriber)");
    }

    let store: Arc<dyn SubscriberStore> = Arc::new(store);
    let sbi: SocketAddr = "0.0.0.0:8004".parse()?;
    sbi_core::run(sbi, sbi_core::nudm::router(store)).await?;
    Ok(())
}

fn demo_enabled() -> bool {
    std::env::var(DEMO_ENV).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// The credential-store master key (KEK). From `RADIANT_UDM_MASTER_KEY` (64 hex
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
