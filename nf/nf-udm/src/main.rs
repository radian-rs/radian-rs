//! UDM — Unified Data Management (Nudm, TS 29.503). SBI-only (JSON).
//!
//! Stateless front-end over a persistent subscriber store (`subscriber-db`, redb
//! backend). Architecturally the data belongs in the UDR (Nudr) — relocating it
//! behind `nf-udr` is a later slice.

use std::net::SocketAddr;
use std::sync::Arc;

use subscriber_db::{RedbStore, SubscriberDb, SubscriberStore};

const DEMO_SUPI: &str = "imsi-999700000000001";
const UDM_DB_PATH: &str = "radiant-udm.redb";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("udm");

    // Persistent subscriber store; provision a demo subscriber (TS 35.208 key) once.
    let store = RedbStore::open(UDM_DB_PATH)
        .map_err(|e| anyhow::anyhow!("open UDM store {UDM_DB_PATH}: {e}"))?;
    if !store.exists(DEMO_SUPI) {
        store
            .provision_hex(
                DEMO_SUPI,
                "465b5ce8b199b49faa5f0a2ee238a6bc",
                "cd63cb71954a9f4e48a5994e37a02baf",
                "8000",
            )
            .map_err(|e| anyhow::anyhow!("provision demo subscriber: {e}"))?;
        tracing::info!(supi = DEMO_SUPI, "provisioned demo subscriber");
    }

    let store: Arc<dyn SubscriberStore> = Arc::new(store);
    let sbi: SocketAddr = "0.0.0.0:8004".parse()?;
    sbi_core::run(sbi, sbi_core::nudm::router(store)).await?;
    Ok(())
}
