//! UDM — Unified Data Management (Nudm, TS 29.503). SBI-only (JSON).
//! Subscriber data, authentication vectors, registration; persists via UDR.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("udm");

    // Nudm_UEAuthentication (TS 29.503) with a demo subscriber (TS 35.208 test key).
    let db = sbi_core::nudm::SubscriberDb::new();
    db.insert_hex(
        "imsi-999700000000001",
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "cd63cb71954a9f4e48a5994e37a02baf",
        "8000",
    )
    .expect("provision demo subscriber");
    let sbi: SocketAddr = "0.0.0.0:8004".parse()?;
    sbi_core::run(sbi, sbi_core::nudm::router(db)).await?;
    Ok(())
}
