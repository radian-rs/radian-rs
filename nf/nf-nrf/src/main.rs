//! NRF — Network Repository Function (Nnrf, TS 29.510). SBI-only (JSON).
//! Service registration/discovery; the foundational NF every other NF talks to.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("nrf");

    // Nnrf_NFManagement + Nnrf_NFDiscovery (TS 29.510) over the SBI. Registrations
    // are soft state: NFs heartbeat at the assigned interval or get evicted.
    let store = match std::env::var("RADIAN_NRF_HEARTBEAT_SECS") {
        Ok(v) => {
            let secs: u64 = v.parse().map_err(|e| anyhow::anyhow!("RADIAN_NRF_HEARTBEAT_SECS: {e}"))?;
            sbi_core::nnrf::NrfStore::with_heartbeat_timer(std::time::Duration::from_secs(secs.max(1)))
        }
        Err(_) => sbi_core::nnrf::NrfStore::default(),
    };
    // Enable the OAuth2 token endpoint. Asymmetric (ES256 + JWKS) when
    // RADIAN_SBI_OAUTH=asymmetric — the NRF generates a private key and publishes
    // its public key at /oauth2/jwks (design/55); else HS256 with a shared secret
    // (RADIAN_SBI_SECRET, design/46); else the SBI is open.
    let store = if sbi_core::oauth::asymmetric_enabled() {
        let key = sbi_core::oauth::Es256Key::generate();
        tracing::info!(kid = %key.kid(), "SBI security enabled (asymmetric ES256) — JWKS at /oauth2/jwks");
        store.with_signing_key(key)
    } else {
        let store = store.with_secret(sbi_core::oauth::sbi_secret());
        if sbi_core::oauth::sbi_secret().is_some() {
            tracing::info!("SBI security enabled (shared secret HS256) — tokens at /oauth2/token");
        }
        store
    };
    let sbi: SocketAddr = "0.0.0.0:8000".parse()?;
    sbi_core::run(sbi, sbi_core::nnrf::router(store)).await?;
    Ok(())
}
