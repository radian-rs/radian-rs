//! Shared types and bootstrap helpers for radiant-rs network functions.

use serde::{Deserialize, Serialize};

/// Initialise tracing/logging from `RUST_LOG` (default `info`).
pub fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // `try_init` so multiple NFs in one process (tests) don't panic.
    let _ = fmt().with_env_filter(filter).try_init();
}

/// Log a startup banner for a network function.
pub fn banner(nf: &str) {
    tracing::info!(nf, "radiant-rs network function starting (scaffold)");
}

/// SUPI — Subscription Permanent Identifier, e.g. `imsi-001010000000001`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Supi(pub String);

/// PLMN identity (MCC + MNC).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Plmn {
    pub mcc: String,
    pub mnc: String,
}

/// S-NSSAI — network slice selection assistance information.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Snssai {
    pub sst: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sd: Option<String>,
}
