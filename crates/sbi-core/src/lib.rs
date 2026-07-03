//! Service-Based Interface (SBI) runtime shared by all 5GC network functions.
//!
//! SBI is HTTP/2 + JSON, defined by 3GPP OpenAPI (TS 29.5xx). This crate provides
//! the HTTP/2 (cleartext **h2c**) server runner ([`run`]), an h2c JSON client
//! ([`h2c_client`]), the RFC 7807 [`ProblemDetails`] error body, and the NRF
//! service ([`nnrf`]). Transport is `axum`/`hyper` (server) and `reqwest` (client),
//! both speaking HTTP/2 with prior knowledge — no TLS, matching a typical
//! intra-core SBI deployment.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

pub mod nausf;
pub mod nnrf;
pub mod npcf;
pub mod oauth;
pub mod nudm;
pub mod nudr;

#[derive(Debug, thiserror::Error)]
pub enum SbiError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}

/// RFC 7807 `ProblemDetails`, the SBI error body (TS 29.500).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

/// Bind `addr` and serve an SBI router over HTTP/2 (h2c) + HTTP/1.1.
pub async fn run(addr: SocketAddr, app: axum::Router) -> Result<(), SbiError> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "SBI HTTP/2 listener up");
    run_on(listener, app).await
}

/// Serve an SBI router on an already-bound listener (lets callers pick the port,
/// e.g. an ephemeral `127.0.0.1:0` in tests).
pub async fn run_on(listener: tokio::net::TcpListener, app: axum::Router) -> Result<(), SbiError> {
    axum::serve(listener, app).await?;
    Ok(())
}

/// A root/health router — a real (otherwise empty) HTTP/2 SBI endpoint, used by
/// NFs whose service handlers aren't implemented yet.
pub fn health_router() -> axum::Router {
    axum::Router::new().route("/", axum::routing::get(|| async { "radian-rs SBI" }))
}

/// Build an HTTP/2-prior-knowledge (cleartext h2c) JSON client for SBI calls.
pub fn h2c_client() -> reqwest::Client {
    reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("build h2c reqwest client")
}

/// Generate a fresh NF instance ID (UUIDv4, per TS 29.571 `NfInstanceId`).
pub fn new_nf_instance_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate a random 128-bit RAND challenge (UDM authentication).
pub fn random_rand() -> [u8; 16] {
    let mut r = [0u8; 16];
    getrandom::getrandom(&mut r).expect("getrandom RAND");
    r
}
