//! Service-Based Interface (SBI) runtime shared by all 5GC network functions.
//!
//! The SBI is HTTP/2 + JSON, defined by 3GPP OpenAPI (TS 29.5xx). This crate will
//! host the HTTP/2 stack, the generated OpenAPI models, and `multipart/related`
//! handling for the opaque binary parts the SBI tunnels:
//! `application/vnd.3gpp.5gnas` (NAS) and `application/vnd.3gpp.ngap` (NGAP).

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum SbiError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
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

/// A 5GC network function exposing one or more SBI services.
pub trait NfService: Send + Sync {
    /// Service name as registered in the NRF, e.g. `"namf-comm"`.
    fn service_name(&self) -> &'static str;
}

/// Placeholder SBI server bootstrap.
///
/// TODO: replace the raw TCP accept loop with an HTTP/2 stack (hyper/h2 or axum),
/// route generated OpenAPI handlers (TS 29.5xx), and decode `multipart/related`
/// bodies carrying `vnd.3gpp.5gnas` / `vnd.3gpp.ngap` parts.
pub async fn serve(addr: SocketAddr) -> Result<(), SbiError> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "SBI listener bound (placeholder; HTTP/2 stack TODO)");
    loop {
        let (_stream, peer) = listener.accept().await?;
        tracing::debug!(%peer, "accepted SBI connection (no handler yet)");
    }
}
