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
pub mod nchf;
pub mod nnrf;
pub mod npcf;
pub mod npcf_am;
pub mod oauth;
pub mod tls;
pub mod nudm;
pub mod nudr;

#[derive(Debug, thiserror::Error)]
pub enum SbiError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("tls: {0}")]
    Tls(String),
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

/// Install the **ring** rustls crypto provider as the process default (idempotent).
/// reqwest (built with `rustls-no-provider`, since aws-lc-rs is unavailable) requires
/// a default provider before building *any* client — even a cleartext h2c one.
pub(crate) fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build an HTTP/2-prior-knowledge (cleartext h2c) JSON client for SBI calls.
pub fn h2c_client() -> reqwest::Client {
    ensure_crypto_provider();
    reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("build h2c reqwest client")
}

// ── Process-wide SBI transport (h2c or mutual TLS) ────────────────────────────

struct SbiTransport {
    /// The default shared client, cloned out by [`sbi_client`].
    client: reqwest::Client,
    /// The mTLS client config, kept so bespoke clients (e.g. the no-redirect
    /// deregistration callback) can be rebuilt on the same transport.
    tls: Option<rustls::ClientConfig>,
    scheme: &'static str,
}

static SBI_TRANSPORT: std::sync::OnceLock<SbiTransport> = std::sync::OnceLock::new();

/// Configure the process-wide SBI transport from an optional mTLS identity. With an
/// identity, every SBI client dials over **mutual TLS** and NFs advertise/discover
/// `https`; without, cleartext h2c (`http`). Call once at NF startup, before building
/// clients. Idempotent — a second call is ignored.
pub fn configure_transport(identity: Option<&tls::TlsIdentity>) {
    let transport = match identity {
        Some(id) => {
            let tls = id.client_config().expect("build mTLS client config");
            SbiTransport {
                client: id.client().expect("build mTLS SBI client"),
                tls: Some(tls),
                scheme: "https",
            }
        }
        None => SbiTransport { client: h2c_client(), tls: None, scheme: "http" },
    };
    let _ = SBI_TRANSPORT.set(transport);
}

/// The process-wide SBI HTTP client — mutual TLS when [`configure_transport`] was
/// given an identity, else cleartext h2c. Client constructors use this.
pub fn sbi_client() -> reqwest::Client {
    SBI_TRANSPORT.get().map(|t| t.client.clone()).unwrap_or_else(h2c_client)
}

/// A `reqwest::ClientBuilder` pre-configured for the SBI transport (mTLS or h2c), so
/// callers needing extra options (e.g. `.redirect(none)`) build on the right stack.
pub fn sbi_client_builder() -> reqwest::ClientBuilder {
    ensure_crypto_provider();
    match SBI_TRANSPORT.get().and_then(|t| t.tls.clone()) {
        Some(cfg) => reqwest::Client::builder().use_preconfigured_tls(cfg),
        None => reqwest::Client::builder().http2_prior_knowledge(),
    }
}

/// The SBI URL scheme this NF advertises and dials (`https` under mTLS, else `http`).
pub fn sbi_scheme() -> &'static str {
    SBI_TRANSPORT.get().map(|t| t.scheme).unwrap_or("http")
}

/// Rewrite a configured base URL's scheme to match the SBI transport
/// (`http`↔`https`) — for env-supplied bases (e.g. the NRF) under mTLS.
pub fn sbi_base(base: impl Into<String>) -> String {
    let base = base.into();
    match (sbi_scheme(), base.strip_prefix("http://"), base.strip_prefix("https://")) {
        ("https", Some(rest), _) => format!("https://{rest}"),
        ("http", _, Some(rest)) => format!("http://{rest}"),
        _ => base,
    }
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
