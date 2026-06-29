//! Nnrf — Network Repository Function service (TS 29.510): NF registration,
//! heartbeat, deregistration, and discovery over the SBI (HTTP/2 + JSON).
//!
//! The NRF is the registry every other NF depends on. This module provides the
//! data model, an in-memory NRF [`router`] (server side), and an [`NrfClient`]
//! that other NFs use to register themselves and discover peers.
//!
//! # Security (intentionally absent — see `design/04`)
//!
//! These endpoints are **unauthenticated**: any client can register, deregister,
//! or discover NFs, which permits NF impersonation and deregistration DoS. This is
//! a deliberate, temporary state for the cleartext-h2c development phase. The real
//! fix is the TS 33.501 model — mutual TLS between NFs plus OAuth2 access tokens
//! with the NRF as token endpoint — tracked as the "SBI security hardening" slice.
//! Do not deploy this NRF on an untrusted network.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::SbiError;

fn default_registered() -> String {
    "REGISTERED".to_string()
}

/// NF profile (TS 29.510 §6.1.6.2.2), trimmed to the fields this stack uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfProfile {
    // The path is authoritative on register, so the body field is optional.
    #[serde(default)]
    pub nf_instance_id: String,
    pub nf_type: String,
    #[serde(default = "default_registered")]
    pub nf_status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv4_addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nf_services: Option<Vec<NfService>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heart_beat_timer: Option<u32>,
}

impl NfProfile {
    /// Minimal `REGISTERED` profile for `nf_type`, reachable at `ipv4`.
    pub fn new(
        nf_instance_id: impl Into<String>,
        nf_type: impl Into<String>,
        ipv4: impl Into<String>,
    ) -> Self {
        Self {
            nf_instance_id: nf_instance_id.into(),
            nf_type: nf_type.into(),
            nf_status: "REGISTERED".to_string(),
            ipv4_addresses: vec![ipv4.into()],
            nf_services: None,
            heart_beat_timer: None,
        }
    }
}

/// A service exposed by an NF (TS 29.510 §6.1.6.2.3), trimmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfService {
    pub service_instance_id: String,
    pub service_name: String,
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_end_points: Vec<IpEndPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpEndPoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// NFDiscovery result (TS 29.510 §6.2.6.2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub nf_instances: Vec<NfProfile>,
}

/// In-memory NF registry shared by the NRF router handlers.
#[derive(Clone, Default)]
pub struct NrfStore(Arc<Mutex<HashMap<String, NfProfile>>>);

impl NrfStore {
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Build the NRF router: Nnrf_NFManagement + Nnrf_NFDiscovery (TS 29.510).
pub fn router(store: NrfStore) -> Router {
    Router::new()
        .route(
            "/nnrf-nfm/v1/nf-instances/{nf_instance_id}",
            put(register).patch(heartbeat).delete(deregister),
        )
        .route("/nnrf-nfm/v1/nf-instances", get(list))
        .route("/nnrf-disc/v1/nf-instances", get(discover))
        .with_state(store)
}

// ── Nnrf_NFManagement ────────────────────────────────────────────────────────

async fn register(
    State(store): State<NrfStore>,
    Path(id): Path<String>,
    Json(mut profile): Json<NfProfile>,
) -> impl IntoResponse {
    profile.nf_instance_id = id.clone();
    store.0.lock().unwrap().insert(id, profile.clone());
    (StatusCode::CREATED, Json(profile))
}

async fn heartbeat(State(store): State<NrfStore>, Path(id): Path<String>) -> StatusCode {
    if store.0.lock().unwrap().contains_key(&id) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn deregister(State(store): State<NrfStore>, Path(id): Path<String>) -> StatusCode {
    store.0.lock().unwrap().remove(&id);
    StatusCode::NO_CONTENT
}

async fn list(State(store): State<NrfStore>) -> Json<SearchResult> {
    let nf_instances = store.0.lock().unwrap().values().cloned().collect();
    Json(SearchResult { nf_instances })
}

// ── Nnrf_NFDiscovery ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct DiscoveryQuery {
    target_nf_type: String,
    #[serde(default)]
    #[allow(dead_code)] // accepted per spec; not yet used for filtering
    requester_nf_type: Option<String>,
}

async fn discover(
    State(store): State<NrfStore>,
    Query(q): Query<DiscoveryQuery>,
) -> Json<SearchResult> {
    let nf_instances = store
        .0
        .lock()
        .unwrap()
        .values()
        .filter(|p| p.nf_type.eq_ignore_ascii_case(&q.target_nf_type))
        .cloned()
        .collect();
    Json(SearchResult { nf_instances })
}

/// Client other NFs use to talk to the NRF over HTTP/2 (h2c).
pub struct NrfClient {
    base: String,
    http: reqwest::Client,
}

impl NrfClient {
    /// Target an NRF at `base_url`, e.g. `http://127.0.0.1:8000`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into(),
            http: crate::h2c_client(),
        }
    }

    /// NFRegister (PUT). Returns the stored profile.
    pub async fn register(&self, profile: &NfProfile) -> Result<NfProfile, SbiError> {
        let resp = self
            .http
            .put(self.nfm_url(&profile.nf_instance_id))
            .json(profile)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// NFUpdate / heartbeat (PATCH).
    pub async fn heartbeat(&self, nf_instance_id: &str) -> Result<(), SbiError> {
        self.http
            .patch(self.nfm_url(nf_instance_id))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// NFDeregister (DELETE).
    pub async fn deregister(&self, nf_instance_id: &str) -> Result<(), SbiError> {
        self.http
            .delete(self.nfm_url(nf_instance_id))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// NFDiscovery (GET) — find NFs of `target_nf_type`.
    pub async fn discover(
        &self,
        target_nf_type: &str,
        requester_nf_type: &str,
    ) -> Result<Vec<NfProfile>, SbiError> {
        let resp = self
            .http
            .get(format!("{}/nnrf-disc/v1/nf-instances", self.base))
            .query(&[
                ("target-nf-type", target_nf_type),
                ("requester-nf-type", requester_nf_type),
            ])
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json::<SearchResult>().await?.nf_instances)
    }

    fn nfm_url(&self, id: &str) -> String {
        format!("{}/nnrf-nfm/v1/nf-instances/{}", self.base, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full NF lifecycle over real h2c: register → discover → heartbeat → deregister.
    #[tokio::test]
    async fn register_discover_heartbeat_deregister() {
        let store = NrfStore::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(listener, router(store)).await.unwrap() });

        let nrf = NrfClient::new(format!("http://{addr}"));

        // An AUSF registers; the AMF discovers it.
        let ausf = NfProfile::new("ausf-1", "AUSF", "127.0.0.1");
        let registered = nrf.register(&ausf).await.unwrap();
        assert_eq!(registered.nf_type, "AUSF");
        assert_eq!(registered.nf_status, "REGISTERED");

        let found = nrf.discover("AUSF", "AMF").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].nf_instance_id, "ausf-1");

        // No UDM registered yet → empty discovery.
        assert!(nrf.discover("UDM", "AMF").await.unwrap().is_empty());

        nrf.heartbeat("ausf-1").await.unwrap();
        nrf.deregister("ausf-1").await.unwrap();
        assert!(nrf.discover("AUSF", "AMF").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn heartbeat_unknown_nf_errors() {
        let store = NrfStore::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(listener, router(store)).await.unwrap() });

        let nrf = NrfClient::new(format!("http://{addr}"));
        // 404 → reqwest error_for_status → SbiError.
        assert!(nrf.heartbeat("never-registered").await.is_err());
    }
}
