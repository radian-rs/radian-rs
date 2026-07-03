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
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::SbiError;

/// Heartbeat interval the NRF assigns to registering NFs (TS 29.510 `heartBeatTimer`).
pub const DEFAULT_HEARTBEAT_TIMER: Duration = Duration::from_secs(10);

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
    /// SMF capabilities (TS 29.510 §6.1.6.2.10) — which slices/DNNs this SMF
    /// serves. Present on SMF profiles; drives `(S-NSSAI, DNN)` discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smf_info: Option<SmfInfo>,
}

/// SMF-specific NF info (TS 29.510 §6.1.6.2.10), trimmed to the slice/DNN map
/// used for SMF selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmfInfo {
    pub s_nssai_smf_info_list: Vec<SnssaiSmfInfoItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnssaiSmfInfoItem {
    pub s_nssai: ProfileSnssai,
    pub dnn_smf_info_list: Vec<DnnSmfInfoItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSnssai {
    pub sst: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnnSmfInfoItem {
    pub dnn: String,
}

impl SmfInfo {
    /// Whether this SMF serves `dnn`, optionally within slice `snssai`
    /// (`(sst, optional lowercase-hex sd)`). `None` slice → any slice serving
    /// the DNN matches.
    pub fn serves(&self, snssai: Option<(u8, Option<&str>)>, dnn: &str) -> bool {
        self.s_nssai_smf_info_list.iter().any(|item| {
            let slice_ok = match snssai {
                None => true,
                Some((sst, sd)) => {
                    item.s_nssai.sst == sst
                        && match (item.s_nssai.sd.as_deref(), sd) {
                            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                            (None, None) => true,
                            _ => false,
                        }
                }
            };
            slice_ok && item.dnn_smf_info_list.iter().any(|d| d.dnn == dnn)
        })
    }

    /// Build an SmfInfo from `(sst, optional sd, dnn)` triples (config helper).
    pub fn from_served(served: &[(u8, Option<&str>, &str)]) -> Self {
        use std::collections::BTreeMap;
        // Group DNNs under each (sst, sd) slice.
        let mut by_slice: BTreeMap<(u8, Option<String>), Vec<String>> = BTreeMap::new();
        for (sst, sd, dnn) in served {
            by_slice
                .entry((*sst, sd.map(|s| s.to_string())))
                .or_default()
                .push(dnn.to_string());
        }
        SmfInfo {
            s_nssai_smf_info_list: by_slice
                .into_iter()
                .map(|((sst, sd), dnns)| SnssaiSmfInfoItem {
                    s_nssai: ProfileSnssai { sst, sd },
                    dnn_smf_info_list: dnns.into_iter().map(|dnn| DnnSmfInfoItem { dnn }).collect(),
                })
                .collect(),
        }
    }
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
            smf_info: None,
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

/// A registered profile plus when we last heard from the NF.
struct Entry {
    profile: NfProfile,
    last_seen: Instant,
}

/// In-memory NF registry shared by the NRF router handlers.
///
/// Registrations are **soft state**: an NF must heartbeat (PATCH) within twice the
/// assigned `heartBeatTimer` or its profile is evicted — a crashed NF stops being
/// discoverable instead of lingering forever. Eviction is lazy (on read/heartbeat);
/// a heartbeat after eviction returns `404`, telling the NF to re-register.
#[derive(Clone)]
pub struct NrfStore {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    heartbeat_timer: Duration,
}

impl Default for NrfStore {
    fn default() -> Self {
        Self::with_heartbeat_timer(DEFAULT_HEARTBEAT_TIMER)
    }
}

impl NrfStore {
    /// A registry that assigns `heartbeat_timer` and evicts after 2× that interval.
    pub fn with_heartbeat_timer(heartbeat_timer: Duration) -> Self {
        Self { entries: Arc::new(Mutex::new(HashMap::new())), heartbeat_timer }
    }

    pub fn len(&self) -> usize {
        let mut g = self.entries.lock().unwrap();
        self.purge_stale(&mut g);
        g.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// One missed heartbeat is tolerated; a second means the NF is gone.
    fn ttl(&self) -> Duration {
        2 * self.heartbeat_timer
    }

    fn purge_stale(&self, entries: &mut HashMap<String, Entry>) {
        let ttl = self.ttl();
        entries.retain(|id, e| {
            let alive = e.last_seen.elapsed() <= ttl;
            if !alive {
                tracing::info!(nf = %id, nf_type = %e.profile.nf_type, "evicting stale NF (heartbeat expired)");
            }
            alive
        });
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
    // The NRF assigns the heartbeat contract (TS 29.510): the NF must PATCH at
    // this interval or be evicted. The wire field is whole seconds — never
    // advertise 0 even if the store's timer is sub-second (tests).
    profile.heart_beat_timer = Some(store.heartbeat_timer.as_secs().max(1) as u32);
    store
        .entries
        .lock()
        .unwrap()
        .insert(id, Entry { profile: profile.clone(), last_seen: Instant::now() });
    (StatusCode::CREATED, Json(profile))
}

async fn heartbeat(State(store): State<NrfStore>, Path(id): Path<String>) -> StatusCode {
    let mut g = store.entries.lock().unwrap();
    store.purge_stale(&mut g);
    match g.get_mut(&id) {
        Some(e) => {
            e.last_seen = Instant::now();
            StatusCode::NO_CONTENT
        }
        None => StatusCode::NOT_FOUND,
    }
}

async fn deregister(State(store): State<NrfStore>, Path(id): Path<String>) -> StatusCode {
    store.entries.lock().unwrap().remove(&id);
    StatusCode::NO_CONTENT
}

async fn list(State(store): State<NrfStore>) -> Json<SearchResult> {
    let mut g = store.entries.lock().unwrap();
    store.purge_stale(&mut g);
    let nf_instances = g.values().map(|e| e.profile.clone()).collect();
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
    // (S-NSSAI, DNN) filter for SMF selection. Trim: the spec encodes `snssais`
    // as a JSON array; we take scalar `snssai-sst` / `snssai-sd` / `dnn`.
    #[serde(default)]
    snssai_sst: Option<u8>,
    #[serde(default)]
    snssai_sd: Option<String>,
    #[serde(default)]
    dnn: Option<String>,
}

async fn discover(
    State(store): State<NrfStore>,
    Query(q): Query<DiscoveryQuery>,
) -> Json<SearchResult> {
    let mut g = store.entries.lock().unwrap();
    store.purge_stale(&mut g);
    let nf_instances = g
        .values()
        .filter(|e| e.profile.nf_type.eq_ignore_ascii_case(&q.target_nf_type))
        .filter(|e| match &q.dnn {
            // A DNN filter selects SMFs whose smf_info serves it (optionally in
            // the given slice). A profile without smf_info can't be slice/DNN
            // matched, so it's excluded when the query is filtered.
            Some(dnn) => e
                .profile
                .smf_info
                .as_ref()
                .is_some_and(|info| info.serves(q.snssai_sst.map(|sst| (sst, q.snssai_sd.as_deref())), dnn)),
            None => true,
        })
        .map(|e| e.profile.clone())
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

    /// NFDiscovery (GET) — find NFs of `target_nf_type` (no slice/DNN filter).
    pub async fn discover(
        &self,
        target_nf_type: &str,
        requester_nf_type: &str,
    ) -> Result<Vec<NfProfile>, SbiError> {
        self.discover_for(target_nf_type, requester_nf_type, None, None).await
    }

    /// NFDiscovery (GET) with an optional `(S-NSSAI, DNN)` filter — SMF selection.
    /// `snssai` is `(sst, optional lowercase-hex sd)`.
    pub async fn discover_for(
        &self,
        target_nf_type: &str,
        requester_nf_type: &str,
        snssai: Option<(u8, Option<&str>)>,
        dnn: Option<&str>,
    ) -> Result<Vec<NfProfile>, SbiError> {
        let mut query: Vec<(&str, String)> = vec![
            ("target-nf-type", target_nf_type.to_string()),
            ("requester-nf-type", requester_nf_type.to_string()),
        ];
        if let Some(dnn) = dnn {
            query.push(("dnn", dnn.to_string()));
        }
        if let Some((sst, sd)) = snssai {
            query.push(("snssai-sst", sst.to_string()));
            if let Some(sd) = sd {
                query.push(("snssai-sd", sd.to_string()));
            }
        }
        let resp = self
            .http
            .get(format!("{}/nnrf-disc/v1/nf-instances", self.base))
            .query(&query)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json::<SearchResult>().await?.nf_instances)
    }

    /// NFListRetrieval (GET) — every currently-registered profile. The NRF purges
    /// heartbeat-expired NFs lazily on read, so this reflects live instances.
    pub async fn list_instances(&self) -> Result<Vec<NfProfile>, SbiError> {
        let resp = self
            .http
            .get(format!("{}/nnrf-nfm/v1/nf-instances", self.base))
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json::<SearchResult>().await?.nf_instances)
    }

    fn nfm_url(&self, id: &str) -> String {
        format!("{}/nnrf-nfm/v1/nf-instances/{}", self.base, id)
    }
}

/// Register `profile` with the NRF and keep the registration alive: spawns a
/// background task that heartbeats at the NRF-assigned `heartBeatTimer` interval
/// and re-registers if the NRF has evicted us (heartbeat → 404). Returns once the
/// initial registration succeeds.
pub async fn register_and_maintain(nrf_base: &str, profile: NfProfile) -> Result<(), SbiError> {
    let client = NrfClient::new(nrf_base.to_string());
    let registered = client.register(&profile).await?;
    let period = Duration::from_secs(u64::from(
        registered.heart_beat_timer.unwrap_or(DEFAULT_HEARTBEAT_TIMER.as_secs() as u32).max(1),
    ));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            if client.heartbeat(&profile.nf_instance_id).await.is_ok() {
                continue;
            }
            match client.register(&profile).await {
                Ok(_) => tracing::info!(nf = %profile.nf_instance_id, "re-registered with NRF after eviction"),
                Err(e) => tracing::warn!(nf = %profile.nf_instance_id, "NRF heartbeat and re-register failed: {e}"),
            }
        }
    });
    Ok(())
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
    async fn discovery_filters_smf_by_snssai_and_dnn() {
        let nrf = serve(NrfStore::default()).await;

        // SMF-A serves slice 1/010203 dnn internet; SMF-B serves slice 2 dnn ims.
        let mut a = NfProfile::new("smf-a", "SMF", "127.0.0.1");
        a.smf_info = Some(SmfInfo::from_served(&[(1, Some("010203"), "internet")]));
        let mut b = NfProfile::new("smf-b", "SMF", "127.0.0.2");
        b.smf_info = Some(SmfInfo::from_served(&[(2, None, "ims")]));
        nrf.register(&a).await.unwrap();
        nrf.register(&b).await.unwrap();

        // Filter by (1/010203, internet) → only SMF-A.
        let got =
            nrf.discover_for("SMF", "AMF", Some((1, Some("010203"))), Some("internet")).await.unwrap();
        assert_eq!(got.iter().map(|p| p.nf_instance_id.as_str()).collect::<Vec<_>>(), ["smf-a"]);

        // Filter by dnn ims (any slice) → only SMF-B.
        let got = nrf.discover_for("SMF", "AMF", None, Some("ims")).await.unwrap();
        assert_eq!(got.iter().map(|p| p.nf_instance_id.as_str()).collect::<Vec<_>>(), ["smf-b"]);

        // A DNN nobody serves → empty.
        assert!(nrf.discover_for("SMF", "AMF", None, Some("corporate")).await.unwrap().is_empty());

        // Right DNN, wrong slice → empty (slice must match when given).
        assert!(nrf.discover_for("SMF", "AMF", Some((9, None)), Some("internet")).await.unwrap().is_empty());

        // Unfiltered discover still returns both.
        assert_eq!(nrf.discover("SMF", "AMF").await.unwrap().len(), 2);
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

    async fn serve(store: NrfStore) -> NrfClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(listener, router(store)).await.unwrap() });
        NrfClient::new(format!("http://{addr}"))
    }

    #[tokio::test]
    async fn register_assigns_heartbeat_timer() {
        let nrf = serve(NrfStore::with_heartbeat_timer(Duration::from_secs(7))).await;
        let registered = nrf.register(&NfProfile::new("smf-1", "SMF", "127.0.0.1")).await.unwrap();
        assert_eq!(registered.heart_beat_timer, Some(7));
    }

    #[tokio::test]
    async fn stale_nf_is_evicted_and_heartbeat_404s() {
        // 50ms heartbeat timer → eviction after 100ms of silence.
        let nrf = serve(NrfStore::with_heartbeat_timer(Duration::from_millis(50))).await;
        nrf.register(&NfProfile::new("ausf-1", "AUSF", "127.0.0.1")).await.unwrap();
        assert_eq!(nrf.discover("AUSF", "AMF").await.unwrap().len(), 1);

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(nrf.discover("AUSF", "AMF").await.unwrap().is_empty(), "stale NF still discoverable");
        // Post-eviction heartbeat → 404, the signal to re-register.
        assert!(nrf.heartbeat("ausf-1").await.is_err());
    }

    #[tokio::test]
    async fn heartbeat_keeps_nf_discoverable_past_ttl() {
        let nrf = serve(NrfStore::with_heartbeat_timer(Duration::from_millis(50))).await;
        nrf.register(&NfProfile::new("ausf-1", "AUSF", "127.0.0.1")).await.unwrap();
        // Heartbeat every 40ms for 400ms — well past the 100ms TTL.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(40)).await;
            nrf.heartbeat("ausf-1").await.unwrap();
        }
        assert_eq!(nrf.discover("AUSF", "AMF").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn register_and_maintain_survives_eviction() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // The advertised heartBeatTimer is whole seconds, so the maintenance loop
        // can't be tested faster than a 1s interval (TTL 2s).
        let store = NrfStore::with_heartbeat_timer(Duration::from_secs(1));
        tokio::spawn(async move { crate::run_on(listener, router(store)).await.unwrap() });

        let base = format!("http://{addr}");
        register_and_maintain(&base, NfProfile::new("smf-1", "SMF", "127.0.0.1")).await.unwrap();
        // Past the 2s TTL the maintenance heartbeats (at ~1s, ~2s) must have kept
        // the NF discoverable.
        tokio::time::sleep(Duration::from_millis(2300)).await;
        let found = NrfClient::new(base).discover("SMF", "AMF").await.unwrap();
        assert_eq!(found.len(), 1);
    }
}
