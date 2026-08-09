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

use crate::otel::Traced;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
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

    /// Base URL of this profile's first service, honouring its advertised `scheme`
    /// (`https` under mTLS, else `http`) — e.g. `https://127.0.0.1:8005`. So a
    /// discovering NF dials the transport the target actually serves.
    pub fn service_base(&self) -> Option<String> {
        let svc = self.nf_services.as_ref()?.first()?;
        let ep = svc.ip_end_points.first()?;
        let ip = ep.ipv4_address.as_deref()?;
        let port = ep.port?;
        let scheme = if svc.scheme.is_empty() { "http" } else { &svc.scheme };
        Some(format!("{scheme}://{ip}:{port}"))
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
    /// The mTLS client-cert thumbprint that registered this NF (RFC 8705), when the
    /// registration arrived over mTLS. Access-token requests for this instance must
    /// present the same certificate (design/137 F4); `None` under cleartext SBI.
    cert_fp: Option<String>,
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
    /// SBI signing secret for HS256 tokens (`None` = no shared-secret signing).
    secret: Option<Vec<u8>>,
    /// The NRF's ES256 private key (asymmetric mode) — signs tokens; its public key
    /// is served at `/oauth2/jwks`. Takes precedence over `secret`.
    signing_key: Option<Arc<crate::oauth::Es256Key>>,
}

impl Default for NrfStore {
    fn default() -> Self {
        Self::with_heartbeat_timer(DEFAULT_HEARTBEAT_TIMER)
    }
}

impl NrfStore {
    /// A registry that assigns `heartbeat_timer` and evicts after 2× that interval.
    pub fn with_heartbeat_timer(heartbeat_timer: Duration) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            heartbeat_timer,
            secret: None,
            signing_key: None,
        }
    }

    /// Enable HS256 token signing with this shared secret. In production pass
    /// `oauth::sbi_secret()`; `None` leaves it disabled.
    pub fn with_secret(mut self, secret: Option<Vec<u8>>) -> Self {
        self.secret = secret;
        self
    }

    /// Enable ES256 token signing with this private key (asymmetric mode); its
    /// public key is served at `/oauth2/jwks`.
    pub fn with_signing_key(mut self, key: crate::oauth::Es256Key) -> Self {
        self.signing_key = Some(Arc::new(key));
        self
    }

    /// Whether any token signing is enabled (HS256 or ES256).
    fn oauth_enabled(&self) -> bool {
        self.secret.is_some() || self.signing_key.is_some()
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

    /// Whether an NF instance id is currently registered (alive) — the NRF checks
    /// this before issuing it an access token.
    pub fn is_registered(&self, nf_instance_id: &str) -> bool {
        let mut g = self.entries.lock().unwrap();
        self.purge_stale(&mut g);
        g.contains_key(nf_instance_id)
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
        .route("/oauth2/token", post(access_token))
        .route("/oauth2/jwks", get(jwks))
        .with_state(store)
}

/// `GET /oauth2/jwks` — the NRF's public signing keys (asymmetric mode). Empty in
/// shared-secret / disabled mode.
async fn jwks(State(store): State<NrfStore>) -> Json<crate::oauth::Jwks> {
    Json(store.signing_key.as_ref().map(|k| k.jwks()).unwrap_or_default())
}

// ── Nnrf_AccessToken (TS 29.510 §6.3) — the OAuth2 authorization server ────────

/// `POST /oauth2/token` — issue an access token for a `client_credentials`
/// request. Requires `RADIAN_SBI_SECRET` (else `404` — SBI security disabled) and
/// that the requesting NF is registered. See [`crate::oauth`] for the trust model.
async fn access_token(
    State(store): State<NrfStore>,
    client_cert: Option<axum::Extension<crate::oauth::ClientCert>>,
    Json(req): Json<crate::oauth::AccessTokenReq>,
) -> Result<Json<crate::oauth::AccessTokenRsp>, (StatusCode, Json<crate::ProblemDetails>)> {
    let problem = |status: StatusCode, cause: &str, detail: &str| {
        (
            status,
            Json(crate::ProblemDetails {
                status: Some(status.as_u16()),
                cause: Some(cause.to_string()),
                detail: Some(detail.to_string()),
                ..Default::default()
            }),
        )
    };
    if !store.oauth_enabled() {
        return Err(problem(StatusCode::NOT_FOUND, "SERVICE_DISABLED", "SBI security is not enabled"));
    }
    if req.grant_type != "client_credentials" {
        return Err(problem(StatusCode::BAD_REQUEST, "UNSUPPORTED_GRANT_TYPE", "expected client_credentials"));
    }
    // Only a registered NF may obtain a token (ties issuance to the registry).
    if !store.is_registered(&req.nf_instance_id) {
        return Err(problem(StatusCode::FORBIDDEN, "UNAUTHORIZED_CLIENT", "requesting NF is not registered"));
    }
    // Bind issuance to the authenticated mTLS caller (design/137 F4): the presenting
    // certificate must be the one that registered this NF instance, so a core NF cannot
    // obtain a token under another NF's identity. Skipped under cleartext SBI (no cert).
    if let Some(axum::Extension(cert)) = &client_cert {
        let bound = {
            let mut g = store.entries.lock().unwrap();
            store.purge_stale(&mut g);
            g.get(&req.nf_instance_id).and_then(|e| e.cert_fp.clone())
        };
        if bound.as_deref() != Some(cert.0.as_str()) {
            return Err(problem(
                StatusCode::FORBIDDEN,
                "UNAUTHORIZED_CLIENT",
                "client certificate does not match the registered NF instance",
            ));
        }
    }
    // Prefer asymmetric (ES256) signing when a private key is configured.
    let rsp = match (&store.signing_key, &store.secret) {
        (Some(key), _) => crate::oauth::issue_token_es256(key, "radian-nrf", &req),
        (None, Some(secret)) => crate::oauth::issue_token(secret, "radian-nrf", &req),
        (None, None) => unreachable!("oauth_enabled() checked above"),
    };
    tracing::info!(client = %req.nf_instance_id, target = %req.target_nf_type, "issued SBI access token");
    Ok(Json(rsp))
}

// ── Nnrf_NFManagement ────────────────────────────────────────────────────────

async fn register(
    State(store): State<NrfStore>,
    Path(id): Path<String>,
    client_cert: Option<axum::Extension<crate::oauth::ClientCert>>,
    Json(mut profile): Json<NfProfile>,
) -> impl IntoResponse {
    profile.nf_instance_id = id.clone();
    // The NRF assigns the heartbeat contract (TS 29.510): the NF must PATCH at
    // this interval or be evicted. The wire field is whole seconds — never
    // advertise 0 even if the store's timer is sub-second (tests).
    profile.heart_beat_timer = Some(store.heartbeat_timer.as_secs().max(1) as u32);
    let fp = client_cert.map(|axum::Extension(c)| c.0);
    let mut g = store.entries.lock().unwrap();
    // A cert-bound registration may only be updated by the same certificate — a core NF
    // (even one holding a valid core cert) must not hijack another NF's registration to
    // redirect its discovery or impersonate it (design/137 F4).
    if let Some(existing) = g.get(&id) {
        if let Some(bound) = &existing.cert_fp {
            if fp.as_deref() != Some(bound.as_str()) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(crate::ProblemDetails {
                        status: Some(403),
                        cause: Some("UNAUTHORIZED_CLIENT".into()),
                        detail: Some("registration is bound to a different certificate".into()),
                        ..Default::default()
                    }),
                )
                    .into_response();
            }
        }
    }
    g.insert(id, Entry { profile: profile.clone(), last_seen: Instant::now(), cert_fp: fp });
    (StatusCode::CREATED, Json(profile)).into_response()
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
#[derive(Clone)]
pub struct NrfClient {
    base: String,
    http: reqwest::Client,
}

impl NrfClient {
    /// Target an NRF at `base_url`, e.g. `http://127.0.0.1:8000`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into(),
            http: crate::sbi_client(),
        }
    }

    /// NFRegister (PUT). Returns the stored profile.
    pub async fn register(&self, profile: &NfProfile) -> Result<NfProfile, SbiError> {
        let resp = self
            .http
            .put(self.nfm_url(&profile.nf_instance_id))
            .json(profile)
            .traced()
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// NFUpdate / heartbeat (PATCH).
    pub async fn heartbeat(&self, nf_instance_id: &str) -> Result<(), SbiError> {
        self.http
            .patch(self.nfm_url(nf_instance_id))
            .traced()
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// NFDeregister (DELETE).
    pub async fn deregister(&self, nf_instance_id: &str) -> Result<(), SbiError> {
        self.http
            .delete(self.nfm_url(nf_instance_id))
            .traced()
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
            .traced()
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
            .traced()
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

    /// An NRF endpoint over `store` that stamps every request with `cert_fp` as if it
    /// arrived over mTLS under that client certificate (what [`crate::tls`] injects).
    async fn spawn_nrf_as(store: NrfStore, cert_fp: &str) -> String {
        let app = router(store).layer(axum::Extension(crate::oauth::ClientCert(cert_fp.to_string())));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// design/137 F4: with mTLS, the NRF binds each registration + access token to the
    /// client certificate that registered the NF, so another core NF (a different cert)
    /// can neither obtain a token as that NF nor hijack its registration.
    #[tokio::test]
    async fn nrf_binds_tokens_to_the_registering_client_certificate() {
        let store = NrfStore::default().with_secret(Some(vec![0x44u8; 32]));
        // Same registry, two callers distinguished by their certificate thumbprint.
        let amf_ep = spawn_nrf_as(store.clone(), "amf-cert-fp").await;
        let smf_ep = spawn_nrf_as(store.clone(), "smf-cert-fp").await;
        let http = crate::sbi_client();
        let token_req = serde_json::json!({
            "grant_type": "client_credentials",
            "nfInstanceId": "amf-1",
            "targetNfType": "UDR",
            "scope": "nudr-dr",
        });

        // The AMF registers over its cert, then obtains a token bound to that cert.
        let reg = http
            .put(format!("{amf_ep}/nnrf-nfm/v1/nf-instances/amf-1"))
            .json(&NfProfile::new("amf-1", "AMF", "127.0.0.1"))
            .send()
            .await
            .unwrap();
        assert_eq!(reg.status(), 201);
        let ok = http.post(format!("{amf_ep}/oauth2/token")).json(&token_req).send().await.unwrap();
        assert_eq!(ok.status(), 200, "the registering certificate gets a token");

        // A different certificate cannot obtain a token as amf-1…
        let stolen = http.post(format!("{smf_ep}/oauth2/token")).json(&token_req).send().await.unwrap();
        assert_eq!(stolen.status(), 403, "a different certificate can't get a token as amf-1");

        // …nor hijack amf-1's registration (which would redirect its discovery).
        let hijack = http
            .put(format!("{smf_ep}/nnrf-nfm/v1/nf-instances/amf-1"))
            .json(&NfProfile::new("amf-1", "AMF", "6.6.6.6"))
            .send()
            .await
            .unwrap();
        assert_eq!(hijack.status(), 403, "a different certificate can't hijack amf-1's registration");

        // The rightful cert still updates its own registration.
        let reup = http
            .put(format!("{amf_ep}/nnrf-nfm/v1/nf-instances/amf-1"))
            .json(&NfProfile::new("amf-1", "AMF", "127.0.0.2"))
            .send()
            .await
            .unwrap();
        assert_eq!(reup.status(), 201, "the registering certificate can re-register");
    }

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

    /// `service_base` honours the advertised scheme so a discovering NF dials the
    /// transport (http/https) the target actually serves — the mTLS mesh (design/57).
    #[test]
    fn service_base_follows_advertised_scheme() {
        let mut profile = NfProfile::new("udr-1", "UDR", "127.0.0.1");
        let svc = |scheme: &str| NfService {
            service_instance_id: "nudr-dr-1".into(),
            service_name: "nudr-dr".into(),
            scheme: scheme.into(),
            ip_end_points: vec![IpEndPoint {
                ipv4_address: Some("127.0.0.1".into()),
                port: Some(8005),
            }],
        };

        profile.nf_services = Some(vec![svc("https")]);
        assert_eq!(profile.service_base().as_deref(), Some("https://127.0.0.1:8005"));

        profile.nf_services = Some(vec![svc("http")]);
        assert_eq!(profile.service_base().as_deref(), Some("http://127.0.0.1:8005"));

        // An empty scheme (older profile) defaults to http, not an empty scheme.
        profile.nf_services = Some(vec![svc("")]);
        assert_eq!(profile.service_base().as_deref(), Some("http://127.0.0.1:8005"));

        // No service → no base.
        profile.nf_services = None;
        assert_eq!(profile.service_base(), None);
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
