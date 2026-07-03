//! Nudr_DataRepository — the UDR data-access service (TS 29.504 / 29.505), trimmed.
//!
//! The UDR owns the subscriber store (`subscriber-db`); the UDM and later PCF are
//! stateless front-ends over this API. Provisioned-data resources follow the
//! TS 29.505 resource tree (`/{ueId}/{servingPlmnId}/provisioned-data/…`) with
//! JSON documents stored verbatim.
//!
//! # Deviation: the ARPF stays behind the store boundary
//!
//! TS 29.505 exposes `authentication-subscription` with the permanent key inside,
//! which would put **K on the SBI wire** (currently cleartext h2c). We deliberately
//! deviate: the UDR co-hosts the ARPF compute, exposing `generate-av` instead —
//! the SQN advances and the vector is derived next to the credentials, and only
//! RAND/AUTN/XRES*/K_AUSF ever leave (design/24). When TLS + HSM arrive this seam
//! is where they plug in.
//!
//! # Security: the withdrawal callback is a bounded SSRF surface
//!
//! On subscription withdrawal the UDR POSTs to the serving AMF's stored
//! `deregCallbackUri` (Nudm_UECM). That URI is written through **unauthenticated**
//! SBI endpoints (the whole SBI is cleartext h2c with no OAuth2 — the deferred
//! TS 33.501 hardening slice), so a hostile client can register an arbitrary URI
//! and trigger the callback: server-side request forgery. Mitigations here:
//! [`is_valid_callback_uri`] restricts it to `http`/`https`, and the callback
//! client does **not** follow redirects. The residual risk (an attacker steering
//! the callback at an internal *HTTP* target) is only fully closed by SBI mutual
//! auth — only a cert-holding AMF may register a callback. Do not expose this UDR
//! on an untrusted network.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subscriber_db::{DataSet, SubscriberStore};

use crate::SbiError;

/// Router state: the subscriber store.
#[derive(Clone)]
struct NudrState {
    store: Arc<dyn SubscriberStore>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAvRequest {
    pub mcc: String,
    pub mnc: String,
}

/// A derived 5G HE authentication vector — hex strings, never key material.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeAv {
    pub rand: String,
    pub autn: String,
    pub xres_star: String,
    pub kausf: String,
}

/// Build the UDR router (Nudr_DataRepository) over the subscriber store. A
/// subscription withdrawal (`DELETE …/subscription-data/{ueId}`) notifies the
/// **serving AMF recorded in the UECM context data** at its `deregCallbackUri`
/// (deviation: TS 23.502 mediates this through UDM data-change subscriptions;
/// we collapse UDR→UDM→AMF to UDR→AMF).
pub fn router(store: Arc<dyn SubscriberStore>) -> Router {
    let state = NudrState { store };
    let router = Router::new()
        .route(
            "/nudr-dr/v2/subscription-data/{ue_id}/authentication-data/generate-av",
            post(generate_av),
        )
        .route("/nudr-dr/v2/subscription-data/{ue_id}", delete(delete_subscription))
        .route(
            "/nudr-dr/v2/subscription-data/{ue_id}/context-data/amf-3gpp-access",
            get(get_amf_reg).put(put_amf_reg).delete(delete_amf_reg),
        )
        .route(
            "/nudr-dr/v2/subscription-data/{ue_id}/context-data/smf-registrations/{pdu_session_id}",
            get(get_smf_reg).put(put_smf_reg).delete(delete_smf_reg),
        )
        .route(
            "/nudr-dr/v2/subscription-data/{ue_id}/{serving_plmn_id}/provisioned-data/am-data",
            get(get_am_data).put(put_am_data),
        )
        .route(
            "/nudr-dr/v2/subscription-data/{ue_id}/{serving_plmn_id}/provisioned-data/sm-data",
            get(get_sm_data).put(put_sm_data),
        )
        .route(
            "/nudr-dr/v2/subscription-data/{ue_id}/{serving_plmn_id}/provisioned-data/smf-selection-subscription-data",
            get(get_smf_sel).put(put_smf_sel),
        )
        // SM policy data (TS 29.519) — the PCF's policy source. Not PLMN-scoped.
        .route(
            "/nudr-dr/v2/policy-data/ues/{ue_id}/sm-data",
            get(get_sm_policy_data).put(put_sm_policy_data),
        )
        .with_state(state);
    // SBI security: require a valid `UDR` access token when a secret is configured
    // (open otherwise). The UDR holds subscriber data + the withdrawal that can
    // trigger the AMF callback, so it is the first service protected (design/46).
    crate::oauth::protect(router, "UDR", crate::oauth::sbi_secret())
}

/// Withdraw a subscription: remove everything stored for the SUPI, then notify
/// the serving AMF (the UECM registration's `deregCallbackUri`) so it
/// network-deregisters the UE. No registration recorded → nobody to notify.
async fn delete_subscription(
    State(st): State<NudrState>,
    Path(ue_id): Path<String>,
) -> StatusCode {
    // The registration is wiped with the subscriber — read the callback first.
    let callback = st
        .store
        .get_amf_registration(&ue_id)
        .and_then(|r| r.get("deregCallbackUri").and_then(|v| v.as_str()).map(str::to_owned));
    if !st.store.remove_subscriber(&ue_id) {
        return StatusCode::NOT_FOUND;
    }
    tracing::info!(supi = %ue_id, "subscription withdrawn");
    match callback {
        Some(uri) => {
            // Best-effort, off the request path: the withdrawal stands even if
            // the AMF is unreachable.
            tokio::spawn(async move {
                if let Err(e) = notify_amf_deregistration(&uri, &ue_id).await {
                    tracing::warn!(supi = %ue_id, "AMF deregistration notify failed: {e}");
                }
            });
        }
        None => tracing::info!(supi = %ue_id, "no serving AMF registered — nobody to notify"),
    }
    StatusCode::NO_CONTENT
}

/// Evict UECM registrations whose serving NF is no longer alive at the NRF —
/// **the UECM analogue of the NRF's own heartbeat-TTL eviction** (design/25).
/// A crashed AMF/SMF stops heartbeating the NRF and is purged there; this sweep
/// then drops any context-data registration naming a now-absent instance, so a
/// stale record can't outlive its NF until the subscriber is withdrawn.
///
/// One NRF query per pass (not per registration). Returns the number evicted.
/// **Fail-safe:** if the NRF is unreachable, nothing is evicted — an unreachable
/// NRF must not be read as "every NF is dead".
pub async fn sweep_stale_registrations(
    store: &Arc<dyn SubscriberStore>,
    nrf_base: &str,
) -> usize {
    let live: std::collections::HashSet<String> =
        match crate::nnrf::NrfClient::new(nrf_base.to_string()).list_instances().await {
            Ok(profiles) => profiles.into_iter().map(|p| p.nf_instance_id).collect(),
            Err(e) => {
                tracing::warn!("UECM sweep skipped (NRF unreachable): {e}");
                return 0;
            }
        };

    let mut evicted = 0;
    for (supi, doc) in store.list_amf_registrations() {
        let alive = doc
            .get("amfInstanceId")
            .and_then(|v| v.as_str())
            .is_some_and(|id| live.contains(id));
        if !alive && store.remove_amf_registration(&supi) {
            tracing::info!(supi = %supi, "evicted stale serving-AMF registration (NF gone)");
            evicted += 1;
        }
    }
    for ((supi, psi), doc) in store.list_smf_registrations() {
        let alive = doc
            .get("smfInstanceId")
            .and_then(|v| v.as_str())
            .is_some_and(|id| live.contains(id));
        if !alive && store.remove_smf_registration(&supi, psi) {
            tracing::info!(supi = %supi, psi, "evicted stale serving-SMF registration (NF gone)");
            evicted += 1;
        }
    }
    evicted
}

/// Whether `uri` is acceptable as a serving-AMF deregistration callback: a
/// well-formed absolute `http`/`https` URL. This is an **SSRF guard** — the URI
/// is attacker-influenceable while the SBI is unauthenticated (see the module
/// `# Security` note), so a hostile client must not be able to steer the UDR's
/// callback at non-HTTP schemes (`file:`, `gopher:`, …). It does **not** bound
/// the host: the legitimate AMF lives on the same private/loopback space as any
/// internal target, so host allowlisting needs deployment config — the real fix
/// is SBI mutual auth (only a cert-holding AMF can register a callback).
pub(crate) fn is_valid_callback_uri(uri: &str) -> bool {
    reqwest::Url::parse(uri).is_ok_and(|u| matches!(u.scheme(), "http" | "https"))
}

/// POST a `DeregistrationData` (TS 29.503-shaped) to the serving AMF's stored
/// deregistration callback URI. The URI is re-validated here (the guaranteed
/// choke point — a raw context-data PUT bypasses the UECM handler's check), and
/// redirects are **not** followed so a stored callback can't bounce the request
/// to a different host/port.
async fn notify_amf_deregistration(callback_uri: &str, supi: &str) -> Result<(), String> {
    if !is_valid_callback_uri(callback_uri) {
        return Err("stored deregCallbackUri is not a valid http(s) URL".to_string());
    }
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("build callback client: {e}"))?;
    let resp = client
        .post(callback_uri)
        .json(&serde_json::json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN" }))
        .send()
        .await
        .map_err(|e| format!("callback failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("AMF answered {}", resp.status()));
    }
    tracing::info!(supi = %supi, "serving AMF notified of subscription withdrawal");
    Ok(())
}

/// Context-data handlers (TS 29.505 `amf-3gpp-access`): the serving AMF's
/// registration, written by the UDM's Nudm_UECM front.
async fn get_amf_reg(
    State(st): State<NudrState>,
    Path(ue_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    st.store.get_amf_registration(&ue_id).map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn put_amf_reg(
    State(st): State<NudrState>,
    Path(ue_id): Path<String>,
    Json(doc): Json<serde_json::Value>,
) -> StatusCode {
    match st.store.put_amf_registration(&ue_id, &doc) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::warn!(supi = %ue_id, "put amf-3gpp-access failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn delete_amf_reg(State(st): State<NudrState>, Path(ue_id): Path<String>) -> StatusCode {
    if st.store.remove_amf_registration(&ue_id) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// Context-data handlers (TS 29.505 `smf-registrations/{pduSessionId}`): the
/// serving SMF's per-PDU-session registration, written by the UDM's Nudm_UECM front.
async fn get_smf_reg(
    State(st): State<NudrState>,
    Path((ue_id, psi)): Path<(String, u8)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    st.store.get_smf_registration(&ue_id, psi).map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn put_smf_reg(
    State(st): State<NudrState>,
    Path((ue_id, psi)): Path<(String, u8)>,
    Json(doc): Json<serde_json::Value>,
) -> StatusCode {
    match st.store.put_smf_registration(&ue_id, psi, &doc) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::warn!(supi = %ue_id, psi, "put smf-registrations failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn delete_smf_reg(
    State(st): State<NudrState>,
    Path((ue_id, psi)): Path<(String, u8)>,
) -> StatusCode {
    if st.store.remove_smf_registration(&ue_id, psi) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn generate_av(
    State(st): State<NudrState>,
    Path(ue_id): Path<String>,
    Json(req): Json<GenerateAvRequest>,
) -> Result<Json<HeAv>, StatusCode> {
    let sqn = st.store.next_sqn(&ue_id).ok_or(StatusCode::NOT_FOUND)?;
    let rand = crate::random_rand();
    let av = st.store
        .generate_he_av(&ue_id, &sqn, &rand, &req.mcc, &req.mnc)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(HeAv {
        rand: hex::encode(av.rand),
        autn: hex::encode(av.autn),
        xres_star: hex::encode(av.xres_star),
        kausf: hex::encode(av.kausf),
    }))
}

async fn get_doc(
    store: Arc<dyn SubscriberStore>,
    ds: DataSet,
    ue_id: String,
    plmn: String,
) -> Result<Json<serde_json::Value>, StatusCode> {
    store.get_provisioned(ds, &ue_id, &plmn).map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn put_doc(
    store: Arc<dyn SubscriberStore>,
    ds: DataSet,
    ue_id: String,
    plmn: String,
    doc: serde_json::Value,
) -> StatusCode {
    match store.put_provisioned(ds, &ue_id, &plmn, &doc) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::warn!(supi = %ue_id, "put provisioned data failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

macro_rules! doc_handlers {
    ($get:ident, $put:ident, $ds:expr) => {
        async fn $get(
            State(st): State<NudrState>,
            Path((ue_id, plmn)): Path<(String, String)>,
        ) -> Result<Json<serde_json::Value>, StatusCode> {
            get_doc(st.store, $ds, ue_id, plmn).await
        }
        async fn $put(
            State(st): State<NudrState>,
            Path((ue_id, plmn)): Path<(String, String)>,
            Json(doc): Json<serde_json::Value>,
        ) -> StatusCode {
            put_doc(st.store, $ds, ue_id, plmn, doc).await
        }
    };
}

doc_handlers!(get_am_data, put_am_data, DataSet::Am);
doc_handlers!(get_sm_data, put_sm_data, DataSet::Sm);
doc_handlers!(get_smf_sel, put_smf_sel, DataSet::SmfSelection);

/// Policy-data handlers (TS 29.519). The resource is keyed by ueId only, so these
/// read/write `DataSet::Policy` under an empty PLMN key.
async fn get_sm_policy_data(
    State(st): State<NudrState>,
    Path(ue_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    get_doc(st.store, DataSet::Policy, ue_id, String::new()).await
}
async fn put_sm_policy_data(
    State(st): State<NudrState>,
    Path(ue_id): Path<String>,
    Json(doc): Json<serde_json::Value>,
) -> StatusCode {
    put_doc(st.store, DataSet::Policy, ue_id, String::new(), doc).await
}

fn dataset_path(ds: DataSet) -> &'static str {
    match ds {
        DataSet::Am => "am-data",
        DataSet::Sm => "sm-data",
        DataSet::SmfSelection => "smf-selection-subscription-data",
        // Policy data has its own resource tree (see `policy_data_url`); never
        // reached via the provisioned-data path.
        DataSet::Policy => "sm-data",
    }
}

/// Client the UDM (and later PCF) uses to reach the UDR over h2c. When built with
/// [`UdrClient::with_tokens`], it obtains an NRF-issued OAuth2 access token
/// (audience `UDR`) and presents it on every request — required once the UDR is
/// protected (SBI security enabled). Plain [`UdrClient::new`] sends no token
/// (open SBI).
pub struct UdrClient {
    base: String,
    http: reqwest::Client,
    tokens: Option<std::sync::Arc<crate::oauth::TokenSource>>,
}

impl UdrClient {
    /// Target a UDR at `base_url`, e.g. `http://127.0.0.1:8005` (no access token).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base: base_url.into(), http: crate::h2c_client(), tokens: None }
    }

    /// Like [`new`], but obtains and attaches a `UDR` access token from the NRF
    /// (via `tokens`) on every request.
    pub fn with_tokens(
        base_url: impl Into<String>,
        tokens: std::sync::Arc<crate::oauth::TokenSource>,
    ) -> Self {
        Self { base: base_url.into(), http: crate::h2c_client(), tokens: Some(tokens) }
    }

    /// Attach a `UDR` Bearer token to a request when a token source is configured.
    async fn bearer(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.tokens {
            Some(ts) => match ts.token_for("UDR", "nudr-dr").await {
                Some(tok) => rb.bearer_auth(tok),
                None => rb,
            },
            None => rb,
        }
    }

    /// Derive a 5G HE AV for `supi` (the UDR advances the SQN). `Ok(None)` for an
    /// unknown subscriber.
    pub async fn generate_av(
        &self,
        supi: &str,
        mcc: &str,
        mnc: &str,
    ) -> Result<Option<HeAv>, SbiError> {
        let url = format!(
            "{}/nudr-dr/v2/subscription-data/{}/authentication-data/generate-av",
            self.base, supi
        );
        let resp = self
            .bearer(
                self.http
                    .post(url)
                    .json(&GenerateAvRequest { mcc: mcc.to_string(), mnc: mnc.to_string() }),
            )
            .await
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// Fetch a provisioned-data document. `Ok(None)` if not provisioned.
    pub async fn get_provisioned(
        &self,
        ds: DataSet,
        supi: &str,
        plmn: &str,
    ) -> Result<Option<serde_json::Value>, SbiError> {
        let resp = self.bearer(self.http.get(self.doc_url(ds, supi, plmn))).await.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// Fetch the subscriber's SM policy data (TS 29.519 `policy-data/ues/{ueId}/
    /// sm-data`). `Ok(None)` if not provisioned. Used by the PCF.
    pub async fn get_sm_policy_data(
        &self,
        supi: &str,
    ) -> Result<Option<serde_json::Value>, SbiError> {
        let resp = self.bearer(self.http.get(self.policy_data_url(supi))).await.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// Provision (create or replace) the subscriber's SM policy data.
    pub async fn put_sm_policy_data(
        &self,
        supi: &str,
        doc: &serde_json::Value,
    ) -> Result<(), SbiError> {
        self.bearer(self.http.put(self.policy_data_url(supi)).json(doc))
            .await
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn policy_data_url(&self, supi: &str) -> String {
        format!("{}/nudr-dr/v2/policy-data/ues/{}/sm-data", self.base, supi)
    }

    /// Withdraw a subscription (`DELETE …/subscription-data/{ueId}`). `Ok(true)`
    /// if it existed, `Ok(false)` on 404.
    pub async fn delete_subscriber(&self, supi: &str) -> Result<bool, SbiError> {
        let resp = self
            .bearer(self.http.delete(format!("{}/nudr-dr/v2/subscription-data/{}", self.base, supi)))
            .await
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        resp.error_for_status()?;
        Ok(true)
    }

    /// Fetch the serving AMF's registration (context data). `Ok(None)` if absent.
    pub async fn get_amf_registration(
        &self,
        supi: &str,
    ) -> Result<Option<serde_json::Value>, SbiError> {
        let resp = self.bearer(self.http.get(self.amf_reg_url(supi))).await.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// Record the serving AMF's registration (context data).
    pub async fn put_amf_registration(
        &self,
        supi: &str,
        doc: &serde_json::Value,
    ) -> Result<(), SbiError> {
        self.bearer(self.http.put(self.amf_reg_url(supi)).json(doc)).await.send().await?.error_for_status()?;
        Ok(())
    }

    /// Purge the serving AMF's registration. `Ok(false)` if none was recorded.
    pub async fn delete_amf_registration(&self, supi: &str) -> Result<bool, SbiError> {
        let resp = self.bearer(self.http.delete(self.amf_reg_url(supi))).await.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        resp.error_for_status()?;
        Ok(true)
    }

    fn amf_reg_url(&self, supi: &str) -> String {
        format!("{}/nudr-dr/v2/subscription-data/{}/context-data/amf-3gpp-access", self.base, supi)
    }

    /// Record the serving SMF for a PDU session (context data).
    pub async fn put_smf_registration(
        &self,
        supi: &str,
        pdu_session_id: u8,
        doc: &serde_json::Value,
    ) -> Result<(), SbiError> {
        self.bearer(self.http.put(self.smf_reg_url(supi, pdu_session_id)).json(doc))
            .await
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Fetch the serving SMF's registration for a PDU session. `Ok(None)` if absent.
    pub async fn get_smf_registration(
        &self,
        supi: &str,
        pdu_session_id: u8,
    ) -> Result<Option<serde_json::Value>, SbiError> {
        let resp = self.bearer(self.http.get(self.smf_reg_url(supi, pdu_session_id))).await.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// Purge a serving-SMF registration. `Ok(false)` if none was recorded.
    pub async fn delete_smf_registration(
        &self,
        supi: &str,
        pdu_session_id: u8,
    ) -> Result<bool, SbiError> {
        let resp = self.bearer(self.http.delete(self.smf_reg_url(supi, pdu_session_id))).await.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        resp.error_for_status()?;
        Ok(true)
    }

    fn smf_reg_url(&self, supi: &str, pdu_session_id: u8) -> String {
        format!(
            "{}/nudr-dr/v2/subscription-data/{}/context-data/smf-registrations/{}",
            self.base, supi, pdu_session_id
        )
    }

    /// Store (create or replace) a provisioned-data document.
    pub async fn put_provisioned(
        &self,
        ds: DataSet,
        supi: &str,
        plmn: &str,
        doc: &serde_json::Value,
    ) -> Result<(), SbiError> {
        self.bearer(self.http.put(self.doc_url(ds, supi, plmn)).json(doc))
            .await
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn doc_url(&self, ds: DataSet, supi: &str, plmn: &str) -> String {
        format!(
            "{}/nudr-dr/v2/subscription-data/{}/{}/provisioned-data/{}",
            self.base,
            supi,
            plmn,
            dataset_path(ds)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subscriber_db::InMemoryStore;

    /// End-to-end SBI OAuth2: a UDR protected with an explicit secret rejects
    /// tokenless calls, and a UdrClient carrying an NRF-issued token succeeds.
    #[tokio::test]
    async fn protected_udr_requires_a_valid_access_token() {
        // Secret shared by the NRF (signer) and the UDR (verifier). Test injects it
        // explicitly rather than via env (which is process-global).
        let secret = vec![0x11u8; 32];

        // NRF (token endpoint, injected secret) with the client NF ("udm-1") registered.
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let nrf_store = crate::nnrf::NrfStore::default().with_secret(Some(secret.clone()));
        tokio::spawn(async move { crate::run_on(nrf_l, crate::nnrf::router(nrf_store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");
        crate::nnrf::NrfClient::new(nrf_base.clone())
            .register(&crate::nnrf::NfProfile::new("udm-1", "UDM", "127.0.0.1"))
            .await
            .unwrap();

        // UDR protected with the same secret; one provisioned subscriber.
        let store = Arc::new(InMemoryStore::new());
        store.provision_hex("imsi-1", "465b5ce8b199b49faa5f0a2ee238a6bc", "cd63cb71954a9f4e48a5994e37a02baf", "8000").unwrap();
        let store: Arc<dyn SubscriberStore> = store;
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        let protected = crate::oauth::protect(router(store), "UDR", Some(secret.clone()));
        tokio::spawn(async move { crate::run_on(udr_l, protected).await.unwrap() });
        let udr_url = format!("http://{udr_addr}");

        // Tokenless client → 401.
        let open = UdrClient::new(udr_url.clone());
        let err = open.get_amf_registration("imsi-1").await.expect_err("must be rejected");
        assert!(matches!(err, SbiError::Http(ref e) if e.status() == Some(reqwest::StatusCode::UNAUTHORIZED)));

        // Token-bearing client (fetches from the NRF as "udm-1") → authorized.
        let tokens = std::sync::Arc::new(crate::oauth::TokenSource::new(nrf_base.clone(), "udm-1"));
        let client = UdrClient::with_tokens(udr_url.clone(), tokens);
        // No registration yet, but the store answers 404 through the auth layer.
        assert!(client.get_amf_registration("imsi-1").await.unwrap().is_none());
        // And a real read works.
        assert!(client.generate_av("imsi-1", "999", "70").await.unwrap().is_some());

        // A token from an unregistered client is refused by the NRF (no token → 401).
        let tokens_bad = std::sync::Arc::new(crate::oauth::TokenSource::new(nrf_base, "rogue-1"));
        let rogue = UdrClient::with_tokens(udr_url, tokens_bad);
        assert!(rogue.get_amf_registration("imsi-1").await.is_err(), "unregistered client can't get a token");
    }

    async fn serve(store: Arc<dyn SubscriberStore>) -> UdrClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(listener, router(store)).await.unwrap() });
        UdrClient::new(format!("http://{addr}"))
    }

    #[tokio::test]
    async fn generate_av_advances_sqn_and_hides_k() {
        let store = Arc::new(InMemoryStore::new());
        store
            .provision_hex(
                "imsi-1",
                "465b5ce8b199b49faa5f0a2ee238a6bc",
                "cd63cb71954a9f4e48a5994e37a02baf",
                "8000",
            )
            .unwrap();
        let udr = serve(store).await;

        let av1 = udr.generate_av("imsi-1", "999", "70").await.unwrap().expect("AV");
        let av2 = udr.generate_av("imsi-1", "999", "70").await.unwrap().expect("AV");
        // The SQN advanced between calls → different AUTN even for equal RANDs.
        assert_ne!(av1.autn, av2.autn);
        // Only derived material crosses the wire — no field can hold K (34-hex check
        // is structural: HeAv simply has no key field, this guards the JSON too).
        for av in [&av1, &av2] {
            let json = serde_json::to_string(av).unwrap();
            assert!(!json.contains("465b5ce8b199b49faa5f0a2ee238a6bc"));
        }

        assert!(udr.generate_av("imsi-unknown", "999", "70").await.unwrap().is_none());
    }

    /// A DELETE withdraws the subscription and notifies the serving AMF recorded
    /// via Nudm_UECM — at its stored deregCallbackUri, not by NRF discovery. A
    /// subscriber with no UECM registration notifies nobody.
    #[tokio::test]
    async fn subscription_withdrawal_notifies_the_serving_amf() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NOTIFIED: AtomicUsize = AtomicUsize::new(0);

        // Mock AMF callback endpoint.
        async fn notify() -> axum::http::StatusCode {
            NOTIFIED.fetch_add(1, Ordering::Relaxed);
            axum::http::StatusCode::NO_CONTENT
        }
        let amf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let amf_addr = amf_l.local_addr().unwrap();
        let amf_router = axum::Router::new().route(
            "/namf-callback/v1/{supi}/dereg-notify",
            axum::routing::post(notify),
        );
        tokio::spawn(async move { crate::run_on(amf_l, amf_router).await.unwrap() });

        // UDR (plain router — no NRF involved) with two provisioned subscribers.
        let store = Arc::new(InMemoryStore::new());
        for supi in ["imsi-1", "imsi-2"] {
            store
                .provision_hex(
                    supi,
                    "465b5ce8b199b49faa5f0a2ee238a6bc",
                    "cd63cb71954a9f4e48a5994e37a02baf",
                    "8000",
                )
                .unwrap();
        }
        let store: Arc<dyn SubscriberStore> = store;
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, router(store)).await.unwrap() });
        let udr_base = format!("http://{udr_addr}");
        let udr = UdrClient::new(udr_base.clone());

        // The serving AMF registers via the UDM's Nudm_UECM front — full chain.
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        let udr_for_udm = Arc::new(UdrClient::new(udr_base));
        tokio::spawn(async move {
            crate::run_on(udm_l, crate::nudm::router(udr_for_udm)).await.unwrap()
        });
        let sdm = crate::nudm::NudmClient::new(format!("http://{udm_addr}"));
        sdm.uecm_register_amf(
            "imsi-1",
            &crate::nudm::Amf3GppAccessRegistration {
                amf_instance_id: "amf-1".into(),
                dereg_callback_uri: format!(
                    "http://{amf_addr}/namf-callback/v1/imsi-1/dereg-notify"
                ),
            },
        )
        .await
        .unwrap();

        // Withdraw imsi-1 → the stored callback fires exactly once.
        assert_eq!(udr.delete_subscriber("imsi-1").await.unwrap(), true);
        assert!(udr.generate_av("imsi-1", "999", "70").await.unwrap().is_none(), "withdrawn");
        assert_eq!(udr.delete_subscriber("imsi-1").await.unwrap(), false, "second delete 404s");
        for _ in 0..50 {
            if NOTIFIED.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(NOTIFIED.load(Ordering::Relaxed), 1, "serving AMF notified exactly once");

        // imsi-2 has no serving AMF — its withdrawal notifies nobody.
        assert_eq!(udr.delete_subscriber("imsi-2").await.unwrap(), true);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(NOTIFIED.load(Ordering::Relaxed), 1, "no extra notification");
    }

    #[test]
    fn callback_uri_ssrf_guard() {
        assert!(is_valid_callback_uri("http://127.0.0.1:8001/namf-callback/v1/imsi-1/dereg-notify"));
        assert!(is_valid_callback_uri("https://amf.example/cb"));
        // Non-HTTP schemes and junk are rejected (would otherwise be SSRF vectors).
        assert!(!is_valid_callback_uri("file:///etc/passwd"));
        assert!(!is_valid_callback_uri("gopher://169.254.169.254/"));
        assert!(!is_valid_callback_uri("ftp://internal/x"));
        assert!(!is_valid_callback_uri("not a url"));
        assert!(!is_valid_callback_uri(""));
    }

    /// A UECM registration with a non-http(s) callback is rejected at the UDM
    /// front (400) and never stored.
    #[tokio::test]
    async fn uecm_rejects_ssrf_callback_uri() {
        let store: Arc<dyn SubscriberStore> = Arc::new(InMemoryStore::new());
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, router(store)).await.unwrap() });

        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        let udr_for_udm = Arc::new(UdrClient::new(format!("http://{udr_addr}")));
        tokio::spawn(async move {
            crate::run_on(udm_l, crate::nudm::router(udr_for_udm)).await.unwrap()
        });
        let sdm = crate::nudm::NudmClient::new(format!("http://{udm_addr}"));

        let err = sdm
            .uecm_register_amf(
                "imsi-1",
                &crate::nudm::Amf3GppAccessRegistration {
                    amf_instance_id: "amf-1".into(),
                    dereg_callback_uri: "file:///etc/passwd".into(),
                },
            )
            .await
            .expect_err("malicious callback must be rejected");
        assert!(matches!(err, SbiError::Http(_)), "got {err:?}");
        // Nothing was stored.
        let udr = UdrClient::new(format!("http://{udr_addr}"));
        assert!(udr.get_amf_registration("imsi-1").await.unwrap().is_none());
    }

    /// The UECM sweep evicts registrations whose serving NF is gone from the NRF,
    /// keeps live ones, and (fail-safe) evicts nothing when the NRF is unreachable.
    #[tokio::test]
    async fn uecm_sweep_evicts_dead_nf_registrations() {
        use subscriber_db::ProvisionedDataStore;

        // NRF with one live AMF instance ("amf-live") registered.
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let nrf_store = crate::nnrf::NrfStore::default();
        tokio::spawn(async move { crate::run_on(nrf_l, crate::nnrf::router(nrf_store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");
        crate::nnrf::NrfClient::new(nrf_base.clone())
            .register(&crate::nnrf::NfProfile::new("amf-live", "AMF", "127.0.0.1"))
            .await
            .unwrap();

        // Two AMF registrations (one live, one dead) + one dead SMF registration.
        let store = Arc::new(InMemoryStore::new());
        store.put_amf_registration("imsi-live", &serde_json::json!({"amfInstanceId": "amf-live"})).unwrap();
        store.put_amf_registration("imsi-dead", &serde_json::json!({"amfInstanceId": "amf-gone"})).unwrap();
        store.put_smf_registration("imsi-live", 5, &serde_json::json!({"smfInstanceId": "smf-gone"})).unwrap();
        let store: Arc<dyn SubscriberStore> = store;

        let evicted = sweep_stale_registrations(&store, &nrf_base).await;
        assert_eq!(evicted, 2, "the dead AMF and dead SMF registrations are evicted");
        assert!(store.get_amf_registration("imsi-live").is_some(), "live AMF registration kept");
        assert!(store.get_amf_registration("imsi-dead").is_none(), "dead AMF registration gone");
        assert!(store.get_smf_registration("imsi-live", 5).is_none(), "dead SMF registration gone");

        // Idempotent: a second pass evicts nothing more.
        assert_eq!(sweep_stale_registrations(&store, &nrf_base).await, 0);

        // Fail-safe: an unreachable NRF evicts nothing (even the still-present live one).
        assert_eq!(sweep_stale_registrations(&store, "http://127.0.0.1:1").await, 0);
        assert!(store.get_amf_registration("imsi-live").is_some(), "unreachable NRF is not 'all dead'");
    }

    /// SMF UECM register → per-session context data at the UDR; purge → gone.
    #[tokio::test]
    async fn smf_uecm_registration_roundtrips_through_udm_and_udr() {
        let store: Arc<dyn SubscriberStore> = Arc::new(InMemoryStore::new());
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, router(store)).await.unwrap() });
        let udr = UdrClient::new(format!("http://{udr_addr}"));

        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        let udr_for_udm = Arc::new(UdrClient::new(format!("http://{udr_addr}")));
        tokio::spawn(async move {
            crate::run_on(udm_l, crate::nudm::router(udr_for_udm)).await.unwrap()
        });
        let sdm = crate::nudm::NudmClient::new(format!("http://{udm_addr}"));

        assert!(udr.get_smf_registration("imsi-1", 5).await.unwrap().is_none());
        sdm.uecm_register_smf(
            "imsi-1",
            &crate::nudm::SmfRegistration {
                smf_instance_id: "smf-1".into(),
                pdu_session_id: 5,
                dnn: "internet".into(),
            },
        )
        .await
        .unwrap();
        let reg = udr.get_smf_registration("imsi-1", 5).await.unwrap().expect("stored");
        assert_eq!(reg.get("smfInstanceId").and_then(|v| v.as_str()), Some("smf-1"));
        assert_eq!(reg.get("dnn").and_then(|v| v.as_str()), Some("internet"));
        // Keyed per session — a different PDU session is independent.
        assert!(udr.get_smf_registration("imsi-1", 6).await.unwrap().is_none());

        assert_eq!(sdm.uecm_deregister_smf("imsi-1", 5).await.unwrap(), true);
        assert!(udr.get_smf_registration("imsi-1", 5).await.unwrap().is_none(), "purged");
        assert_eq!(sdm.uecm_deregister_smf("imsi-1", 5).await.unwrap(), false, "re-purge 404s");
    }

    /// UECM register → readable context data; purge → gone (and 404 on re-purge).
    #[tokio::test]
    async fn uecm_registration_roundtrips_through_udm_and_udr() {
        let store: Arc<dyn SubscriberStore> = Arc::new(InMemoryStore::new());
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, router(store)).await.unwrap() });
        let udr = UdrClient::new(format!("http://{udr_addr}"));

        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        let udr_for_udm = Arc::new(UdrClient::new(format!("http://{udr_addr}")));
        tokio::spawn(async move {
            crate::run_on(udm_l, crate::nudm::router(udr_for_udm)).await.unwrap()
        });
        let sdm = crate::nudm::NudmClient::new(format!("http://{udm_addr}"));

        assert!(udr.get_amf_registration("imsi-1").await.unwrap().is_none());
        sdm.uecm_register_amf(
            "imsi-1",
            &crate::nudm::Amf3GppAccessRegistration {
                amf_instance_id: "amf-1".into(),
                dereg_callback_uri: "http://amf/cb".into(),
            },
        )
        .await
        .unwrap();
        let reg = udr.get_amf_registration("imsi-1").await.unwrap().expect("stored");
        assert_eq!(reg.get("amfInstanceId").and_then(|v| v.as_str()), Some("amf-1"));
        assert_eq!(reg.get("deregCallbackUri").and_then(|v| v.as_str()), Some("http://amf/cb"));

        assert_eq!(sdm.uecm_deregister_amf("imsi-1").await.unwrap(), true);
        assert!(udr.get_amf_registration("imsi-1").await.unwrap().is_none(), "purged");
        assert_eq!(sdm.uecm_deregister_amf("imsi-1").await.unwrap(), false, "re-purge 404s");
    }

    #[tokio::test]
    async fn provisioned_data_roundtrip_over_h2c() {
        let udr = serve(Arc::new(InMemoryStore::new())).await;
        let am = serde_json::json!({"nssai": {"defaultSingleNssais": [{"sst": 1, "sd": "010203"}]}});

        assert!(udr.get_provisioned(DataSet::Am, "imsi-1", "99970").await.unwrap().is_none());
        udr.put_provisioned(DataSet::Am, "imsi-1", "99970", &am).await.unwrap();
        assert_eq!(
            udr.get_provisioned(DataSet::Am, "imsi-1", "99970").await.unwrap(),
            Some(am)
        );
        // Other data sets and PLMNs stay independent.
        assert!(udr.get_provisioned(DataSet::Sm, "imsi-1", "99970").await.unwrap().is_none());
        assert!(udr.get_provisioned(DataSet::Am, "imsi-1", "00101").await.unwrap().is_none());
    }
}
