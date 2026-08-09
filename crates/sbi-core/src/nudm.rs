//! Nudm — UDM services (TS 29.503): `Nudm_UEAuthentication` (authentication
//! vectors) and `Nudm_SDM` (subscriber data management, the SMF's view of
//! sm-data / smf-select-data).
//!
//! The UDM here is a stateless front-end over the **UDR** (Nudr, design/24 step 1):
//! authentication asks the UDR — which co-hosts the ARPF — to derive a 5G HE
//! vector (**the long-term key K never reaches this module or the UDM↔UDR wire**),
//! and SDM proxies the provisioned-data documents verbatim.

use crate::otel::Traced;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{FromRef, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subscriber_db::DataSet;

use crate::nudr::UdrClient;
use crate::SbiError;

/// In-memory `Nudm_SDM` change subscriptions (TS 29.503 §5.3.2), keyed by SUPI. A
/// consumer (the AMF) subscribes with a callback; a data-change fans a
/// `ModificationNotification` out to every callback for that SUPI. Cloneable
/// (shared handle); the UDM is a single process.
#[derive(Clone, Default)]
pub struct SdmStore {
    subs: Arc<Mutex<HashMap<String, Vec<SdmSub>>>>,
    next_id: Arc<AtomicU64>,
}

#[derive(Clone)]
struct SdmSub {
    id: String,
    callback: String,
}

impl SdmStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a subscription for `supi`, returning its id.
    fn subscribe(&self, supi: &str, callback: String) -> String {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).to_string();
        self.subs
            .lock()
            .unwrap()
            .entry(supi.to_string())
            .or_default()
            .push(SdmSub { id: id.clone(), callback });
        id
    }

    /// Remove a subscription; `true` if it existed.
    fn unsubscribe(&self, supi: &str, id: &str) -> bool {
        let mut map = self.subs.lock().unwrap();
        let Some(list) = map.get_mut(supi) else {
            return false;
        };
        let before = list.len();
        list.retain(|s| s.id != id);
        let removed = list.len() != before;
        if list.is_empty() {
            map.remove(supi);
        }
        removed
    }

    /// The callback URIs subscribed for `supi`.
    fn callbacks_for(&self, supi: &str) -> Vec<String> {
        self.subs
            .lock()
            .unwrap()
            .get(supi)
            .map(|list| list.iter().map(|s| s.callback.clone()).collect())
            .unwrap_or_default()
    }
}

/// Combined UDM router state: the UDR client plus the SDM subscription store.
/// `FromRef` lets each handler extract just the piece it needs.
#[derive(Clone)]
struct UdmState {
    udr: Arc<UdrClient>,
    sdm: SdmStore,
    /// Home-network private keys for SUCI deconcealment (design/137 G2).
    suci: Arc<aka::suci::HomeNetworkKeys>,
}

impl FromRef<UdmState> for Arc<UdrClient> {
    fn from_ref(s: &UdmState) -> Self {
        s.udr.clone()
    }
}

impl FromRef<UdmState> for SdmStore {
    fn from_ref(s: &UdmState) -> Self {
        s.sdm.clone()
    }
}

impl FromRef<UdmState> for Arc<aka::suci::HomeNetworkKeys> {
    fn from_ref(s: &UdmState) -> Self {
        s.suci.clone()
    }
}

/// Load the home-network ECIES private keys from the environment (design/137 G2):
/// `RADIAN_UDM_HNET_A_KEY` (64-hex X25519 private key, key id `…_A_KEY_ID`, default 1)
/// for Profile A, `RADIAN_UDM_HNET_B_KEY` (64-hex P-256 scalar, id default 2) for
/// Profile B. Absent ⇒ only null-scheme SUCIs (and plain SUPIs) deconceal.
fn hnet_keys_from_env() -> aka::suci::HomeNetworkKeys {
    fn key32(var: &str) -> Option<[u8; 32]> {
        let hex = std::env::var(var).ok()?;
        let bytes = hex::decode(hex.trim()).ok()?;
        bytes.try_into().ok()
    }
    fn key_id(var: &str, default: u8) -> u8 {
        std::env::var(var).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    }
    let mut keys = aka::suci::HomeNetworkKeys::empty();
    if let Some(k) = key32("RADIAN_UDM_HNET_A_KEY") {
        keys = keys.with_profile_a(key_id("RADIAN_UDM_HNET_A_KEY_ID", 1), k);
    }
    if let Some(k) = key32("RADIAN_UDM_HNET_B_KEY") {
        keys = keys.with_profile_b(key_id("RADIAN_UDM_HNET_B_KEY_ID", 2), k);
    }
    keys
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfoRequest {
    pub serving_network_name: String,
    #[serde(default)]
    pub ausf_instance_id: Option<String>,
}

/// Resynchronisation info (TS 29.503): the challenge `rand` and the UE `auts`, hex.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResyncInfo {
    pub rand: String,
    pub auts: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfoResult {
    pub auth_type: String,
    pub authentication_vector: Av5gHe,
    pub supi: String,
}

/// 5G HE authentication vector — values are lowercase hex strings (SBI convention).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Av5gHe {
    pub av_type: String,
    pub rand: String,
    pub xres_star: String,
    pub autn: String,
    pub kausf: String,
}

/// Build the UDM router (Nudm_UEAuthentication_Get + Nudm_SDM) backed by the UDR
/// over Nudr.
pub fn router(udr: Arc<UdrClient>) -> Router {
    Router::new()
        .route(
            "/nudm-ueau/v1/{supi_or_suci}/security-information/generate-auth-data",
            post(generate_auth_data),
        )
        .route("/nudm-ueau/v1/{supi}/auth-events/resync", post(resync))
        .route(
            "/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access",
            axum::routing::put(uecm_register_amf).delete(uecm_deregister_amf),
        )
        .route(
            "/nudm-uecm/v1/{supi}/registrations/smf-registrations/{pdu_session_id}",
            axum::routing::put(uecm_register_smf).delete(uecm_deregister_smf),
        )
        .route("/nudm-sdm/v2/{supi}/am-data", get(sdm_am_data))
        .route("/nudm-sdm/v2/{supi}/sm-data", get(sdm_sm_data))
        .route("/nudm-sdm/v2/{supi}/smf-select-data", get(sdm_smf_select_data))
        // Nudm_SDM change subscriptions: subscribe/unsubscribe + a data-change
        // fan-out (the trigger a data source — e.g. the UDR — invokes on a change).
        .route("/nudm-sdm/v2/{supi}/sdm-subscriptions", post(sdm_subscribe))
        .route("/nudm-sdm/v2/{supi}/sdm-subscriptions/{sub_id}", delete(sdm_unsubscribe))
        .route("/nudm-sdm/v2/{supi}/notify-data-change", post(sdm_notify_change))
        .with_state(UdmState { udr, sdm: SdmStore::new(), suci: Arc::new(hnet_keys_from_env()) })
}

/// `Nudm_SDM` subscription (TS 29.503 §6.1.6.2.10, trimmed): a consumer's callback
/// for subscriber-data changes, plus the monitored resources (advisory here — the
/// AMF re-fetches am-data on any notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdmSubscription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    pub callback_reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitored_resource_uris: Option<Vec<String>>,
}

/// `Nudm_SDM` **ModificationNotification** (TS 29.503 §6.1.6.2.10): the changed
/// resources for a SUPI, POSTed to each subscriber's callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModificationNotification {
    pub notify_items: Vec<NotifyItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyItem {
    /// The changed resource (e.g. `am-data`).
    pub resource_id: String,
}

/// `Nudm_SDM_Subscribe`: record a consumer's callback for `supi`'s data changes.
/// `201` with the created subscription (carrying its id) and a `Location` header.
async fn sdm_subscribe(
    State(sdm): State<SdmStore>,
    Path(supi): Path<String>,
    Json(mut sub): Json<SdmSubscription>,
) -> Result<(StatusCode, [(axum::http::HeaderName, String); 1], Json<SdmSubscription>), StatusCode> {
    // SSRF guard on the callback (same posture as the UECM dereg callback).
    if !crate::nudr::is_valid_callback_uri(&sub.callback_reference) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id = sdm.subscribe(&supi, sub.callback_reference.clone());
    tracing::info!(%supi, sub_id = %id, callback = %sub.callback_reference, "Nudm_SDM subscription created");
    let location = format!("/nudm-sdm/v2/{supi}/sdm-subscriptions/{id}");
    sub.subscription_id = Some(id);
    Ok((StatusCode::CREATED, [(axum::http::header::LOCATION, location)], Json(sub)))
}

/// `Nudm_SDM_Unsubscribe`: drop a subscription. `204`, or `404` if unknown.
async fn sdm_unsubscribe(
    State(sdm): State<SdmStore>,
    Path((supi, sub_id)): Path<(String, String)>,
) -> StatusCode {
    if sdm.unsubscribe(&supi, &sub_id) {
        tracing::info!(%supi, %sub_id, "Nudm_SDM subscription removed");
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// Fan a subscriber-data change out to every `Nudm_SDM` subscriber for `supi`
/// (the trigger a data source invokes on a change). Best-effort: each callback is
/// POSTed a `ModificationNotification`; failures are logged, not fatal. `200` with
/// the number of subscribers notified.
async fn sdm_notify_change(
    State(sdm): State<SdmStore>,
    Path(supi): Path<String>,
) -> Json<serde_json::Value> {
    let callbacks = sdm.callbacks_for(&supi);
    let notification = ModificationNotification {
        notify_items: vec![NotifyItem { resource_id: "am-data".to_string() }],
    };
    let client = crate::sbi_client();
    let mut notified = 0u32;
    for cb in &callbacks {
        match client.post(cb).json(&notification).traced().send().await {
            Ok(r) if r.status().is_success() => notified += 1,
            Ok(r) => tracing::warn!(%supi, callback = %cb, status = %r.status(), "SDM notify rejected"),
            Err(e) => tracing::warn!(%supi, callback = %cb, "SDM notify failed: {e}"),
        }
    }
    tracing::info!(%supi, subscribers = callbacks.len(), notified, "Nudm_SDM data-change fanned out");
    Json(serde_json::json!({ "notified": notified }))
}

/// `Nudm_UECM` (TS 29.503 §5.3): the AMF records itself as the serving AMF for a
/// SUPI — stored as UDR context data; a subscription withdrawal is delivered to
/// this registration's `deregCallbackUri`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Amf3GppAccessRegistration {
    pub amf_instance_id: String,
    pub dereg_callback_uri: String,
}

async fn uecm_register_amf(
    State(udr): State<Arc<UdrClient>>,
    Path(supi): Path<String>,
    Json(reg): Json<Amf3GppAccessRegistration>,
) -> Result<StatusCode, StatusCode> {
    // Reject an unusable callback up front (SSRF guard — see nudr's `# Security`).
    // The UDR re-checks at call time, so a raw context-data PUT can't slip past.
    if !crate::nudr::is_valid_callback_uri(&reg.dereg_callback_uri) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let doc = serde_json::to_value(&reg).map_err(|_| StatusCode::BAD_REQUEST)?;
    udr.put_amf_registration(&supi, &doc).await.map_err(|e| {
        tracing::warn!("UDR amf-3gpp-access put failed: {e}");
        StatusCode::BAD_GATEWAY
    })?;
    tracing::info!(%supi, amf = %reg.amf_instance_id, "serving AMF registered (UECM)");
    Ok(StatusCode::CREATED)
}

async fn uecm_deregister_amf(
    State(udr): State<Arc<UdrClient>>,
    Path(supi): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let existed = udr.delete_amf_registration(&supi).await.map_err(|e| {
        tracing::warn!("UDR amf-3gpp-access delete failed: {e}");
        StatusCode::BAD_GATEWAY
    })?;
    if existed {
        tracing::info!(%supi, "serving AMF purged (UECM)");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// `Nudm_UECM` `SmfRegistration` (TS 29.503 §6.2.6.2.6), trimmed: the serving SMF
/// for a PDU session — stored as UDR context data keyed by `(SUPI, pduSessionId)`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmfRegistration {
    pub smf_instance_id: String,
    pub pdu_session_id: u8,
    pub dnn: String,
}

async fn uecm_register_smf(
    State(udr): State<Arc<UdrClient>>,
    Path((supi, psi)): Path<(String, u8)>,
    Json(reg): Json<SmfRegistration>,
) -> Result<StatusCode, StatusCode> {
    let doc = serde_json::to_value(&reg).map_err(|_| StatusCode::BAD_REQUEST)?;
    udr.put_smf_registration(&supi, psi, &doc).await.map_err(|e| {
        tracing::warn!("UDR smf-registrations put failed: {e}");
        StatusCode::BAD_GATEWAY
    })?;
    tracing::info!(%supi, psi, smf = %reg.smf_instance_id, "serving SMF registered (UECM)");
    Ok(StatusCode::CREATED)
}

async fn uecm_deregister_smf(
    State(udr): State<Arc<UdrClient>>,
    Path((supi, psi)): Path<(String, u8)>,
) -> Result<StatusCode, StatusCode> {
    let existed = udr.delete_smf_registration(&supi, psi).await.map_err(|e| {
        tracing::warn!("UDR smf-registrations delete failed: {e}");
        StatusCode::BAD_GATEWAY
    })?;
    if existed {
        tracing::info!(%supi, psi, "serving SMF purged (UECM)");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// `Nudm_SDM` query: the serving PLMN selects which provisioned dataset applies
/// (TS 29.503 `plmn-id`; we take the concatenated MCC+MNC form, e.g. `99970`).
#[derive(Debug, Deserialize)]
struct SdmQuery {
    #[serde(rename = "plmn-id")]
    plmn_id: String,
}

async fn sdm_am_data(
    State(udr): State<Arc<UdrClient>>,
    Path(supi): Path<String>,
    Query(q): Query<SdmQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    sdm_fetch(udr, DataSet::Am, supi, q.plmn_id).await
}

async fn sdm_sm_data(
    State(udr): State<Arc<UdrClient>>,
    Path(supi): Path<String>,
    Query(q): Query<SdmQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    sdm_fetch(udr, DataSet::Sm, supi, q.plmn_id).await
}

async fn sdm_smf_select_data(
    State(udr): State<Arc<UdrClient>>,
    Path(supi): Path<String>,
    Query(q): Query<SdmQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    sdm_fetch(udr, DataSet::SmfSelection, supi, q.plmn_id).await
}

async fn sdm_fetch(
    udr: Arc<UdrClient>,
    ds: DataSet,
    supi: String,
    plmn: String,
) -> Result<Json<serde_json::Value>, StatusCode> {
    udr.get_provisioned(ds, &supi, &plmn)
        .await
        .map_err(|e| {
            tracing::warn!("UDR provisioned-data fetch failed: {e}");
            StatusCode::BAD_GATEWAY
        })?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn generate_auth_data(
    State(udr): State<Arc<UdrClient>>,
    State(suci): State<Arc<aka::suci::HomeNetworkKeys>>,
    Path(supi_or_suci): Path<String>,
    Json(req): Json<AuthenticationInfoRequest>,
) -> Result<Json<AuthenticationInfoResult>, StatusCode> {
    // Recover the SUPI: deconceal a SUCI (null scheme, or ECIES Profile A/B with the
    // home-network private key), or pass a plain SUPI through unchanged (design/137 G2).
    let supi = aka::suci::deconceal(&supi_or_suci, &suci).map_err(|e| {
        tracing::warn!("SUCI deconcealment failed: {e}");
        StatusCode::FORBIDDEN
    })?;
    let (mcc, mnc) = parse_snn(&req.serving_network_name).ok_or(StatusCode::BAD_REQUEST)?;
    let av = udr
        .generate_av(&supi, &mcc, &mnc)
        .await
        .map_err(|e| {
            tracing::warn!("UDR generate-av failed: {e}");
            StatusCode::BAD_GATEWAY
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(AuthenticationInfoResult {
        auth_type: "5G_AKA".to_string(),
        authentication_vector: Av5gHe {
            av_type: "5G_HE_AKA".to_string(),
            rand: av.rand,
            xres_star: av.xres_star,
            autn: av.autn,
            kausf: av.kausf,
        },
        // The response carries the *deconcealed* SUPI (the AUSF/AMF key it by SUPI).
        supi,
    }))
}

/// Nudm_UEAuthentication resynchronisation (TS 29.503 §5.2): relay the UE's AUTS
/// (from a NAS Authentication Failure, cause #21) to the UDR/ARPF, which verifies
/// MAC-S and adopts the UE's SQN. `204` on success, `403` on a MAC-S mismatch,
/// `404` for an unknown subscriber (mapped from the Nudr response).
async fn resync(
    State(udr): State<Arc<UdrClient>>,
    Path(supi): Path<String>,
    Json(req): Json<ResyncInfo>,
) -> StatusCode {
    match udr.resync_av(&supi, &req.rand, &req.auts).await {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::FORBIDDEN,
        Err(e) => {
            tracing::warn!(supi = %supi, "UDR resync failed: {e}");
            StatusCode::BAD_GATEWAY
        }
    }
}

/// Parse `5G:mnc<MNC3>.mcc<MCC3>.3gppnetwork.org` → (mcc, mnc).
pub fn parse_snn(snn: &str) -> Option<(String, String)> {
    let mnc = snn.split("mnc").nth(1)?.get(..3)?.to_string();
    let mcc = snn.split("mcc").nth(1)?.get(..3)?.to_string();
    (mnc.bytes().all(|b| b.is_ascii_digit()) && mcc.bytes().all(|b| b.is_ascii_digit()))
        .then_some((mcc, mnc))
}

/// Client the AUSF uses to call the UDM.
pub struct NudmClient {
    base: String,
    http: reqwest::Client,
}

impl NudmClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: crate::sbi_client(),
        }
    }

    /// Nudm_UEAuthentication_Get — fetch a 5G HE AV for a subscriber.
    pub async fn generate_auth_data(
        &self,
        supi_or_suci: &str,
        serving_network_name: &str,
    ) -> Result<AuthenticationInfoResult, SbiError> {
        let url = format!(
            "{}/nudm-ueau/v1/{}/security-information/generate-auth-data",
            self.base, supi_or_suci
        );
        let resp = self
            .http
            .post(url)
            .json(&AuthenticationInfoRequest {
                serving_network_name: serving_network_name.to_string(),
                ausf_instance_id: None,
            })
            .traced()
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// Nudm_UEAuthentication — resynchronise the subscriber's SQN from a UE AUTS
    /// (hex `rand` + `auts`). `Ok(true)` when the SQN was adopted.
    pub async fn resync(&self, supi: &str, rand: &str, auts: &str) -> Result<bool, SbiError> {
        let resp = self
            .http
            .post(format!("{}/nudm-ueau/v1/{}/auth-events/resync", self.base, supi))
            .json(&ResyncInfo { rand: rand.to_string(), auts: auts.to_string() })
            .traced()
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    /// Nudm_UECM — register as the serving AMF for `supi` (create or replace).
    pub async fn uecm_register_amf(
        &self,
        supi: &str,
        reg: &Amf3GppAccessRegistration,
    ) -> Result<(), SbiError> {
        self.http
            .put(format!("{}/nudm-uecm/v1/{}/registrations/amf-3gpp-access", self.base, supi))
            .json(reg)
            .traced()
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Nudm_UECM — purge the serving-AMF registration. `Ok(false)` when none existed.
    pub async fn uecm_deregister_amf(&self, supi: &str) -> Result<bool, SbiError> {
        let resp = self
            .http
            .delete(format!("{}/nudm-uecm/v1/{}/registrations/amf-3gpp-access", self.base, supi))
            .traced()
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        resp.error_for_status()?;
        Ok(true)
    }

    /// Nudm_UECM — register as the serving SMF for a PDU session.
    pub async fn uecm_register_smf(&self, supi: &str, reg: &SmfRegistration) -> Result<(), SbiError> {
        self.http
            .put(format!(
                "{}/nudm-uecm/v1/{}/registrations/smf-registrations/{}",
                self.base, supi, reg.pdu_session_id
            ))
            .json(reg)
            .traced()
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Nudm_UECM — purge a serving-SMF registration. `Ok(false)` when none existed.
    pub async fn uecm_deregister_smf(
        &self,
        supi: &str,
        pdu_session_id: u8,
    ) -> Result<bool, SbiError> {
        let resp = self
            .http
            .delete(format!(
                "{}/nudm-uecm/v1/{}/registrations/smf-registrations/{}",
                self.base, supi, pdu_session_id
            ))
            .traced()
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        resp.error_for_status()?;
        Ok(true)
    }

    /// Nudm_SDM — Access and Mobility Subscription data (subscribed S-NSSAIs,
    /// UE-AMBR). `Ok(None)` if not provisioned.
    pub async fn get_am_data(
        &self,
        supi: &str,
        plmn: &str,
    ) -> Result<Option<serde_json::Value>, SbiError> {
        self.sdm_get("am-data", supi, plmn).await
    }

    /// Nudm_SDM — Session Management Subscription data. `Ok(None)` if not provisioned.
    pub async fn get_sm_data(
        &self,
        supi: &str,
        plmn: &str,
    ) -> Result<Option<serde_json::Value>, SbiError> {
        self.sdm_get("sm-data", supi, plmn).await
    }

    /// Nudm_SDM — SMF selection subscription data. `Ok(None)` if not provisioned.
    pub async fn get_smf_select_data(
        &self,
        supi: &str,
        plmn: &str,
    ) -> Result<Option<serde_json::Value>, SbiError> {
        self.sdm_get("smf-select-data", supi, plmn).await
    }

    async fn sdm_get(
        &self,
        resource: &str,
        supi: &str,
        plmn: &str,
    ) -> Result<Option<serde_json::Value>, SbiError> {
        let resp = self
            .http
            .get(format!("{}/nudm-sdm/v2/{}/{}", self.base, supi, resource))
            .query(&[("plmn-id", plmn)])
            .traced()
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// `Nudm_SDM_Subscribe` — subscribe `callback` to `supi`'s subscriber-data
    /// changes. Returns the created subscription id (for a later unsubscribe).
    pub async fn sdm_subscribe(&self, supi: &str, callback: &str) -> Result<String, SbiError> {
        let sub = SdmSubscription {
            subscription_id: None,
            callback_reference: callback.to_string(),
            monitored_resource_uris: Some(vec![format!("{}/nudm-sdm/v2/{}/am-data", self.base, supi)]),
        };
        let created: SdmSubscription = self
            .http
            .post(format!("{}/nudm-sdm/v2/{}/sdm-subscriptions", self.base, supi))
            .json(&sub)
            .traced()
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(created.subscription_id.unwrap_or_default())
    }

    /// `Nudm_SDM_Unsubscribe` — drop a change subscription. `Ok(false)` if unknown.
    pub async fn sdm_unsubscribe(&self, supi: &str, sub_id: &str) -> Result<bool, SbiError> {
        let resp = self
            .http
            .delete(format!("{}/nudm-sdm/v2/{}/sdm-subscriptions/{}", self.base, supi, sub_id))
            .traced()
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        resp.error_for_status()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subscriber_db::{InMemoryStore, ProvisionedDataStore, SubscriberStore};

    /// The UDM proxies Nudm_SDM am-data from the UDR verbatim; absent → 404/None.
    #[tokio::test]
    async fn sdm_am_data_proxies_the_udr_document() {
        let store = Arc::new(InMemoryStore::new());
        let am = serde_json::json!({
            "nssai": { "defaultSingleNssais": [{ "sst": 1, "sd": "010203" }] },
            "subscribedUeAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" }
        });
        store.put_provisioned(DataSet::Am, "imsi-1", "99970", &am).unwrap();
        let store: Arc<dyn SubscriberStore> = store;

        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, crate::nudr::router(store)).await.unwrap() });

        let udr = Arc::new(UdrClient::new(format!("http://{udr_addr}")));
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udm_l, router(udr)).await.unwrap() });

        let sdm = NudmClient::new(format!("http://{udm_addr}"));
        assert_eq!(sdm.get_am_data("imsi-1", "99970").await.unwrap(), Some(am));
        assert_eq!(sdm.get_am_data("imsi-1", "00101").await.unwrap(), None, "other PLMN");
        assert_eq!(sdm.get_am_data("imsi-2", "99970").await.unwrap(), None, "unknown SUPI");
    }

    /// The UDM deconceals a SUCI before looking up the subscriber (design/137 G2): a
    /// null-scheme SUCI resolves to the SUPI the credentials were provisioned under, so
    /// an AV comes back and the response carries the *deconcealed* SUPI. (The ECIES
    /// profiles are exercised in `aka::suci`; here we prove the UDM is wired to it.)
    #[tokio::test]
    async fn generate_auth_data_deconceals_a_suci() {
        let store = Arc::new(InMemoryStore::new());
        // TS 35.208 test credentials, provisioned under the *deconcealed* SUPI.
        store
            .provision_hex(
                "imsi-999700000000001",
                "465b5ce8b199b49faa5f0a2ee238a6bc",
                "cd63cb71954a9f4e48a5994e37a02baf",
                "8000",
            )
            .unwrap();
        let store: Arc<dyn SubscriberStore> = store;

        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, crate::nudr::router(store)).await.unwrap() });

        let udr = Arc::new(UdrClient::new(format!("http://{udr_addr}")));
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udm_l, router(udr)).await.unwrap() });

        let udm = NudmClient::new(format!("http://{udm_addr}"));
        let snn = aka::serving_network_name("999", "70");

        // A null-scheme SUCI → imsi-999700000000001, which the UDR knows.
        let result = udm
            .generate_auth_data("suci-0-999-70-0-0-0-0000000001", &snn)
            .await
            .expect("AV for the deconcealed SUPI");
        assert_eq!(result.supi, "imsi-999700000000001", "response carries the deconcealed SUPI");
        assert_eq!(result.authentication_vector.av_type, "5G_HE_AKA");
        assert!(!result.authentication_vector.rand.is_empty(), "an AV was generated");

        // A plain SUPI still works (passthrough).
        assert_eq!(
            udm.generate_auth_data("imsi-999700000000001", &snn).await.unwrap().supi,
            "imsi-999700000000001"
        );
    }

    /// A Nudm_SDM change subscription: subscribe a callback, a data-change fans a
    /// ModificationNotification out to it; after unsubscribing, it reaches nobody.
    #[tokio::test]
    async fn sdm_change_subscription_fans_out() {
        use std::sync::Mutex as StdMutex;

        type Received = Arc<StdMutex<Vec<ModificationNotification>>>;
        async fn cb(
            State(rx): State<Received>,
            Json(n): Json<ModificationNotification>,
        ) -> StatusCode {
            rx.lock().unwrap().push(n);
            StatusCode::NO_CONTENT
        }
        let received: Received = Arc::new(StdMutex::new(Vec::new()));
        let cb_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cb_addr = cb_l.local_addr().unwrap();
        let cb_router = Router::new().route("/cb", post(cb)).with_state(received.clone());
        tokio::spawn(async move { crate::run_on(cb_l, cb_router).await.unwrap() });

        // The UDM router (its UDR is unused by the SDM subscription surface).
        let udr = Arc::new(UdrClient::new("http://127.0.0.1:1"));
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udm_l, router(udr)).await.unwrap() });
        let udm_base = format!("http://{udm_addr}");
        let sdm = NudmClient::new(udm_base.clone());

        let sub_id = sdm.sdm_subscribe("imsi-1", &format!("http://{cb_addr}/cb")).await.unwrap();
        assert!(!sub_id.is_empty(), "a subscription id is returned");

        // The fan-out awaits each callback, so delivery is complete when it returns.
        let http = crate::sbi_client();
        let out: serde_json::Value = http
            .post(format!("{udm_base}/nudm-sdm/v2/imsi-1/notify-data-change"))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(out.get("notified").and_then(|v| v.as_u64()), Some(1));
        {
            let got = received.lock().unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].notify_items[0].resource_id, "am-data");
        }

        // After unsubscribing, a change reaches nobody.
        assert!(sdm.sdm_unsubscribe("imsi-1", &sub_id).await.unwrap());
        let out: serde_json::Value = http
            .post(format!("{udm_base}/nudm-sdm/v2/imsi-1/notify-data-change"))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(out.get("notified").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(received.lock().unwrap().len(), 1, "no delivery after unsubscribe");
    }
}
