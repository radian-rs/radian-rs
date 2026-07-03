//! Nudm — UDM services (TS 29.503): `Nudm_UEAuthentication` (authentication
//! vectors) and `Nudm_SDM` (subscriber data management, the SMF's view of
//! sm-data / smf-select-data).
//!
//! The UDM here is a stateless front-end over the **UDR** (Nudr, design/24 step 1):
//! authentication asks the UDR — which co-hosts the ARPF — to derive a 5G HE
//! vector (**the long-term key K never reaches this module or the UDM↔UDR wire**),
//! and SDM proxies the provisioned-data documents verbatim.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subscriber_db::DataSet;

use crate::nudr::UdrClient;
use crate::SbiError;

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
        .with_state(udr)
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
    Path(supi_or_suci): Path<String>,
    Json(req): Json<AuthenticationInfoRequest>,
) -> Result<Json<AuthenticationInfoResult>, StatusCode> {
    // NOTE: SUCI deconcealment is out of scope; supiOrSuci is treated as the SUPI.
    let (mcc, mnc) = parse_snn(&req.serving_network_name).ok_or(StatusCode::BAD_REQUEST)?;
    let av = udr
        .generate_av(&supi_or_suci, &mcc, &mnc)
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
        supi: supi_or_suci,
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
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
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
}
