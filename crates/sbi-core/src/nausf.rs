//! Nausf_UEAuthentication — AUSF 5G-AKA authentication service (TS 29.509).
//!
//! Orchestrates 5G-AKA: on `authenticate` the AUSF fetches a 5G HE AV from the UDM,
//! derives the 5G SE AV (HXRES*), and returns RAND/AUTN/HXRES* to the SEAF (AMF).
//! On `confirm` it compares the UE's RES* to the stored XRES* and, on success,
//! returns the SUPI and K_SEAF.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::nudm::{parse_snn, NudmClient};
use crate::SbiError;

/// AUSF state: a UDM client plus in-flight authentication contexts.
#[derive(Clone)]
pub struct AusfState {
    udm: Arc<NudmClient>,
    ctxs: Arc<Mutex<HashMap<String, AuthCtx>>>,
}

struct AuthCtx {
    supi: String,
    xres_star: [u8; 16],
    kausf: [u8; 32],
    mcc: String,
    mnc: String,
}

impl AusfState {
    /// Create AUSF state targeting the UDM at `udm_base` (e.g. `http://127.0.0.1:8004`).
    pub fn new(udm_base: impl Into<String>) -> Self {
        Self {
            udm: Arc::new(NudmClient::new(udm_base)),
            ctxs: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfo {
    pub supi_or_suci: String,
    pub serving_network_name: String,
    /// Present on a **resynchronisation** retry (TS 29.509 §6.1): the UE's AUTS
    /// (from a NAS Authentication Failure, cause #21) with the `rand` it answers.
    /// The AUSF relays it to the UDM to adopt the UE's SQN before fetching a
    /// fresh 5G HE AV.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resynchronization_info: Option<ResynchronizationInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResynchronizationInfo {
    pub rand: String,
    pub auts: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UeAuthenticationCtx {
    pub auth_type: String,
    pub fiveg_auth_data: FivegAuthData,
    pub auth_ctx_id: String,
}

/// 5G SE authentication data sent to the SEAF (hex strings).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FivegAuthData {
    pub rand: String,
    pub autn: String,
    pub hxres_star: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationData {
    pub res_star: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationDataResponse {
    pub auth_result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kseaf: Option<String>,
}

/// Build the AUSF router (Nausf_UEAuthentication).
pub fn router(state: AusfState) -> Router {
    Router::new()
        .route("/nausf-auth/v1/ue-authentications", post(authenticate))
        .route(
            "/nausf-auth/v1/ue-authentications/{ctx}/5g-aka-confirmation",
            put(confirm),
        )
        .with_state(state)
}

async fn authenticate(
    State(state): State<AusfState>,
    Json(info): Json<AuthenticationInfo>,
) -> Result<(StatusCode, Json<UeAuthenticationCtx>), StatusCode> {
    let (mcc, mnc) = parse_snn(&info.serving_network_name).ok_or(StatusCode::BAD_REQUEST)?;

    // Resynchronisation retry: relay the UE's AUTS to the UDM (which adopts the
    // UE's SQN) before fetching a fresh AV, so the new challenge is in sync. A
    // refused resync (MAC-S mismatch) fails the request rather than handing back
    // a vector the UE will reject again.
    if let Some(rs) = &info.resynchronization_info {
        let ok = state
            .udm
            .resync(&info.supi_or_suci, &rs.rand, &rs.auts)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        if !ok {
            tracing::warn!(supi = %info.supi_or_suci, "resync refused by the UDM");
            return Err(StatusCode::FORBIDDEN);
        }
        tracing::info!(supi = %info.supi_or_suci, "SQN resynchronised; issuing a fresh challenge");
    }

    // Fetch the HE AV from the UDM.
    let result = state
        .udm
        .generate_auth_data(&info.supi_or_suci, &info.serving_network_name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let av = &result.authentication_vector;
    let rand = parse16(&av.rand).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let xres_star = parse16(&av.xres_star).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let kausf = parse32(&av.kausf).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Derive the 5G SE AV and stash the context for confirmation.
    let hxres = aka::hxres_star(&rand, &xres_star);
    let ctx_id = crate::new_nf_instance_id();
    state.ctxs.lock().unwrap().insert(
        ctx_id.clone(),
        AuthCtx {
            supi: result.supi,
            xres_star,
            kausf,
            mcc,
            mnc,
        },
    );

    Ok((
        StatusCode::CREATED,
        Json(UeAuthenticationCtx {
            auth_type: "5G_AKA".to_string(),
            fiveg_auth_data: FivegAuthData {
                rand: av.rand.clone(),
                autn: av.autn.clone(),
                hxres_star: hex::encode(hxres),
            },
            auth_ctx_id: ctx_id,
        }),
    ))
}

async fn confirm(
    State(state): State<AusfState>,
    Path(ctx_id): Path<String>,
    Json(data): Json<ConfirmationData>,
) -> Result<Json<ConfirmationDataResponse>, StatusCode> {
    let res_star = parse16(&data.res_star).ok_or(StatusCode::BAD_REQUEST)?;
    let mut guard = state.ctxs.lock().unwrap();
    let ctx = guard.get(&ctx_id).ok_or(StatusCode::NOT_FOUND)?;

    if res_star == ctx.xres_star {
        let kseaf = aka::kseaf(&ctx.kausf, &ctx.mcc, &ctx.mnc);
        let supi = ctx.supi.clone();
        guard.remove(&ctx_id); // single-use context
        Ok(Json(ConfirmationDataResponse {
            auth_result: "AUTHENTICATION_SUCCESS".to_string(),
            supi: Some(supi),
            kseaf: Some(hex::encode(kseaf)),
        }))
    } else {
        Ok(Json(ConfirmationDataResponse {
            auth_result: "AUTHENTICATION_FAILURE".to_string(),
            supi: None,
            kseaf: None,
        }))
    }
}

fn parse16(h: &str) -> Option<[u8; 16]> {
    hex::decode(h).ok()?.try_into().ok()
}

fn parse32(h: &str) -> Option<[u8; 32]> {
    hex::decode(h).ok()?.try_into().ok()
}

/// Client the AMF/SEAF uses to authenticate a UE via the AUSF.
pub struct AusfClient {
    base: String,
    http: reqwest::Client,
}

impl AusfClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: crate::sbi_client(),
        }
    }

    /// Nausf_UEAuthentication_Authenticate (initiate) — returns RAND/AUTN/HXRES* + ctx.
    pub async fn authenticate(
        &self,
        supi_or_suci: &str,
        serving_network_name: &str,
    ) -> Result<UeAuthenticationCtx, SbiError> {
        self.authenticate_inner(supi_or_suci, serving_network_name, None).await
    }

    /// Like [`authenticate`], but carries the UE's **AUTS** (hex `rand`/`auts`) so
    /// the AUSF/UDM resynchronise the SQN before issuing a fresh challenge
    /// (TS 29.509 §6.1). Returns the new RAND/AUTN/HXRES* + ctx.
    pub async fn authenticate_resync(
        &self,
        supi_or_suci: &str,
        serving_network_name: &str,
        rand: &str,
        auts: &str,
    ) -> Result<UeAuthenticationCtx, SbiError> {
        let info = ResynchronizationInfo { rand: rand.to_string(), auts: auts.to_string() };
        self.authenticate_inner(supi_or_suci, serving_network_name, Some(info)).await
    }

    async fn authenticate_inner(
        &self,
        supi_or_suci: &str,
        serving_network_name: &str,
        resynchronization_info: Option<ResynchronizationInfo>,
    ) -> Result<UeAuthenticationCtx, SbiError> {
        let resp = self
            .http
            .post(format!("{}/nausf-auth/v1/ue-authentications", self.base))
            .json(&AuthenticationInfo {
                supi_or_suci: supi_or_suci.to_string(),
                serving_network_name: serving_network_name.to_string(),
                resynchronization_info,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// 5G-AKA confirmation (PUT) — submit the UE's RES*.
    pub async fn confirm(
        &self,
        ctx_id: &str,
        res_star_hex: &str,
    ) -> Result<ConfirmationDataResponse, SbiError> {
        let resp = self
            .http
            .put(format!(
                "{}/nausf-auth/v1/ue-authentications/{}/5g-aka-confirmation",
                self.base, ctx_id
            ))
            .json(&ConfirmationData {
                res_star: res_star_hex.to_string(),
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::sync::Arc;
    use subscriber_db::{InMemoryStore, SubscriberStore};

    fn test_subscriber() -> aka::SubscriberKey {
        aka::SubscriberKey {
            k: hex!("465b5ce8b199b49faa5f0a2ee238a6bc"),
            opc: hex!("cd63cb71954a9f4e48a5994e37a02baf"),
            amf: hex!("8000"),
        }
    }

    /// Spin a UDR + UDM + AUSF chain and return (ausf_base, udr provisioned with `supi`).
    async fn spin(supi: &str, sub: aka::SubscriberKey) -> String {
        let store = Arc::new(InMemoryStore::new());
        store.provision(supi, sub);
        let store: Arc<dyn SubscriberStore> = store;
        let udr = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr, crate::nudr::router(store)).await.unwrap() });

        let udr_client = Arc::new(crate::nudr::UdrClient::new(format!("http://{udr_addr}")));
        let udm = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udm, crate::nudm::router(udr_client)).await.unwrap() });

        let ausf = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ausf_addr = ausf.local_addr().unwrap();
        let state = AusfState::new(format!("http://{udm_addr}"));
        tokio::spawn(async move { crate::run_on(ausf, router(state)).await.unwrap() });

        format!("http://{ausf_addr}")
    }

    #[tokio::test]
    async fn five_g_aka_over_sbi_succeeds() {
        let supi = "imsi-999700000000001";
        let sub = test_subscriber();
        let ausf_base = spin(supi, sub.clone()).await;
        let snn = aka::serving_network_name("999", "70");
        let amf = AusfClient::new(ausf_base);

        // AMF/SEAF initiates authentication; AUSF returns RAND/AUTN.
        let ctx = amf.authenticate(supi, &snn).await.unwrap();
        assert_eq!(ctx.auth_type, "5G_AKA");
        let rand = parse16(&ctx.fiveg_auth_data.rand).unwrap();
        let autn = parse16(&ctx.fiveg_auth_data.autn).unwrap();

        // UE verifies AUTN and computes RES*.
        let res_star = aka::ue_compute_res_star(&sub, &rand, &autn, "999", "70").unwrap();

        // AMF confirms RES* — AUSF compares to XRES* and returns SUPI + K_SEAF.
        let result = amf
            .confirm(&ctx.auth_ctx_id, &hex::encode(res_star))
            .await
            .unwrap();
        assert_eq!(result.auth_result, "AUTHENTICATION_SUCCESS");
        assert_eq!(result.supi.as_deref(), Some(supi));
        assert!(result.kseaf.is_some(), "K_SEAF returned on success");
    }

    #[tokio::test]
    async fn wrong_res_star_fails() {
        let supi = "imsi-999700000000002";
        let ausf_base = spin(supi, test_subscriber()).await;
        let snn = aka::serving_network_name("999", "70");
        let amf = AusfClient::new(ausf_base);

        let ctx = amf.authenticate(supi, &snn).await.unwrap();
        let result = amf
            .confirm(&ctx.auth_ctx_id, &hex::encode([0u8; 16]))
            .await
            .unwrap();
        assert_eq!(result.auth_result, "AUTHENTICATION_FAILURE");
        assert!(result.supi.is_none());
    }
}
