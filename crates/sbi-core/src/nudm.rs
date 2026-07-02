//! Nudm_UEAuthentication — UDM authentication-vector service (TS 29.503).
//!
//! The UDM here is a stateless front-end over the **UDR** (Nudr, design/24 step 1):
//! it parses the serving network and asks the UDR — which co-hosts the ARPF — to
//! derive a 5G HE authentication vector. **The long-term key K never reaches this
//! module or the UDM↔UDR wire** — only the derived vector does.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::nudr::UdrClient;
use crate::SbiError;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfoRequest {
    pub serving_network_name: String,
    #[serde(default)]
    pub ausf_instance_id: Option<String>,
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

/// Build the UDM router (Nudm_UEAuthentication_Get) backed by the UDR over Nudr.
pub fn router(udr: Arc<UdrClient>) -> Router {
    Router::new()
        .route(
            "/nudm-ueau/v1/{supi_or_suci}/security-information/generate-auth-data",
            post(generate_auth_data),
        )
        .with_state(udr)
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
            http: crate::h2c_client(),
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
}
