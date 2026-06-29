//! Nudm_UEAuthentication — UDM/ARPF authentication-vector service (TS 29.503).
//!
//! Holds long-term subscriber credentials and generates 5G HE authentication
//! vectors (RAND, AUTN, XRES*, K_AUSF) on request from the AUSF, using the `aka`
//! crate (MILENAGE + TS 33.501 key derivation).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aka::SubscriberKey;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::SbiError;

/// In-memory subscriber database (ARPF). Maps SUPI → credentials + sequence number.
#[derive(Clone, Default)]
pub struct SubscriberDb(Arc<Mutex<HashMap<String, SubscriberState>>>);

struct SubscriberState {
    key: SubscriberKey,
    sqn: [u8; 6],
}

impl SubscriberDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision a subscriber (SQN starts at zero).
    pub fn insert(&self, supi: impl Into<String>, key: SubscriberKey) {
        self.0
            .lock()
            .unwrap()
            .insert(supi.into(), SubscriberState { key, sqn: [0u8; 6] });
    }

    /// Provision a subscriber from hex strings (K, OPc = 16 bytes; AMF = 2 bytes).
    pub fn insert_hex(&self, supi: &str, k: &str, opc: &str, amf: &str) -> Result<(), String> {
        self.insert(
            supi,
            SubscriberKey {
                k: parse_n(k)?,
                opc: parse_n(opc)?,
                amf: parse_n(amf)?,
            },
        );
        Ok(())
    }
}

fn parse_n<const N: usize>(h: &str) -> Result<[u8; N], String> {
    hex::decode(h)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| format!("expected {N} bytes"))
}

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

/// Build the UDM router (Nudm_UEAuthentication_Get).
pub fn router(db: SubscriberDb) -> Router {
    Router::new()
        .route(
            "/nudm-ueau/v1/{supi_or_suci}/security-information/generate-auth-data",
            post(generate_auth_data),
        )
        .with_state(db)
}

async fn generate_auth_data(
    State(db): State<SubscriberDb>,
    Path(supi_or_suci): Path<String>,
    Json(req): Json<AuthenticationInfoRequest>,
) -> Result<Json<AuthenticationInfoResult>, StatusCode> {
    // NOTE: SUCI deconcealment is out of scope; supiOrSuci is treated as the SUPI.
    let (mcc, mnc) = parse_snn(&req.serving_network_name).ok_or(StatusCode::BAD_REQUEST)?;

    let av = {
        let mut guard = db.0.lock().unwrap();
        let sub = guard.get_mut(&supi_or_suci).ok_or(StatusCode::NOT_FOUND)?;
        sub.sqn = increment_sqn(sub.sqn);
        let rand = crate::random_rand();
        aka::generate_5g_he_av(&sub.key, &sub.sqn, &rand, &mcc, &mnc)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    Ok(Json(AuthenticationInfoResult {
        auth_type: "5G_AKA".to_string(),
        authentication_vector: Av5gHe {
            av_type: "5G_HE_AKA".to_string(),
            rand: hex::encode(av.rand),
            xres_star: hex::encode(av.xres_star),
            autn: hex::encode(av.autn),
            kausf: hex::encode(av.kausf),
        },
        supi: supi_or_suci,
    }))
}

fn increment_sqn(mut sqn: [u8; 6]) -> [u8; 6] {
    for i in (0..6).rev() {
        let (v, carry) = sqn[i].overflowing_add(1);
        sqn[i] = v;
        if !carry {
            break;
        }
    }
    sqn
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
