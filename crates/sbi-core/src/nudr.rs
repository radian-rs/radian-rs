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

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subscriber_db::{DataSet, SubscriberStore};

use crate::SbiError;

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

/// Build the UDR router (Nudr_DataRepository) over the subscriber store.
pub fn router(store: Arc<dyn SubscriberStore>) -> Router {
    Router::new()
        .route(
            "/nudr-dr/v2/subscription-data/{ue_id}/authentication-data/generate-av",
            post(generate_av),
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
        .with_state(store)
}

async fn generate_av(
    State(store): State<Arc<dyn SubscriberStore>>,
    Path(ue_id): Path<String>,
    Json(req): Json<GenerateAvRequest>,
) -> Result<Json<HeAv>, StatusCode> {
    let sqn = store.next_sqn(&ue_id).ok_or(StatusCode::NOT_FOUND)?;
    let rand = crate::random_rand();
    let av = store
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
            State(store): State<Arc<dyn SubscriberStore>>,
            Path((ue_id, plmn)): Path<(String, String)>,
        ) -> Result<Json<serde_json::Value>, StatusCode> {
            get_doc(store, $ds, ue_id, plmn).await
        }
        async fn $put(
            State(store): State<Arc<dyn SubscriberStore>>,
            Path((ue_id, plmn)): Path<(String, String)>,
            Json(doc): Json<serde_json::Value>,
        ) -> StatusCode {
            put_doc(store, $ds, ue_id, plmn, doc).await
        }
    };
}

doc_handlers!(get_am_data, put_am_data, DataSet::Am);
doc_handlers!(get_sm_data, put_sm_data, DataSet::Sm);
doc_handlers!(get_smf_sel, put_smf_sel, DataSet::SmfSelection);

fn dataset_path(ds: DataSet) -> &'static str {
    match ds {
        DataSet::Am => "am-data",
        DataSet::Sm => "sm-data",
        DataSet::SmfSelection => "smf-selection-subscription-data",
    }
}

/// Client the UDM (and later PCF) uses to reach the UDR over h2c.
pub struct UdrClient {
    base: String,
    http: reqwest::Client,
}

impl UdrClient {
    /// Target a UDR at `base_url`, e.g. `http://127.0.0.1:8005`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into(),
            http: crate::h2c_client(),
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
            .http
            .post(url)
            .json(&GenerateAvRequest { mcc: mcc.to_string(), mnc: mnc.to_string() })
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
        let resp = self.http.get(self.doc_url(ds, supi, plmn)).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// Store (create or replace) a provisioned-data document.
    pub async fn put_provisioned(
        &self,
        ds: DataSet,
        supi: &str,
        plmn: &str,
        doc: &serde_json::Value,
    ) -> Result<(), SbiError> {
        self.http
            .put(self.doc_url(ds, supi, plmn))
            .json(doc)
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
