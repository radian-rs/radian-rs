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
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subscriber_db::{DataSet, SubscriberStore};

use crate::SbiError;

/// Router state: the store plus (optionally) the NRF used to notify the AMF of
/// subscription withdrawals.
#[derive(Clone)]
struct NudrState {
    store: Arc<dyn SubscriberStore>,
    notify_nrf: Option<String>,
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

/// Build the UDR router (Nudr_DataRepository) over the subscriber store.
pub fn router(store: Arc<dyn SubscriberStore>) -> Router {
    router_with_notify(store, None)
}

/// Like [`router`], but a subscription withdrawal (`DELETE …/subscription-data/
/// {ueId}`) also notifies the serving AMF — discovered via the NRF at `nrf_base` —
/// with a `DeregistrationData` callback (deviation: TS 23.502 mediates this
/// through UDM data-change subscriptions; we collapse UDR→UDM→AMF to UDR→AMF).
pub fn router_with_notify(store: Arc<dyn SubscriberStore>, notify_nrf: Option<String>) -> Router {
    let state = NudrState { store, notify_nrf };
    Router::new()
        .route(
            "/nudr-dr/v2/subscription-data/{ue_id}/authentication-data/generate-av",
            post(generate_av),
        )
        .route("/nudr-dr/v2/subscription-data/{ue_id}", delete(delete_subscription))
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
        .with_state(state)
}

/// Withdraw a subscription: remove everything stored for the SUPI, then (when
/// configured) notify the serving AMF so it network-deregisters the UE.
async fn delete_subscription(
    State(st): State<NudrState>,
    Path(ue_id): Path<String>,
) -> StatusCode {
    if !st.store.remove_subscriber(&ue_id) {
        return StatusCode::NOT_FOUND;
    }
    tracing::info!(supi = %ue_id, "subscription withdrawn");
    if let Some(nrf) = st.notify_nrf.clone() {
        // Best-effort, off the request path: the withdrawal stands even if the
        // AMF is unreachable (the UE is simply not chased off until it returns).
        tokio::spawn(async move {
            if let Err(e) = notify_amf_deregistration(&nrf, &ue_id).await {
                tracing::warn!(supi = %ue_id, "AMF deregistration notify failed: {e}");
            }
        });
    }
    StatusCode::NO_CONTENT
}

/// POST a `DeregistrationData` (TS 29.503-shaped) to the NRF-discovered AMF.
async fn notify_amf_deregistration(nrf_base: &str, supi: &str) -> Result<(), String> {
    let profile = crate::nnrf::NrfClient::new(nrf_base.to_string())
        .discover("AMF", "UDR")
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?
        .into_iter()
        .next()
        .ok_or("no AMF registered with the NRF")?;
    let ep = profile
        .nf_services
        .and_then(|s| s.into_iter().next())
        .and_then(|svc| svc.ip_end_points.into_iter().next())
        .ok_or("AMF profile has no service endpoint")?;
    let (ip, port) = (ep.ipv4_address.ok_or("no IP")?, ep.port.ok_or("no port")?);
    let resp = crate::h2c_client()
        .post(format!("http://{ip}:{port}/namf-callback/v1/{supi}/dereg-notify"))
        .json(&serde_json::json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN" }))
        .send()
        .await
        .map_err(|e| format!("callback failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("AMF answered {}", resp.status()));
    }
    tracing::info!(supi = %supi, "AMF notified of subscription withdrawal");
    Ok(())
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

    /// Withdraw a subscription (`DELETE …/subscription-data/{ueId}`). `Ok(true)`
    /// if it existed, `Ok(false)` on 404.
    pub async fn delete_subscriber(&self, supi: &str) -> Result<bool, SbiError> {
        let resp = self
            .http
            .delete(format!("{}/nudr-dr/v2/subscription-data/{}", self.base, supi))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        resp.error_for_status()?;
        Ok(true)
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

    /// A DELETE withdraws the subscription and (when configured) notifies the
    /// NRF-discovered AMF with a DeregistrationData callback.
    #[tokio::test]
    async fn subscription_withdrawal_notifies_the_amf() {
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

        // NRF with the mock AMF registered.
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let store = crate::nnrf::NrfStore::default();
        tokio::spawn(async move { crate::run_on(nrf_l, crate::nnrf::router(store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");
        let mut profile =
            crate::nnrf::NfProfile::new("amf-1", "AMF", amf_addr.ip().to_string());
        profile.nf_services = Some(vec![crate::nnrf::NfService {
            service_instance_id: "namf-callback-1".into(),
            service_name: "namf-callback".into(),
            scheme: "http".into(),
            ip_end_points: vec![crate::nnrf::IpEndPoint {
                ipv4_address: Some(amf_addr.ip().to_string()),
                port: Some(amf_addr.port()),
            }],
        }]);
        crate::nnrf::NrfClient::new(nrf_base.clone()).register(&profile).await.unwrap();

        // UDR with notification enabled and one provisioned subscriber.
        let store = Arc::new(InMemoryStore::new());
        store
            .provision_hex(
                "imsi-1",
                "465b5ce8b199b49faa5f0a2ee238a6bc",
                "cd63cb71954a9f4e48a5994e37a02baf",
                "8000",
            )
            .unwrap();
        let store: Arc<dyn SubscriberStore> = store;
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move {
            crate::run_on(udr_l, router_with_notify(store, Some(nrf_base))).await.unwrap()
        });
        let udr = UdrClient::new(format!("http://{udr_addr}"));

        assert_eq!(udr.delete_subscriber("imsi-1").await.unwrap(), true);
        assert!(udr.generate_av("imsi-1", "999", "70").await.unwrap().is_none(), "withdrawn");
        assert_eq!(udr.delete_subscriber("imsi-1").await.unwrap(), false, "second delete 404s");

        // The notification is spawned off the request path — poll briefly.
        for _ in 0..50 {
            if NOTIFIED.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(NOTIFIED.load(Ordering::Relaxed), 1, "AMF notified exactly once");
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
