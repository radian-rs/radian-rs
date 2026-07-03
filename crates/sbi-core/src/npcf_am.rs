//! Npcf_AMPolicyControl — the PCF's **access-and-mobility** policy service
//! (TS 29.507). Complements Npcf_SMPolicyControl ([`crate::npcf`], the session
//! side): the AMF creates an **AM policy association** at registration and the PCF
//! returns AM policy data — here the **RFSP** index (RAT/Frequency Selection
//! Priority) and a policy **UE-AMBR** the AMF enforces at the gNB. Deleted at
//! deregistration.
//!
//! Policy source is a local [`AmPolicyConfig`] (per-subscriber UDR am-policy-data
//! sourcing is a follow-up, mirroring the SM side's Nudr wiring).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::nudr::UdrClient;
use crate::SbiError;

/// An aggregate maximum bit rate (TS 29.571 `Ambr`) — bitrate strings like "1 Gbps".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ambr {
    pub uplink: String,
    pub downlink: String,
}

/// `PolicyAssociationRequest` (TS 29.507 §5.6.2.2), trimmed — what the AMF tells
/// the PCF when creating the association.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAssociationRequest {
    pub supi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving_plmn: Option<String>,
}

/// `PolicyAssociation` (TS 29.507 §5.6.2.4) — the AM policy the PCF returns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAssociation {
    /// RAT/Frequency Selection Priority index (TS 23.501 §5.3.4.3) — RAN steering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfsp: Option<u16>,
    /// The UE-AMBR the AMF enforces at the gNB (policy override of the subscribed one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue_ambr: Option<Ambr>,
    /// Policy control request triggers (informational here).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggers: Vec<String>,
}

/// Local AM policy configuration — the decision the PCF returns for an association.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfsp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue_ambr: Option<Ambr>,
}

impl AmPolicyConfig {
    /// A demo AM policy: an RFSP index + a policy UE-AMBR (tighter than the
    /// subscribed 1/2 Gbps, so the override is observable end to end).
    pub fn demo() -> Self {
        Self {
            rfsp: Some(3),
            ue_ambr: Some(Ambr { uplink: "500 Mbps".into(), downlink: "1 Gbps".into() }),
        }
    }

    fn decide(&self) -> PolicyAssociation {
        PolicyAssociation {
            rfsp: self.rfsp,
            ue_ambr: self.ue_ambr.clone(),
            triggers: Vec::new(),
        }
    }
}

/// PCF AM-policy runtime: the policy source (UDR when configured, else the local
/// config) + in-memory AM policy associations.
#[derive(Clone, Default)]
pub struct AmPcfState {
    config: AmPolicyConfig,
    /// UDR client — the authoritative source (Nudr am-policy-data). `None` ⇒ local
    /// config only.
    udr: Option<Arc<UdrClient>>,
    associations: Arc<Mutex<HashMap<String, PolicyAssociationRequest>>>,
    next_id: Arc<AtomicU64>,
}

impl AmPcfState {
    pub fn new(config: AmPolicyConfig) -> Self {
        Self {
            config,
            udr: None,
            associations: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Source AM policy from the UDR (Nudr am-policy-data), per subscriber, falling
    /// back to the local config when a subscriber has none provisioned.
    pub fn with_udr(mut self, udr: Arc<UdrClient>) -> Self {
        self.udr = Some(udr);
        self
    }

    /// Number of open AM policy associations — test/observability hook.
    pub fn association_count(&self) -> usize {
        self.associations.lock().unwrap().len()
    }

    /// The AM policy for `supi`: the subscriber's UDR am-policy-data when
    /// provisioned, else the local config.
    async fn decide_for(&self, supi: &str) -> PolicyAssociation {
        if let Some(udr) = &self.udr {
            match udr.get_am_policy_data(supi).await {
                Ok(Some(doc)) => match serde_json::from_value::<AmPolicyConfig>(doc) {
                    Ok(cfg) => return cfg.decide(),
                    Err(e) => tracing::warn!(%supi, "UDR am-policy-data malformed ({e}); using local policy"),
                },
                Ok(None) => tracing::debug!(%supi, "no UDR am-policy-data; using local policy"),
                Err(e) => tracing::warn!("UDR am-policy-data fetch failed ({e}); using local policy"),
            }
        }
        self.config.decide()
    }
}

/// The Npcf_AMPolicyControl router (create / delete). Merge with the SM router.
pub fn router(state: AmPcfState) -> Router {
    Router::new()
        .route("/npcf-am-policy-control/v1/policies", post(create))
        .route("/npcf-am-policy-control/v1/policies/{id}/delete", post(delete))
        .with_state(state)
}

/// `Npcf_AMPolicyControl_Create` — open the association, return the AM policy. The
/// association id is echoed in the `Location` header.
async fn create(
    State(pcf): State<AmPcfState>,
    Json(req): Json<PolicyAssociationRequest>,
) -> (StatusCode, [(axum::http::HeaderName, String); 1], Json<PolicyAssociation>) {
    let id = pcf.next_id.fetch_add(1, Ordering::Relaxed).to_string();
    let decision = pcf.decide_for(&req.supi).await;
    tracing::info!(supi = %req.supi, assoc = %id, rfsp = ?decision.rfsp, "created AM policy association");
    pcf.associations.lock().unwrap().insert(id.clone(), req);
    let location = format!("/npcf-am-policy-control/v1/policies/{id}");
    (StatusCode::CREATED, [(axum::http::header::LOCATION, location)], Json(decision))
}

/// `Npcf_AMPolicyControl_Delete`.
async fn delete(State(pcf): State<AmPcfState>, Path(id): Path<String>) -> StatusCode {
    if pcf.associations.lock().unwrap().remove(&id).is_some() {
        tracing::info!(assoc = %id, "deleted AM policy association");
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// The AM policy association the AMF created: the id (from `Location`) + the policy.
pub struct AmPolicyCreated {
    pub assoc_id: String,
    pub policy: PolicyAssociation,
}

/// Client the AMF uses to reach the PCF's Npcf_AMPolicyControl.
pub struct AmPolicyClient {
    base: String,
    http: reqwest::Client,
}

impl AmPolicyClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into(), http: crate::sbi_client() }
    }

    /// Create an AM policy association; returns the id (from `Location`) + policy.
    pub async fn create(&self, req: &PolicyAssociationRequest) -> Result<AmPolicyCreated, SbiError> {
        let resp = self
            .http
            .post(format!("{}/npcf-am-policy-control/v1/policies", self.base))
            .json(req)
            .send()
            .await?
            .error_for_status()?;
        let assoc_id = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|l| l.rsplit('/').next())
            .unwrap_or_default()
            .to_string();
        let policy = resp.json().await?;
        Ok(AmPolicyCreated { assoc_id, policy })
    }

    /// Delete an AM policy association (best-effort at deregistration).
    pub async fn delete(&self, assoc_id: &str) -> Result<(), SbiError> {
        self.http
            .post(format!("{}/npcf-am-policy-control/v1/policies/{assoc_id}/delete", self.base))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn serve() -> (AmPcfState, AmPolicyClient) {
        let state = AmPcfState::new(AmPolicyConfig::demo());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = state.clone();
        tokio::spawn(async move { crate::run_on(listener, router(served)).await.unwrap() });
        (state, AmPolicyClient::new(format!("http://{addr}")))
    }

    #[tokio::test]
    async fn am_policy_association_lifecycle() {
        let (state, client) = serve().await;
        let created = client
            .create(&PolicyAssociationRequest {
                supi: "imsi-999700000000001".into(),
                serving_plmn: Some("99970".into()),
            })
            .await
            .expect("create AM policy");
        assert_eq!(state.association_count(), 1);
        assert_eq!(created.policy.rfsp, Some(3));
        let ambr = created.policy.ue_ambr.as_ref().expect("policy UE-AMBR");
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("500 Mbps", "1 Gbps"));

        client.delete(&created.assoc_id).await.expect("delete AM policy");
        assert_eq!(state.association_count(), 0);
        // Deleting an unknown association is an error (404).
        assert!(client.delete("999").await.is_err());
    }

    /// The PCF sources AM policy per-subscriber from the UDR (Nudr am-policy-data),
    /// falling back to the local config for a subscriber with none provisioned.
    #[tokio::test]
    async fn am_policy_sourced_from_udr() {
        use subscriber_db::SubscriberStore;

        // In-process UDR with one subscriber's am-policy-data (distinct from the demo).
        let store: Arc<dyn SubscriberStore> = Arc::new(subscriber_db::InMemoryStore::new());
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, crate::nudr::router(store)).await.unwrap() });
        let udr = Arc::new(UdrClient::new(format!("http://{udr_addr}")));
        udr.put_am_policy_data(
            "imsi-1",
            &serde_json::json!({ "rfsp": 7, "ueAmbr": { "uplink": "100 Mbps", "downlink": "200 Mbps" } }),
        )
        .await
        .unwrap();

        // PCF backed by that UDR; its local demo config is the fallback.
        let state = AmPcfState::new(AmPolicyConfig::demo()).with_udr(udr);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = state.clone();
        tokio::spawn(async move { crate::run_on(listener, router(served)).await.unwrap() });
        let client = AmPolicyClient::new(format!("http://{addr}"));

        // The provisioned subscriber gets the UDR policy.
        let got = client
            .create(&PolicyAssociationRequest { supi: "imsi-1".into(), serving_plmn: None })
            .await
            .unwrap();
        assert_eq!(got.policy.rfsp, Some(7));
        assert_eq!(got.policy.ue_ambr.as_ref().unwrap().downlink, "200 Mbps");

        // An unprovisioned subscriber falls back to the local demo (RFSP 3).
        let fallback = client
            .create(&PolicyAssociationRequest { supi: "imsi-unknown".into(), serving_plmn: None })
            .await
            .unwrap();
        assert_eq!(fallback.policy.rfsp, Some(3));
    }
}
