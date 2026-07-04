//! Npcf_AMPolicyControl — the PCF's **access-and-mobility** policy service
//! (TS 29.507). Complements Npcf_SMPolicyControl ([`crate::npcf`], the session
//! side): the AMF creates an **AM policy association** at registration and the PCF
//! returns AM policy data — here the **RFSP** index (RAT/Frequency Selection
//! Priority) and a policy **UE-AMBR** the AMF enforces at the gNB. Deleted at
//! deregistration.
//!
//! Policy is sourced per-subscriber from the UDR (Nudr am-policy-data) when a UDR
//! client is configured ([`AmPcfState::with_udr`]), falling back to a local
//! [`AmPolicyConfig`]. An `Npcf_AMPolicyControl_UpdateNotify` trigger re-evaluates
//! an association and pushes a changed policy to the AMF.

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ambr {
    pub uplink: String,
    pub downlink: String,
}

/// A service area restriction (TS 29.571 `ServiceAreaRestriction`) — the tracking
/// areas the UE is allowed (or forbidden) to be served in. `restriction_type` is
/// `ALLOWED_AREAS` or `NOT_ALLOWED_AREAS`; `tacs` are hex TAC strings ("000001").
/// The AMF signals this to the RAN as an NGAP Mobility Restriction List.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAreaRestriction {
    pub restriction_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tacs: Vec<String>,
}

/// `PolicyAssociationRequest` (TS 29.507 §5.6.2.2), trimmed — what the AMF tells
/// the PCF when creating the association.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAssociationRequest {
    pub supi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving_plmn: Option<String>,
    /// The AMF's callback URI for `Npcf_AMPolicyControl_UpdateNotify` — where the
    /// PCF pushes a mid-registration AM policy change (TS 29.507 §5.6.2.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_uri: Option<String>,
}

/// `PolicyAssociation` (TS 29.507 §5.6.2.4) — the AM policy the PCF returns.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAssociation {
    /// RAT/Frequency Selection Priority index (TS 23.501 §5.3.4.3) — RAN steering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfsp: Option<u16>,
    /// The UE-AMBR the AMF enforces at the gNB (policy override of the subscribed one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue_ambr: Option<Ambr>,
    /// The UE's service area restriction (TS 29.507 `servAreaRes`) — signalled to the
    /// RAN as a Mobility Restriction List.
    #[serde(rename = "servAreaRes", default, skip_serializing_if = "Option::is_none")]
    pub serv_area_res: Option<ServiceAreaRestriction>,
    /// Policy control request triggers (informational here).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggers: Vec<String>,
}

/// The partial-update primitive, shared with the SM policy side ([`crate::npcf`]).
/// Re-exported so `sbi_core::npcf_am::FieldUpdate` keeps resolving.
pub use crate::policy::FieldUpdate;
use crate::policy::{de_field_update, ser_field_update};

/// `PolicyUpdate` (TS 29.507 §5.6.2) — the **partial** body of an
/// `Npcf_AMPolicyControl_UpdateNotify`. Each attribute is a [`FieldUpdate`]: omitted
/// means the AMF keeps its current value, `null` removes it, a value sets it. Built
/// by [`PolicyAssociation::diff`] from the previous and fresh decisions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyUpdate {
    #[serde(
        default,
        skip_serializing_if = "FieldUpdate::is_keep",
        serialize_with = "ser_field_update",
        deserialize_with = "de_field_update"
    )]
    pub rfsp: FieldUpdate<u16>,
    #[serde(
        default,
        skip_serializing_if = "FieldUpdate::is_keep",
        serialize_with = "ser_field_update",
        deserialize_with = "de_field_update"
    )]
    pub ue_ambr: FieldUpdate<Ambr>,
    #[serde(
        rename = "servAreaRes",
        default,
        skip_serializing_if = "FieldUpdate::is_keep",
        serialize_with = "ser_field_update",
        deserialize_with = "de_field_update"
    )]
    pub serv_area_res: FieldUpdate<ServiceAreaRestriction>,
}

impl PolicyAssociation {
    /// The partial UpdateNotify that carries `self` (the previous decision) to `next`:
    /// each attribute that changed is present (a new value → `Set`, a removed value →
    /// `Clear`/JSON `null`); unchanged attributes are omitted so the AMF keeps them.
    /// `None` when nothing relevant changed (the PCF then notifies nothing).
    pub fn diff(&self, next: &PolicyAssociation) -> Option<PolicyUpdate> {
        let update = PolicyUpdate {
            rfsp: FieldUpdate::diff(&self.rfsp, &next.rfsp),
            ue_ambr: FieldUpdate::diff(&self.ue_ambr, &next.ue_ambr),
            serv_area_res: FieldUpdate::diff(&self.serv_area_res, &next.serv_area_res),
        };
        (update != PolicyUpdate::default()).then_some(update)
    }
}

/// Local AM policy configuration — the decision the PCF returns for an association.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfsp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue_ambr: Option<Ambr>,
    #[serde(rename = "servAreaRes", default, skip_serializing_if = "Option::is_none")]
    pub serv_area_res: Option<ServiceAreaRestriction>,
}

impl AmPolicyConfig {
    /// A demo AM policy: an RFSP index + a policy UE-AMBR (tighter than the
    /// subscribed 1/2 Gbps, so the override is observable end to end) + a service
    /// area restriction allowing only the serving tracking area (TAC 000001).
    pub fn demo() -> Self {
        Self {
            rfsp: Some(3),
            ue_ambr: Some(Ambr { uplink: "500 Mbps".into(), downlink: "1 Gbps".into() }),
            serv_area_res: Some(ServiceAreaRestriction {
                restriction_type: "ALLOWED_AREAS".into(),
                tacs: vec!["000001".into()],
            }),
        }
    }

    fn decide(&self) -> PolicyAssociation {
        PolicyAssociation {
            rfsp: self.rfsp,
            ue_ambr: self.ue_ambr.clone(),
            serv_area_res: self.serv_area_res.clone(),
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
    /// association id → (creating request, current decision). The decision lets an
    /// Update re-evaluate and notify the AMF only when the policy actually changed.
    associations: Arc<Mutex<HashMap<String, (PolicyAssociationRequest, PolicyAssociation)>>>,
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

/// The Npcf_AMPolicyControl router (create / update / delete). Merge with the SM
/// router.
pub fn router(state: AmPcfState) -> Router {
    Router::new()
        .route("/npcf-am-policy-control/v1/policies", post(create))
        .route("/npcf-am-policy-control/v1/policies/{id}/update", post(update))
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
    pcf.associations.lock().unwrap().insert(id.clone(), (req, decision.clone()));
    let location = format!("/npcf-am-policy-control/v1/policies/{id}");
    (StatusCode::CREATED, [(axum::http::header::LOCATION, location)], Json(decision))
}

/// Re-evaluate an association against the *current* AM policy (re-reading the UDR)
/// and, when it changed, push **`Npcf_AMPolicyControl_UpdateNotify`** to the AMF's
/// notification URI. A trigger for a mid-registration AM policy change (an OAM /
/// operator edit of the subscriber's UDR am-policy-data). Returns the fresh policy
/// (`200`), `204` when unchanged, `404` for an unknown association.
async fn update(State(pcf): State<AmPcfState>, Path(id): Path<String>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some((req, prev)) = pcf.associations.lock().unwrap().get(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let fresh = pcf.decide_for(&req.supi).await;
    if fresh == prev {
        return StatusCode::NO_CONTENT.into_response();
    }
    // Store the new decision (skip if the association was deleted meanwhile).
    if let Some(entry) = pcf.associations.lock().unwrap().get_mut(&id) {
        entry.1 = fresh.clone();
    }
    // Notify the AMF with a **partial** delta — only the attributes that changed,
    // a removed one carried as JSON `null` (TS 29.507 partial UpdateNotify). The AMF
    // keeps any attribute the delta omits rather than treating absence as removal.
    if let (Some(uri), Some(delta)) = (&req.notification_uri, prev.diff(&fresh)) {
        tracing::info!(supi = %req.supi, assoc = %id, "AM policy changed — notifying the AMF (UpdateNotify, partial)");
        if let Err(e) = crate::sbi_client().post(uri).json(&delta).send().await {
            tracing::warn!("Npcf_AMPolicyControl_UpdateNotify failed: {e}");
        }
    }
    (StatusCode::OK, Json(fresh)).into_response()
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

    /// Trigger a re-evaluation of an association (OAM): the PCF re-reads the UDR and
    /// pushes `Npcf_AMPolicyControl_UpdateNotify` to the AMF if the policy changed.
    /// Returns the fresh policy (`Some`) when it changed, `None` when unchanged.
    pub async fn update(&self, assoc_id: &str) -> Result<Option<PolicyAssociation>, SbiError> {
        let resp = self
            .http
            .post(format!("{}/npcf-am-policy-control/v1/policies/{assoc_id}/update", self.base))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
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
                serving_plmn: Some("99970".into()), notification_uri: None,
            })
            .await
            .expect("create AM policy");
        assert_eq!(state.association_count(), 1);
        assert_eq!(created.policy.rfsp, Some(3));
        let ambr = created.policy.ue_ambr.as_ref().expect("policy UE-AMBR");
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("500 Mbps", "1 Gbps"));
        // The service area restriction survives the h2c round trip (servAreaRes).
        let sar = created.policy.serv_area_res.as_ref().expect("policy servAreaRes");
        assert_eq!(sar.restriction_type, "ALLOWED_AREAS");
        assert_eq!(sar.tacs, ["000001"]);

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
            .create(&PolicyAssociationRequest { supi: "imsi-1".into(), serving_plmn: None, notification_uri: None })
            .await
            .unwrap();
        assert_eq!(got.policy.rfsp, Some(7));
        assert_eq!(got.policy.ue_ambr.as_ref().unwrap().downlink, "200 Mbps");

        // An unprovisioned subscriber falls back to the local demo (RFSP 3).
        let fallback = client
            .create(&PolicyAssociationRequest { supi: "imsi-unknown".into(), serving_plmn: None, notification_uri: None })
            .await
            .unwrap();
        assert_eq!(fallback.policy.rfsp, Some(3));
    }

    /// Npcf_AMPolicyControl_UpdateNotify: after the subscriber's UDR am-policy-data
    /// changes, an Update trigger re-evaluates and pushes the new policy to the AMF's
    /// notification URI; an unchanged Update notifies nothing.
    #[tokio::test]
    async fn update_notifies_the_amf_on_a_policy_change() {
        use std::sync::atomic::{AtomicUsize, Ordering as O};
        use subscriber_db::SubscriberStore;

        // Mock AMF notification surface recording the pushed **partial** updates.
        static NOTIFS: AtomicUsize = AtomicUsize::new(0);
        let last: Arc<Mutex<Option<PolicyUpdate>>> = Arc::new(Mutex::new(None));
        let last_h = last.clone();
        let amf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let amf_addr = amf_l.local_addr().unwrap();
        let amf = axum::Router::new().route(
            "/npcf-am-policy-notify/{supi}",
            post(move |axum::Json(p): axum::Json<PolicyUpdate>| {
                let last = last_h.clone();
                async move {
                    NOTIFS.fetch_add(1, O::Relaxed);
                    *last.lock().unwrap() = Some(p);
                    StatusCode::NO_CONTENT
                }
            }),
        );
        tokio::spawn(async move { crate::run_on(amf_l, amf).await.unwrap() });

        // UDR + PCF, with a subscriber provisioned (RFSP 4).
        let store: Arc<dyn SubscriberStore> = Arc::new(subscriber_db::InMemoryStore::new());
        let store2 = store.clone();
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, crate::nudr::router(store2)).await.unwrap() });
        let udr = Arc::new(UdrClient::new(format!("http://{udr_addr}")));
        udr.put_am_policy_data("imsi-1", &serde_json::json!({ "rfsp": 4 })).await.unwrap();

        let state = AmPcfState::new(AmPolicyConfig::demo()).with_udr(udr.clone());
        let pcf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pcf_addr = pcf_l.local_addr().unwrap();
        let served = state.clone();
        tokio::spawn(async move { crate::run_on(pcf_l, router(served)).await.unwrap() });
        let client = AmPolicyClient::new(format!("http://{pcf_addr}"));

        // Create with the AMF notification URI.
        let created = client
            .create(&PolicyAssociationRequest {
                supi: "imsi-1".into(),
                serving_plmn: None,
                notification_uri: Some(format!("http://{amf_addr}/npcf-am-policy-notify/imsi-1")),
            })
            .await
            .unwrap();
        assert_eq!(created.policy.rfsp, Some(4));

        // Update with no change → 204, no notify.
        assert!(client.update(&created.assoc_id).await.unwrap().is_none());
        assert_eq!(NOTIFS.load(O::Relaxed), 0);

        // The operator edits the UDR am-policy-data, then triggers the Update.
        udr.put_am_policy_data("imsi-1", &serde_json::json!({ "rfsp": 8 })).await.unwrap();
        let fresh = client.update(&created.assoc_id).await.unwrap().expect("policy changed");
        assert_eq!(fresh.rfsp, Some(8));
        // The AMF was notified with the new policy.
        for _ in 0..50 {
            if NOTIFS.load(O::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(NOTIFS.load(O::Relaxed), 1, "AMF notified once on the change");
        // Partial delta: only the changed RFSP is present; the (unset) UE-AMBR and
        // service area are omitted (`Keep`) rather than pushed as removals.
        {
            let got = last.lock().unwrap();
            let upd = got.as_ref().unwrap();
            assert_eq!(upd.rfsp, FieldUpdate::Set(8));
            assert_eq!(upd.ue_ambr, FieldUpdate::Keep, "UE-AMBR omitted, not cleared");
            assert_eq!(upd.serv_area_res, FieldUpdate::Keep, "service area omitted");
        }

        // A service-area-only edit (RFSP unchanged) still counts as a change: the
        // notify fires and the pushed policy carries the new servAreaRes.
        udr.put_am_policy_data(
            "imsi-1",
            &serde_json::json!({
                "rfsp": 8,
                "servAreaRes": { "restrictionType": "ALLOWED_AREAS", "tacs": ["000007"] }
            }),
        )
        .await
        .unwrap();
        let fresh = client.update(&created.assoc_id).await.unwrap().expect("service area changed");
        assert_eq!(fresh.rfsp, Some(8), "RFSP unchanged");
        assert_eq!(fresh.serv_area_res.as_ref().unwrap().tacs, ["000007"]);
        for _ in 0..50 {
            if NOTIFS.load(O::Relaxed) == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(NOTIFS.load(O::Relaxed), 2, "AMF notified again on the service-area change");
        // The RFSP didn't change this round, so it's omitted (`Keep`) — the AMF holds
        // the RFSP it already has; only the new service area rides the delta.
        let got = last.lock().unwrap();
        let upd = got.as_ref().unwrap();
        assert_eq!(upd.rfsp, FieldUpdate::Keep, "RFSP unchanged → omitted from the delta");
        let FieldUpdate::Set(sar) = &upd.serv_area_res else { panic!("service area set") };
        assert_eq!(sar.restriction_type, "ALLOWED_AREAS");
        assert_eq!(sar.tacs, ["000007"]);
    }

    /// The partial UpdateNotify wire format (TS 29.507): an omitted attribute
    /// deserializes to `Keep`, a JSON `null` to `Clear`, a value to `Set`; and
    /// [`PolicyAssociation::diff`] emits exactly the attributes that changed (a
    /// removed one as `null`), omitting the rest.
    #[test]
    fn policy_update_partial_semantics() {
        // Wire → FieldUpdate: absent = Keep, null = Clear, value = Set.
        let parsed: PolicyUpdate =
            serde_json::from_value(serde_json::json!({ "rfsp": 5, "ueAmbr": null })).unwrap();
        assert_eq!(parsed.rfsp, FieldUpdate::Set(5), "value → Set");
        assert_eq!(parsed.ue_ambr, FieldUpdate::Clear, "null → Clear");
        assert_eq!(parsed.serv_area_res, FieldUpdate::Keep, "absent → Keep");
        // apply() resolves each against the AMF's current value.
        assert_eq!(FieldUpdate::Keep.apply(Some(3)), Some(3));
        assert_eq!(FieldUpdate::<u16>::Clear.apply(Some(3)), None);
        assert_eq!(FieldUpdate::Set(9).apply(Some(3)), Some(9));

        // diff: change one attribute, remove another, leave the third.
        let prev = PolicyAssociation {
            rfsp: Some(3),
            ue_ambr: Some(Ambr { uplink: "1 Gbps".into(), downlink: "2 Gbps".into() }),
            serv_area_res: Some(ServiceAreaRestriction {
                restriction_type: "ALLOWED_AREAS".into(),
                tacs: vec!["000001".into()],
            }),
            triggers: Vec::new(),
        };
        let next = PolicyAssociation { rfsp: Some(8), ue_ambr: None, ..prev.clone() };
        let delta = prev.diff(&next).expect("something changed");
        assert_eq!(delta.rfsp, FieldUpdate::Set(8), "RFSP changed → Set");
        assert_eq!(delta.ue_ambr, FieldUpdate::Clear, "UE-AMBR removed → Clear");
        assert_eq!(delta.serv_area_res, FieldUpdate::Keep, "service area unchanged → Keep");
        // On the wire the delta is exactly {rfsp, ueAmbr:null} — the service area is absent.
        let wire = serde_json::to_value(&delta).unwrap();
        assert_eq!(wire, serde_json::json!({ "rfsp": 8, "ueAmbr": null }));

        // No change → nothing to notify.
        assert_eq!(prev.diff(&prev.clone()), None);
    }
}
