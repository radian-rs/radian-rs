//! Npcf_SMPolicyControl — the PCF's session-management policy service (TS 29.512),
//! trimmed. On PDU session establishment the SMF creates an **SM policy
//! association**; the PCF returns an [`SmPolicyDecision`] — the authorized
//! session AMBR and the **QoS flows** (the dynamic PCC-rule QoS that
//! [`design/45`] noted "comes from the PCF"). On release the SMF deletes it.
//!
//! The policy shapes ([`QosFlowPolicy`], [`SessionAmbrPolicy`]) are shared with
//! the SMF, so a PCF decision drops straight into the CreateSMContext response.
//!
//! Policy source: a **local default policy** ([`PolicyConfig`]) keyed by DNN
//! (config in production; here one demo default). Real PCFs also read policy from
//! the UDR (`Nudr` policy-data) and apply operator/PCC rules — a later slice.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::SbiError;
use crate::nudr::UdrClient;

/// A GBR flow's rates (TS 29.571 BitRate strings).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GbrPolicy {
    pub gfbr_dl: String,
    pub gfbr_ul: String,
    pub mfbr_dl: String,
    pub mfbr_ul: String,
}

/// One authorized QoS flow — the shared policy shape carried PCF → SMF → AMF
/// (and, when there's no PCF, still built by the SMF from sm-data).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowPolicy {
    pub qfi: u8,
    pub five_qi: u8,
    #[serde(default = "default_arp_priority")]
    pub arp_priority: u8,
    #[serde(default)]
    pub pre_empt_cap: bool,
    #[serde(default)]
    pub pre_empt_vuln: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gbr: Option<GbrPolicy>,
}

fn default_arp_priority() -> u8 {
    8
}

/// A session's aggregate maximum bit rate (TS 29.571 BitRate strings).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAmbrPolicy {
    pub uplink: String,
    pub downlink: String,
}

/// Parse a TS 29.571 BitRate string (`"<value> <unit>"`, e.g. `"100 Mbps"`) to
/// bits per second. `None` on a malformed value/unit.
pub fn bitrate_to_bps(s: &str) -> Option<u64> {
    let (value, unit) = s.trim().split_once(' ')?;
    let value: u64 = value.parse().ok()?;
    let mult: u64 = match unit {
        "bps" => 1,
        "Kbps" => 1_000,
        "Mbps" => 1_000_000,
        "Gbps" => 1_000_000_000,
        "Tbps" => 1_000_000_000_000,
        _ => return None,
    };
    value.checked_mul(mult)
}

impl SessionAmbrPolicy {
    /// The `(uplink_bps, downlink_bps)` this AMBR represents, if both parse.
    pub fn to_bps(&self) -> Option<(u64, u64)> {
        Some((bitrate_to_bps(&self.uplink)?, bitrate_to_bps(&self.downlink)?))
    }
}

/// `SmPolicyContextData` (TS 29.512 §5.6.2.2), trimmed — what the SMF tells the
/// PCF about the session it wants a policy for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyContextData {
    pub supi: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snssai_sst: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snssai_sd: Option<String>,
}

/// `SmPolicyDecision` (TS 29.512 §5.6.2.5), trimmed to the session AMBR and the
/// authorized QoS flows the SMF acts on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyDecision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ambr: Option<SessionAmbrPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub qos_flows: Vec<QosFlowPolicy>,
}

/// `SmPolicyUpdateContextData` (TS 29.512 §5.6.2.4), trimmed — the SMF's update
/// request. The met policy-control request triggers are advisory here (the PCF
/// always re-evaluates the current policy); kept for wire shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyUpdateContextData {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rep_policy_ctrl_req_triggers: Vec<String>,
}

/// A policy decision per DNN, with a network-wide default. Used two ways: as the
/// PCF's built-in local fallback ([`PolicyConfig::demo`]), and as the shape of the
/// **UDR SM policy-data document** (TS 29.519) — a provisioned doc deserializes
/// straight into this, so per-subscriber policy is just a stored `PolicyConfig`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfig {
    #[serde(default)]
    per_dnn: HashMap<String, SmPolicyDecision>,
    default: SmPolicyDecision,
}

impl PolicyConfig {
    /// The demo policy: 1/2 Gbps session AMBR, a default non-GBR flow (5QI 9) and
    /// a GBR flow (5QI 1, GFBR 100 Mbps / MFBR 200 Mbps) — for any DNN.
    pub fn demo() -> Self {
        let decision = SmPolicyDecision {
            session_ambr: Some(SessionAmbrPolicy {
                uplink: "1 Gbps".into(),
                downlink: "2 Gbps".into(),
            }),
            qos_flows: vec![
                QosFlowPolicy {
                    qfi: 1,
                    five_qi: 9,
                    arp_priority: 8,
                    pre_empt_cap: false,
                    pre_empt_vuln: false,
                    gbr: None,
                },
                QosFlowPolicy {
                    qfi: 2,
                    five_qi: 1,
                    arp_priority: 5,
                    pre_empt_cap: true,
                    pre_empt_vuln: false,
                    gbr: Some(GbrPolicy {
                        gfbr_dl: "100 Mbps".into(),
                        gfbr_ul: "100 Mbps".into(),
                        mfbr_dl: "200 Mbps".into(),
                        mfbr_ul: "200 Mbps".into(),
                    }),
                },
            ],
        };
        Self { per_dnn: HashMap::new(), default: decision }
    }

    /// Override the policy for a specific DNN (config for a real deployment).
    pub fn with_dnn(mut self, dnn: impl Into<String>, decision: SmPolicyDecision) -> Self {
        self.per_dnn.insert(dnn.into(), decision);
        self
    }

    /// The decision for a DNN (the per-DNN override, else the default).
    pub fn decide(&self, dnn: &str) -> SmPolicyDecision {
        self.per_dnn.get(dnn).cloned().unwrap_or_else(|| self.default.clone())
    }
}

/// PCF runtime: the policy source (UDR when configured, else the local config) +
/// in-memory SM policy associations.
#[derive(Clone)]
pub struct PcfState {
    /// Local fallback policy, used per-subscriber when the UDR has no policy-data
    /// (or no UDR is configured).
    config: PolicyConfig,
    /// UDR client (configured base, token-bearing when a secret is set) — the
    /// authoritative policy source (Nudr policy-data). `None` ⇒ local config only.
    udr: Option<Arc<UdrClient>>,
    /// SM policy id → (creating context, current decision), for update/delete/audit.
    associations: Arc<Mutex<HashMap<String, (SmPolicyContextData, SmPolicyDecision)>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl PcfState {
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            udr: None,
            associations: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Source policy from the UDR (Nudr policy-data), per subscriber, falling back
    /// to the local config when a subscriber has no provisioned policy-data.
    pub fn with_udr(mut self, udr: Arc<UdrClient>) -> Self {
        self.udr = Some(udr);
        self
    }

    pub fn association_count(&self) -> usize {
        self.associations.lock().unwrap().len()
    }

    /// The policy decision for a session context: the subscriber's UDR SM
    /// policy-data when provisioned, else the local config. Re-read on every
    /// call, so an Update reflects a mid-session UDR policy change.
    async fn decide_for(&self, ctx: &SmPolicyContextData) -> SmPolicyDecision {
        if let Some(udr) = &self.udr {
            match udr.get_sm_policy_data(&ctx.supi).await {
                Ok(Some(doc)) => match serde_json::from_value::<PolicyConfig>(doc) {
                    Ok(cfg) => return cfg.decide(&ctx.dnn),
                    Err(e) => tracing::warn!(
                        supi = %ctx.supi,
                        "UDR SM policy-data malformed ({e}); using local policy"
                    ),
                },
                Ok(None) => tracing::debug!(
                    supi = %ctx.supi,
                    "no UDR SM policy-data; using local policy"
                ),
                Err(e) => {
                    tracing::warn!("UDR SM policy-data fetch failed ({e}); using local policy")
                }
            }
        }
        self.config.decide(&ctx.dnn)
    }
}

/// Build the PCF router (Npcf_SMPolicyControl).
pub fn router(state: PcfState) -> Router {
    Router::new()
        .route("/npcf-smpolicycontrol/v1/sm-policies", post(create_sm_policy))
        .route("/npcf-smpolicycontrol/v1/sm-policies/{policy_id}/update", post(update_sm_policy))
        .route("/npcf-smpolicycontrol/v1/sm-policies/{policy_id}/delete", post(delete_sm_policy))
        .with_state(state)
}

/// `Npcf_SMPolicyControl_Create` — create the association and return the policy
/// decision. The SM policy id is echoed in the `Location` header (TS 29.512).
async fn create_sm_policy(
    State(pcf): State<PcfState>,
    Json(ctx): Json<SmPolicyContextData>,
) -> impl axum::response::IntoResponse {
    let decision = pcf.decide_for(&ctx).await;
    let id = pcf.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_string();
    tracing::info!(
        supi = %ctx.supi,
        pdu_session_id = ctx.pdu_session_id,
        dnn = %ctx.dnn,
        flows = decision.qos_flows.len(),
        "created SM policy association {id}"
    );
    pcf.associations.lock().unwrap().insert(id.clone(), (ctx, decision.clone()));
    let location = format!("/npcf-smpolicycontrol/v1/sm-policies/{id}");
    (StatusCode::CREATED, [(axum::http::header::LOCATION, location)], Json(decision))
}

/// `Npcf_SMPolicyControl_Update` (TS 29.512 §5.6.2.4) — re-authorize an existing
/// association against the *current* policy (re-reading the subscriber's UDR
/// policy-data), so a mid-session policy change is reflected. Returns the updated
/// decision; `404` for an unknown SM policy id.
async fn update_sm_policy(
    State(pcf): State<PcfState>,
    Path(policy_id): Path<String>,
    Json(_upd): Json<SmPolicyUpdateContextData>,
) -> Result<Json<SmPolicyDecision>, StatusCode> {
    let ctx = match pcf.associations.lock().unwrap().get(&policy_id) {
        Some((ctx, _)) => ctx.clone(),
        None => return Err(StatusCode::NOT_FOUND),
    };
    let decision = pcf.decide_for(&ctx).await;
    tracing::info!(
        %policy_id,
        flows = decision.qos_flows.len(),
        "updated SM policy association"
    );
    // Store the fresh decision (skip if the association was deleted meanwhile).
    if let Some(entry) = pcf.associations.lock().unwrap().get_mut(&policy_id) {
        entry.1 = decision.clone();
    }
    Ok(Json(decision))
}

/// `Npcf_SMPolicyControl_Delete`.
async fn delete_sm_policy(State(pcf): State<PcfState>, Path(policy_id): Path<String>) -> StatusCode {
    if pcf.associations.lock().unwrap().remove(&policy_id).is_some() {
        tracing::info!("deleted SM policy association {policy_id}");
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// The SMF's SM policy created at the PCF: the association id + the decision.
pub struct SmPolicyCreated {
    pub policy_id: String,
    pub decision: SmPolicyDecision,
}

/// Client the SMF uses to reach the PCF's Npcf_SMPolicyControl over h2c.
pub struct PcfClient {
    base: String,
    http: reqwest::Client,
}

impl PcfClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into(), http: crate::h2c_client() }
    }

    /// Create an SM policy association; returns the id (from `Location`) + decision.
    pub async fn create_sm_policy(
        &self,
        ctx: &SmPolicyContextData,
    ) -> Result<SmPolicyCreated, SbiError> {
        let resp = self
            .http
            .post(format!("{}/npcf-smpolicycontrol/v1/sm-policies", self.base))
            .json(ctx)
            .send()
            .await?
            .error_for_status()?;
        let policy_id = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|loc| loc.rsplit('/').next())
            .unwrap_or_default()
            .to_string();
        let decision = resp.json().await?;
        Ok(SmPolicyCreated { policy_id, decision })
    }

    /// Update (re-authorize) an SM policy association; returns the fresh decision.
    pub async fn update_sm_policy(
        &self,
        policy_id: &str,
        upd: &SmPolicyUpdateContextData,
    ) -> Result<SmPolicyDecision, SbiError> {
        let decision = self
            .http
            .post(format!(
                "{}/npcf-smpolicycontrol/v1/sm-policies/{}/update",
                self.base, policy_id
            ))
            .json(upd)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(decision)
    }

    /// Delete an SM policy association.
    pub async fn delete_sm_policy(&self, policy_id: &str) -> Result<(), SbiError> {
        self.http
            .post(format!(
                "{}/npcf-smpolicycontrol/v1/sm-policies/{}/delete",
                self.base, policy_id
            ))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_then_delete_sm_policy_over_h2c() {
        let state = PcfState::new(PolicyConfig::demo());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pcf_state = state.clone();
        tokio::spawn(async move { crate::run_on(listener, router(pcf_state)).await.unwrap() });
        let pcf = PcfClient::new(format!("http://{addr}"));

        let ctx = SmPolicyContextData {
            supi: "imsi-1".into(),
            pdu_session_id: 5,
            dnn: "internet".into(),
            snssai_sst: Some(1),
            snssai_sd: Some("010203".into()),
        };
        let created = pcf.create_sm_policy(&ctx).await.expect("policy created");
        assert!(!created.policy_id.is_empty(), "an SM policy id was assigned");
        // The demo decision: 1/2 Gbps AMBR + default (5QI 9) + GBR (5QI 1) flows.
        let ambr = created.decision.session_ambr.as_ref().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("1 Gbps", "2 Gbps"));
        assert_eq!(created.decision.qos_flows.len(), 2);
        assert_eq!((created.decision.qos_flows[0].qfi, created.decision.qos_flows[0].five_qi), (1, 9));
        assert!(created.decision.qos_flows[1].gbr.is_some(), "second flow is GBR");
        assert_eq!(state.association_count(), 1);

        pcf.delete_sm_policy(&created.policy_id).await.expect("deleted");
        assert_eq!(state.association_count(), 0, "association removed");
    }

    #[test]
    fn per_dnn_override_wins_over_default() {
        let ims = SmPolicyDecision {
            session_ambr: Some(SessionAmbrPolicy { uplink: "5 Mbps".into(), downlink: "5 Mbps".into() }),
            qos_flows: vec![QosFlowPolicy {
                qfi: 3,
                five_qi: 5,
                arp_priority: 1,
                pre_empt_cap: true,
                pre_empt_vuln: false,
                gbr: None,
            }],
        };
        let config = PolicyConfig::demo().with_dnn("ims", ims);
        // The override applies to its DNN...
        let d = config.decide("ims");
        assert_eq!(d.qos_flows.len(), 1);
        assert_eq!(d.qos_flows[0].five_qi, 5);
        // ...every other DNN gets the default (two flows incl. a GBR one).
        let d = config.decide("internet");
        assert_eq!(d.qos_flows.len(), 2);
        assert!(d.qos_flows.iter().any(|f| f.gbr.is_some()));
    }

    #[tokio::test]
    async fn pcf_sources_policy_from_udr_and_update_reflects_changes() {
        use subscriber_db::SubscriberStore;

        // In-process UDR.
        let store: Arc<dyn SubscriberStore> = Arc::new(subscriber_db::InMemoryStore::new());
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(udr_l, crate::nudr::router(store)).await.unwrap() });
        let udr = Arc::new(UdrClient::new(format!("http://{udr_addr}")));

        // Provision the subscriber's SM policy-data (distinct from the local demo).
        let v1 = serde_json::json!({
            "default": {
                "sessionAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" },
                "qosFlows": [ { "qfi": 1, "fiveQi": 9 } ]
            }
        });
        udr.put_sm_policy_data("imsi-1", &v1).await.unwrap();

        // PCF backed by that UDR (its local demo config is the fallback, unused here).
        let pcf_state = PcfState::new(PolicyConfig::demo()).with_udr(udr.clone());
        let pcf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pcf_addr = pcf_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(pcf_l, router(pcf_state)).await.unwrap() });
        let pcf = PcfClient::new(format!("http://{pcf_addr}"));

        let ctx = SmPolicyContextData {
            supi: "imsi-1".into(),
            pdu_session_id: 1,
            dnn: "internet".into(),
            snssai_sst: Some(1),
            snssai_sd: None,
        };
        // The UDR policy-data — not the local demo (1/2 Gbps) — drove the decision.
        let created = pcf.create_sm_policy(&ctx).await.unwrap();
        let ambr = created.decision.session_ambr.as_ref().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("200 Mbps", "400 Mbps"));
        assert_eq!(created.decision.qos_flows.len(), 1);

        // Mid-session change: reprovision the UDR, then Update re-reads it.
        let v2 = serde_json::json!({
            "default": {
                "sessionAmbr": { "uplink": "50 Mbps", "downlink": "100 Mbps" },
                "qosFlows": [
                    { "qfi": 1, "fiveQi": 9 },
                    { "qfi": 2, "fiveQi": 1, "gbr": {
                        "gfbrDl": "10 Mbps", "gfbrUl": "10 Mbps",
                        "mfbrDl": "20 Mbps", "mfbrUl": "20 Mbps" } }
                ]
            }
        });
        udr.put_sm_policy_data("imsi-1", &v2).await.unwrap();
        let updated = pcf
            .update_sm_policy(&created.policy_id, &SmPolicyUpdateContextData::default())
            .await
            .unwrap();
        let ambr = updated.session_ambr.as_ref().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("50 Mbps", "100 Mbps"));
        assert_eq!(updated.qos_flows.len(), 2, "the mid-session change added a GBR flow");

        // Updating an unknown association → error (404).
        assert!(
            pcf.update_sm_policy("nope", &SmPolicyUpdateContextData::default()).await.is_err()
        );
    }
}
