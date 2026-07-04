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
use crate::policy::{FieldUpdate, de_field_update, ser_field_update};

/// A GBR flow's rates (TS 29.571 BitRate strings).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GbrPolicy {
    pub gfbr_dl: String,
    pub gfbr_ul: String,
    pub mfbr_dl: String,
    pub mfbr_ul: String,
}

/// A packet classifier for a QoS flow (a compact SDF filter): transport protocol +
/// a port range. The SMF installs it as the UPF's per-flow classifier so GBR
/// traffic is matched to the flow and policed against its MFBR.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PacketFilterPolicy {
    pub protocol: u8,
    pub port_low: u16,
    pub port_high: u16,
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
    /// The flow's packet classifier — present on GBR flows so the UPF can steer
    /// matching traffic to this flow and enforce its MFBR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<PacketFilterPolicy>,
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

/// A **partial** SM policy decision — the Npcf_SMPolicyControl Update response is a
/// delta, not a full replacement (TS 29.512 §5.6.2.5): the session AMBR as a
/// three-way [`FieldUpdate`], and the QoS flows keyed by QFI where a present flow is
/// installed/modified and a `null` one removed (a QFI absent from the map is kept).
/// Built by [`SmPolicyDecision::diff`], merged by [`SmPolicyDecision::apply`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyUpdate {
    #[serde(
        default,
        skip_serializing_if = "FieldUpdate::is_keep",
        serialize_with = "ser_field_update",
        deserialize_with = "de_field_update"
    )]
    pub session_ambr: FieldUpdate<SessionAmbrPolicy>,
    /// QFI → `Some(flow)` to install/modify, `null` to remove; QFIs absent from the
    /// map are kept unchanged.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub qos_flows: HashMap<u8, Option<QosFlowPolicy>>,
}

impl SmPolicyDecision {
    /// The partial Update delta from `self` (the previous decision) to `next`: the
    /// session AMBR as a `FieldUpdate`, plus per-QFI flow changes — a new or changed
    /// flow as `Some`, a removed one as `None` (JSON `null`); unchanged flows omitted.
    /// `None` when nothing changed.
    pub fn diff(&self, next: &SmPolicyDecision) -> Option<SmPolicyUpdate> {
        let session_ambr = FieldUpdate::diff(&self.session_ambr, &next.session_ambr);
        let mut qos_flows = HashMap::new();
        // New or changed flows → install (Some); unchanged QFIs omitted.
        for nf in &next.qos_flows {
            if self.qos_flows.iter().find(|of| of.qfi == nf.qfi) != Some(nf) {
                qos_flows.insert(nf.qfi, Some(nf.clone()));
            }
        }
        // Flows gone from `next` → remove (None / null).
        for of in &self.qos_flows {
            if !next.qos_flows.iter().any(|nf| nf.qfi == of.qfi) {
                qos_flows.insert(of.qfi, None);
            }
        }
        (!session_ambr.is_keep() || !qos_flows.is_empty())
            .then_some(SmPolicyUpdate { session_ambr, qos_flows })
    }

    /// Merge a partial Update onto this decision: set/clear the session AMBR, and for
    /// each QFI in the delta install/replace (`Some`) or remove (`None`) the flow;
    /// flows the delta doesn't mention are kept. Flows stay QFI-ordered.
    pub fn apply(&mut self, update: &SmPolicyUpdate) {
        self.session_ambr = update.session_ambr.clone().apply(self.session_ambr.take());
        for (qfi, change) in &update.qos_flows {
            self.qos_flows.retain(|f| f.qfi != *qfi);
            if let Some(flow) = change {
                self.qos_flows.push(flow.clone());
            }
        }
        self.qos_flows.sort_by_key(|f| f.qfi);
    }
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
                    filter: None,
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
                    // Conversational-voice-style classifier: UDP on ports 5000–5010.
                    filter: Some(PacketFilterPolicy { protocol: 17, port_low: 5000, port_high: 5010 }),
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
) -> Result<Json<SmPolicyUpdate>, StatusCode> {
    let (ctx, prev) = match pcf.associations.lock().unwrap().get(&policy_id) {
        Some((ctx, prev)) => (ctx.clone(), prev.clone()),
        None => return Err(StatusCode::NOT_FOUND),
    };
    let fresh = pcf.decide_for(&ctx).await;
    // Notify a **partial** delta — only what changed since the last decision, a
    // removed flow as JSON `null` (TS 29.512). The SMF merges it onto its stored
    // policy rather than treating the response as a full replacement.
    let delta = prev.diff(&fresh).unwrap_or_default();
    tracing::info!(
        %policy_id,
        flows = fresh.qos_flows.len(),
        flow_changes = delta.qos_flows.len(),
        "updated SM policy association (partial)"
    );
    // Store the fresh full decision (skip if the association was deleted meanwhile).
    if let Some(entry) = pcf.associations.lock().unwrap().get_mut(&policy_id) {
        entry.1 = fresh;
    }
    Ok(Json(delta))
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
        Self { base: base.into(), http: crate::sbi_client() }
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

    /// Update (re-authorize) an SM policy association; returns the **partial** delta
    /// (only what changed) to merge onto the SMF's stored decision.
    pub async fn update_sm_policy(
        &self,
        policy_id: &str,
        upd: &SmPolicyUpdateContextData,
    ) -> Result<SmPolicyUpdate, SbiError> {
        let update = self
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
        Ok(update)
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
                filter: None,
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
        let update = pcf
            .update_sm_policy(&created.policy_id, &SmPolicyUpdateContextData::default())
            .await
            .unwrap();
        // A PARTIAL delta: the session AMBR changed (Set) and only QFI 2 was added;
        // the unchanged QFI 1 is omitted (kept), not restated.
        let FieldUpdate::Set(ambr) = &update.session_ambr else { panic!("AMBR changed → Set") };
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("50 Mbps", "100 Mbps"));
        assert_eq!(update.qos_flows.len(), 1, "only the added GBR flow is in the delta");
        assert!(update.qos_flows.get(&2).unwrap().is_some(), "QFI 2 installed");
        assert!(!update.qos_flows.contains_key(&1), "unchanged QFI 1 omitted (kept)");

        // Merging the delta onto the previous decision recovers the full v2 policy.
        let mut merged = created.decision.clone();
        merged.apply(&update);
        assert_eq!(merged.qos_flows.len(), 2, "merge keeps QFI 1 and installs QFI 2");
        assert_eq!(merged.session_ambr.as_ref().unwrap().downlink, "100 Mbps");

        // Updating an unknown association → error (404).
        assert!(
            pcf.update_sm_policy("nope", &SmPolicyUpdateContextData::default()).await.is_err()
        );
    }

    /// The partial SM Update delta (TS 29.512): `diff` emits only the attributes that
    /// changed — a new/changed flow as a value, a removed flow as JSON `null`, an
    /// unchanged flow omitted; `apply` merges the delta back, keeping omitted flows.
    #[test]
    fn sm_policy_partial_diff_and_apply() {
        let flow = |qfi, five_qi| QosFlowPolicy {
            qfi,
            five_qi,
            arp_priority: 8,
            pre_empt_cap: false,
            pre_empt_vuln: false,
            gbr: None,
            filter: None,
        };
        let prev = SmPolicyDecision {
            session_ambr: Some(SessionAmbrPolicy { uplink: "1 Gbps".into(), downlink: "2 Gbps".into() }),
            qos_flows: vec![flow(1, 9), flow(2, 1)],
        };
        // Next: AMBR unchanged, QFI 1 re-rated (5QI 9→6), QFI 2 removed, QFI 3 added.
        let next = SmPolicyDecision {
            session_ambr: prev.session_ambr.clone(),
            qos_flows: vec![flow(1, 6), flow(3, 5)],
        };
        let delta = prev.diff(&next).expect("something changed");
        assert_eq!(delta.session_ambr, FieldUpdate::Keep, "AMBR unchanged → omitted");
        assert_eq!(delta.qos_flows.len(), 3, "QFI 1 (changed), 2 (removed), 3 (added)");
        assert_eq!(delta.qos_flows.get(&1).unwrap().as_ref().unwrap().five_qi, 6, "QFI 1 re-rated");
        assert_eq!(*delta.qos_flows.get(&2).unwrap(), None, "QFI 2 removed → null");
        assert!(delta.qos_flows.get(&3).unwrap().is_some(), "QFI 3 added");

        // On the wire the removal is a JSON null; the unchanged AMBR is absent.
        let wire = serde_json::to_value(&delta).unwrap();
        assert!(wire.get("sessionAmbr").is_none(), "unchanged AMBR omitted");
        assert!(wire.pointer("/qosFlows/2").unwrap().is_null(), "removed flow is null");

        // apply merges the delta onto prev → exactly next (QFI-ordered).
        let mut merged = prev.clone();
        merged.apply(&delta);
        assert_eq!(merged, next, "merge reconstructs the next decision");

        // A no-op update (prev vs prev) → no delta.
        assert_eq!(prev.diff(&prev.clone()), None);
        // Clearing the AMBR is a Clear, not a Keep.
        let cleared = SmPolicyDecision { session_ambr: None, qos_flows: prev.qos_flows.clone() };
        assert_eq!(prev.diff(&cleared).unwrap().session_ambr, FieldUpdate::Clear);
    }
}
