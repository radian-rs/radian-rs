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
    /// The **charging data** this flow is metered under (TS 29.512 `PccRule.refChgData`)
    /// — an id into [`SmPolicyDecision::charging_descs`] resolving to its rating group.
    /// `None` ⇒ the flow falls back to the legacy rating-group-equals-QFI convention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_chg_data: Option<String>,
}

fn default_arp_priority() -> u8 {
    8
}

/// `ChargingData` (TS 29.512 §5.6.2.11), trimmed — a charging decision referenced by
/// one or more PCC rules (`refChgData`). Carries the **rating group** the CHF
/// accumulates usage under, decoupling charging identity from the QoS flow / QFI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChargingData {
    /// The rating group (TS 32.255) — the CHF sums usage per group.
    pub rating_group: u32,
    /// Metering method ("DURATION" / "VOLUME" / "DURATION_VOLUME"); informational here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering_method: Option<String>,
    /// Online / offline charging enabled (informational here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline: Option<bool>,
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

/// A **session rule** (TS 29.512 §5.6.2.7), trimmed to the authorized session AMBR —
/// the session-level policy, keyed by rule id in [`SmPolicyDecision::session_rules`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_sess_ambr: Option<SessionAmbrPolicy>,
}

/// `QosData` (TS 29.512 §5.6.2.8), trimmed — the authorized QoS of one **QoS flow**:
/// its **QFI** (the flow identifier the SMF binds PCC rules to), 5QI, ARP, and an
/// optional GBR/MBR rate set. Referenced by a PCC rule's `refQosData`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QosData {
    /// The QoS flow identifier this decision defines — the QFI PCC rules bind to (the
    /// result of SMF QoS-flow binding, TS 23.501 §5.7.1.7).
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

/// A `PccRule` (TS 29.512 §5.6.2.6), trimmed — a policy-and-charging-control rule: its
/// packet filter (`flowInfos`), precedence, and references to the QoS
/// (`refQosData` → [`QosData`]) and charging (`refChgData` → [`ChargingData`])
/// decisions. The SMF **binds** the rule to a QoS flow via `refQosData` (the QFI is a
/// property of the referenced [`QosData`], not the rule).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PccRule {
    #[serde(default)]
    pub precedence: u16,
    /// The rule's packet classifier (`flowInfos`, trimmed to one SDF filter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_info: Option<PacketFilterPolicy>,
    /// The QoS flow this rule binds to (`refQosData` → [`SmPolicyDecision::qos_descs`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_qos_data: Option<String>,
    /// The charging this rule is metered under (`refChgData` → [`SmPolicyDecision::charging_descs`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_chg_data: Option<String>,
}

/// `SmPolicyDecision` (TS 29.512 §5.6.2.5), trimmed to the **session rules** (session
/// AMBR), the **PCC rules** (the authorized flows) with the **QoS** and **charging**
/// decisions they reference — all keyed maps.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyDecision {
    /// Session rules keyed by rule id (TS 29.512 `sessRules`) — the session AMBR lives
    /// here. Use [`Self::session_ambr`] to read the effective AMBR.
    #[serde(rename = "sessRules", default, skip_serializing_if = "HashMap::is_empty")]
    pub session_rules: HashMap<String, SessionRule>,
    /// PCC rules keyed by rule id (TS 29.512 `pccRules`) — the authorized flows, each
    /// referencing a QoS decision (`qosDecs`) and optionally a charging one (`chgDecs`).
    /// Use [`Self::qos_flows`] for the flattened per-flow view the SMF acts on.
    #[serde(rename = "pccRules", default, skip_serializing_if = "HashMap::is_empty")]
    pub pcc_rules: HashMap<String, PccRule>,
    /// QoS decisions keyed by QoS id (TS 29.512 `qosDecs`), referenced by a PCC rule's
    /// `refQosData`.
    #[serde(rename = "qosDecs", default, skip_serializing_if = "HashMap::is_empty")]
    pub qos_descs: HashMap<String, QosData>,
    /// Charging decisions keyed by charging-data id (TS 29.512 `chgDecs`), referenced by
    /// a PCC rule's `refChgData`. Each map is conveyed as a keyed partial map in an
    /// Update (present = install/modify, `null` = remove, absent = keep).
    #[serde(rename = "chgDecs", default, skip_serializing_if = "HashMap::is_empty")]
    pub charging_descs: HashMap<String, ChargingData>,
}

impl SmPolicyDecision {
    /// The effective session AMBR — the `authSessAmbr` of a session rule that carries
    /// one (the session has a single default rule). `None` when no rule sets it.
    pub fn session_ambr(&self) -> Option<&SessionAmbrPolicy> {
        self.session_rules.values().find_map(|r| r.auth_sess_ambr.as_ref())
    }

    /// A single "default" session rule carrying `ambr` (or no rules when `None`) —
    /// convenience for building a decision from a flat session AMBR.
    pub fn session_rules_for(ambr: Option<SessionAmbrPolicy>) -> HashMap<String, SessionRule> {
        match ambr {
            Some(a) => HashMap::from([("default".to_string(), SessionRule { auth_sess_ambr: Some(a) })]),
            None => HashMap::new(),
        }
    }

    /// The flattened per-flow view the SMF acts on — the result of **QoS-flow binding**
    /// (TS 23.501 §5.7.1.7): the PCC rules are bound to QoS flows by their `refQosData`,
    /// so rules sharing a QoS decision share one flow (one QFI). Each referenced QoS
    /// decision becomes one flow, carrying its QFI + QoS and the classifier + charging of
    /// the **highest-precedence** rule bound to it. Ordered by QFI. A QoS decision no rule
    /// binds to yields no flow; a rule referencing no/unknown QoS decision binds nothing.
    pub fn qos_flows(&self) -> Vec<QosFlowPolicy> {
        let mut flows: Vec<QosFlowPolicy> = self
            .qos_descs
            .iter()
            .filter_map(|(id, qos)| {
                // The rule bound to this QoS flow with the highest precedence (lowest
                // number) provides the flow's SDF filter + charging reference.
                let rep = self
                    .pcc_rules
                    .values()
                    .filter(|r| r.ref_qos_data.as_deref() == Some(id.as_str()))
                    .min_by_key(|r| r.precedence)?;
                Some(QosFlowPolicy {
                    qfi: qos.qfi,
                    five_qi: qos.five_qi,
                    arp_priority: qos.arp_priority,
                    pre_empt_cap: qos.pre_empt_cap,
                    pre_empt_vuln: qos.pre_empt_vuln,
                    gbr: qos.gbr.clone(),
                    filter: rep.flow_info,
                    ref_chg_data: rep.ref_chg_data.clone(),
                })
            })
            .collect();
        flows.sort_by_key(|f| f.qfi);
        flows
    }

    /// Populate `pcc_rules` + `qos_descs` from a flat list of QoS flows (the sm-data /
    /// demo bridge): each flow becomes a QoS decision `qos-{qfi}` (carrying the QFI) and a
    /// PCC rule `pcc-{qfi}` bound to it — one rule per QoS flow.
    pub fn set_flows(&mut self, flows: impl IntoIterator<Item = QosFlowPolicy>) {
        for f in flows {
            let qos_id = format!("qos-{}", f.qfi);
            self.qos_descs.insert(
                qos_id.clone(),
                QosData {
                    qfi: f.qfi,
                    five_qi: f.five_qi,
                    arp_priority: f.arp_priority,
                    pre_empt_cap: f.pre_empt_cap,
                    pre_empt_vuln: f.pre_empt_vuln,
                    gbr: f.gbr,
                },
            );
            self.pcc_rules.insert(
                format!("pcc-{}", f.qfi),
                PccRule {
                    precedence: u16::from(f.qfi),
                    flow_info: f.filter,
                    ref_qos_data: Some(qos_id),
                    ref_chg_data: f.ref_chg_data,
                },
            );
        }
    }

    /// The rating group a QoS flow is charged under: the `refChgData` of a rule bound to
    /// the QoS decision with this QFI → [`Self::charging_descs`]. `None` when unbound or
    /// unreferenced, so the caller keeps its fallback.
    pub fn rating_group_for(&self, qfi: u8) -> Option<u32> {
        let qos_id = self.qos_descs.iter().find(|(_, q)| q.qfi == qfi).map(|(id, _)| id)?;
        let chg_id = self
            .pcc_rules
            .values()
            .filter(|r| r.ref_qos_data.as_deref() == Some(qos_id.as_str()))
            .find_map(|r| r.ref_chg_data.as_ref())?;
        Some(self.charging_descs.get(chg_id)?.rating_group)
    }
}

/// A **partial** SM policy decision — the Npcf_SMPolicyControl Update response is a
/// delta, not a full replacement (TS 29.512 §5.6.2.5). Each of the decision's keyed
/// maps (session rules, PCC rules, QoS decisions, charging decisions) is a partial map:
/// a present entry is installed/modified, a `null` one removed, an absent one kept.
/// Built by [`SmPolicyDecision::diff`], merged by [`SmPolicyDecision::apply`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyUpdate {
    #[serde(rename = "sessRules", default, skip_serializing_if = "HashMap::is_empty")]
    pub session_rules: HashMap<String, Option<SessionRule>>,
    #[serde(rename = "pccRules", default, skip_serializing_if = "HashMap::is_empty")]
    pub pcc_rules: HashMap<String, Option<PccRule>>,
    #[serde(rename = "qosDecs", default, skip_serializing_if = "HashMap::is_empty")]
    pub qos_descs: HashMap<String, Option<QosData>>,
    #[serde(rename = "chgDecs", default, skip_serializing_if = "HashMap::is_empty")]
    pub charging_descs: HashMap<String, Option<ChargingData>>,
}

impl SmPolicyDecision {
    /// The partial Update delta from `self` (the previous decision) to `next`: for each
    /// keyed map (session rules, PCC rules, QoS decisions, charging decisions), a new or
    /// changed entry is present (`Some`), a removed one `null` (`None`), an unchanged one
    /// omitted. `None` when nothing changed.
    pub fn diff(&self, next: &SmPolicyDecision) -> Option<SmPolicyUpdate> {
        let session_rules = diff_keyed(&self.session_rules, &next.session_rules);
        let pcc_rules = diff_keyed(&self.pcc_rules, &next.pcc_rules);
        let qos_descs = diff_keyed(&self.qos_descs, &next.qos_descs);
        let charging_descs = diff_keyed(&self.charging_descs, &next.charging_descs);
        (!session_rules.is_empty()
            || !pcc_rules.is_empty()
            || !qos_descs.is_empty()
            || !charging_descs.is_empty())
        .then_some(SmPolicyUpdate { session_rules, pcc_rules, qos_descs, charging_descs })
    }

    /// Merge a partial Update onto this decision: for each id in each keyed map's delta,
    /// install/replace (`Some`) or remove (`None`) the entry; ids the delta omits are kept.
    pub fn apply(&mut self, update: &SmPolicyUpdate) {
        apply_keyed(&mut self.session_rules, &update.session_rules);
        apply_keyed(&mut self.pcc_rules, &update.pcc_rules);
        apply_keyed(&mut self.qos_descs, &update.qos_descs);
        apply_keyed(&mut self.charging_descs, &update.charging_descs);
    }
}

/// The partial-map delta between two id-keyed maps: an id whose value changed or is new
/// → `Some(new)`, an id removed → `None` (JSON `null`); unchanged ids omitted.
fn diff_keyed<T: Clone + PartialEq>(
    prev: &HashMap<String, T>,
    next: &HashMap<String, T>,
) -> HashMap<String, Option<T>> {
    let mut delta = HashMap::new();
    for (id, v) in next {
        if prev.get(id) != Some(v) {
            delta.insert(id.clone(), Some(v.clone()));
        }
    }
    for id in prev.keys() {
        if !next.contains_key(id) {
            delta.insert(id.clone(), None);
        }
    }
    delta
}

/// Merge an id-keyed partial-map delta: `Some` installs/replaces, `None` removes; ids
/// the delta omits are kept.
fn apply_keyed<T: Clone>(map: &mut HashMap<String, T>, delta: &HashMap<String, Option<T>>) {
    for (id, change) in delta {
        match change {
            Some(v) => {
                map.insert(id.clone(), v.clone());
            }
            None => {
                map.remove(id);
            }
        }
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
    /// The demo policy: 1/2 Gbps session AMBR, a default non-GBR flow (5QI 9) and a
    /// GBR flow (5QI 1, GFBR 100 Mbps / MFBR 200 Mbps) charged under rating group 100
    /// (via the "chg-voice" charging decision) — for any DNN.
    pub fn demo() -> Self {
        let mut decision = SmPolicyDecision {
            session_rules: SmPolicyDecision::session_rules_for(Some(SessionAmbrPolicy {
                uplink: "1 Gbps".into(),
                downlink: "2 Gbps".into(),
            })),
            charging_descs: HashMap::from([(
                "chg-voice".to_string(),
                ChargingData {
                    rating_group: 100,
                    metering_method: Some("VOLUME".into()),
                    online: Some(false),
                    offline: Some(true),
                },
            )]),
            ..Default::default()
        };
        // Two flows via the sm-data bridge (→ pcc-{qfi} rules + qos-{qfi} decisions): a
        // default non-GBR flow (5QI 9) and a GBR flow (5QI 1) charged under "chg-voice".
        decision.set_flows([
            QosFlowPolicy {
                qfi: 1,
                five_qi: 9,
                arp_priority: 8,
                pre_empt_cap: false,
                pre_empt_vuln: false,
                gbr: None,
                filter: None,
                ref_chg_data: None,
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
                // Charged under the "chg-voice" decision (rating group 100).
                ref_chg_data: Some("chg-voice".into()),
            },
        ]);
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
        flows = decision.pcc_rules.len(),
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
        rules = fresh.pcc_rules.len(),
        rule_changes = delta.pcc_rules.len(),
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
        let ambr = created.decision.session_ambr().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("1 Gbps", "2 Gbps"));
        let flows = created.decision.qos_flows();
        assert_eq!(flows.len(), 2);
        assert_eq!((flows[0].qfi, flows[0].five_qi), (1, 9));
        assert!(flows[1].gbr.is_some(), "second flow is GBR");
        assert_eq!(state.association_count(), 1);

        pcf.delete_sm_policy(&created.policy_id).await.expect("deleted");
        assert_eq!(state.association_count(), 0, "association removed");
    }

    #[test]
    fn per_dnn_override_wins_over_default() {
        let mut ims = SmPolicyDecision {
            session_rules: SmPolicyDecision::session_rules_for(Some(SessionAmbrPolicy {
                uplink: "5 Mbps".into(),
                downlink: "5 Mbps".into(),
            })),
            ..Default::default()
        };
        ims.set_flows([QosFlowPolicy {
            qfi: 3,
            five_qi: 5,
            arp_priority: 1,
            pre_empt_cap: true,
            pre_empt_vuln: false,
            gbr: None,
            filter: None,
            ref_chg_data: None,
        }]);
        let config = PolicyConfig::demo().with_dnn("ims", ims);
        // The override applies to its DNN...
        let d = config.decide("ims");
        assert_eq!(d.qos_flows().len(), 1);
        assert_eq!(d.qos_flows()[0].five_qi, 5);
        // ...every other DNN gets the default (two flows incl. a GBR one).
        let d = config.decide("internet");
        let flows = d.qos_flows();
        assert_eq!(flows.len(), 2);
        assert!(flows.iter().any(|f| f.gbr.is_some()));
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
                "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" } } },
                "pccRules": { "pcc-1": { "refQosData": "qos-1" } },
                "qosDecs": { "qos-1": { "qfi": 1, "fiveQi": 9 } }
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
        let ambr = created.decision.session_ambr().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("200 Mbps", "400 Mbps"));
        assert_eq!(created.decision.qos_flows().len(), 1);

        // Mid-session change: reprovision the UDR, then Update re-reads it.
        let v2 = serde_json::json!({
            "default": {
                "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "50 Mbps", "downlink": "100 Mbps" } } },
                "pccRules": {
                    "pcc-1": { "refQosData": "qos-1" },
                    "pcc-2": { "refQosData": "qos-2" }
                },
                "qosDecs": {
                    "qos-1": { "qfi": 1, "fiveQi": 9 },
                    "qos-2": { "qfi": 2, "fiveQi": 1, "gbr": {
                        "gfbrDl": "10 Mbps", "gfbrUl": "10 Mbps",
                        "mfbrDl": "20 Mbps", "mfbrUl": "20 Mbps" } }
                }
            }
        });
        udr.put_sm_policy_data("imsi-1", &v2).await.unwrap();
        let update = pcf
            .update_sm_policy(&created.policy_id, &SmPolicyUpdateContextData::default())
            .await
            .unwrap();
        // A PARTIAL delta: the session rule's AMBR changed (installed) and only the new
        // PCC rule + QoS decision (QFI 2) were added; the unchanged QFI 1 is omitted.
        let Some(Some(rule)) = update.session_rules.get("rule-1") else {
            panic!("session rule changed → installed")
        };
        let ambr = rule.auth_sess_ambr.as_ref().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("50 Mbps", "100 Mbps"));
        assert_eq!(update.pcc_rules.len(), 1, "only the added PCC rule is in the delta");
        assert!(update.pcc_rules.get("pcc-2").unwrap().is_some(), "pcc-2 installed");
        assert!(!update.pcc_rules.contains_key("pcc-1"), "unchanged pcc-1 omitted (kept)");
        assert!(update.qos_descs.get("qos-2").unwrap().is_some(), "qos-2 installed");

        // Merging the delta onto the previous decision recovers the full v2 policy.
        let mut merged = created.decision.clone();
        merged.apply(&update);
        assert_eq!(merged.qos_flows().len(), 2, "merge keeps QFI 1 and installs QFI 2");
        assert_eq!(merged.session_ambr().unwrap().downlink, "100 Mbps");

        // Updating an unknown association → error (404).
        assert!(
            pcf.update_sm_policy("nope", &SmPolicyUpdateContextData::default()).await.is_err()
        );
    }

    /// The partial SM Update delta (TS 29.512): `diff` emits only the entries that
    /// changed across the PCC-rule and QoS-decision maps — a new/changed one as a value,
    /// a removed one as JSON `null`, an unchanged one omitted; `apply` merges the delta
    /// back, and the derived `qos_flows()` view reflects the result.
    #[test]
    fn sm_policy_partial_diff_and_apply() {
        let qos = |qfi: u8, five_qi: u8| QosData {
            qfi,
            five_qi,
            arp_priority: 8,
            pre_empt_cap: false,
            pre_empt_vuln: false,
            gbr: None,
        };
        let rule = |qfi: u8| PccRule {
            precedence: u16::from(qfi),
            flow_info: None,
            ref_qos_data: Some(format!("qos-{qfi}")),
            ref_chg_data: None,
        };
        let prev = SmPolicyDecision {
            session_rules: SmPolicyDecision::session_rules_for(Some(SessionAmbrPolicy {
                uplink: "1 Gbps".into(),
                downlink: "2 Gbps".into(),
            })),
            pcc_rules: HashMap::from([("pcc-1".into(), rule(1)), ("pcc-2".into(), rule(2))]),
            qos_descs: HashMap::from([("qos-1".into(), qos(1, 9)), ("qos-2".into(), qos(2, 1))]),
            ..Default::default()
        };
        // Next: session rule unchanged; qos-1 re-rated (5QI 9→6); flow 2 removed; flow 3 added.
        let mut next = prev.clone();
        next.qos_descs.insert("qos-1".into(), qos(1, 6));
        next.pcc_rules.remove("pcc-2");
        next.qos_descs.remove("qos-2");
        next.pcc_rules.insert("pcc-3".into(), rule(3));
        next.qos_descs.insert("qos-3".into(), qos(3, 5));

        let delta = prev.diff(&next).expect("something changed");
        assert!(delta.session_rules.is_empty(), "session rule unchanged → omitted");
        // PCC rules: pcc-2 removed (null), pcc-3 added (Some); pcc-1 unchanged (omitted).
        assert_eq!(delta.pcc_rules.len(), 2);
        assert_eq!(*delta.pcc_rules.get("pcc-2").unwrap(), None, "pcc-2 removed → null");
        assert!(delta.pcc_rules.get("pcc-3").unwrap().is_some(), "pcc-3 added");
        assert!(!delta.pcc_rules.contains_key("pcc-1"), "unchanged pcc-1 omitted");
        // QoS decisions: qos-1 re-rated (Some), qos-2 removed (null), qos-3 added (Some).
        assert_eq!(delta.qos_descs.get("qos-1").unwrap().as_ref().unwrap().five_qi, 6, "qos-1 re-rated");
        assert_eq!(*delta.qos_descs.get("qos-2").unwrap(), None, "qos-2 removed → null");
        assert!(delta.qos_descs.get("qos-3").unwrap().is_some(), "qos-3 added");

        // On the wire, removals are JSON null; the unchanged session rule is absent.
        let wire = serde_json::to_value(&delta).unwrap();
        assert!(wire.get("sessRules").is_none(), "unchanged session rule omitted");
        assert!(wire.pointer("/pccRules/pcc-2").unwrap().is_null(), "removed PCC rule is null");
        assert!(wire.pointer("/qosDecs/qos-2").unwrap().is_null(), "removed QoS decision is null");

        // apply merges the delta onto prev → exactly next.
        let mut merged = prev.clone();
        merged.apply(&delta);
        assert_eq!(merged, next, "merge reconstructs the next decision");
        // The derived per-flow view reflects it: QFI 1 (re-rated to 5QI 6) + QFI 3, no QFI 2.
        let flows = merged.qos_flows();
        assert_eq!(flows.iter().map(|f| f.qfi).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(flows[0].five_qi, 6, "QFI 1 re-rated via qos-1");

        // A no-op update (prev vs prev) → no delta.
        assert_eq!(prev.diff(&prev.clone()), None);
    }

    /// Charging decisions (`chgDecs`) are a keyed partial map — diff/apply install, modify
    /// and remove them like PCC/QoS entries — and a flow resolves its rating group through
    /// its `refChgData` reference.
    #[test]
    fn charging_descs_partial_map_and_rating_group() {
        let chg = |rg| ChargingData { rating_group: rg, metering_method: None, online: None, offline: None };
        let flow = |qfi, chg_id: Option<&str>| QosFlowPolicy {
            qfi,
            five_qi: 1,
            arp_priority: 8,
            pre_empt_cap: false,
            pre_empt_vuln: false,
            gbr: None,
            filter: None,
            ref_chg_data: chg_id.map(String::from),
        };
        // A flow charged under "chg-a" (rating group 100); an unreferenced "chg-b". The
        // PCC rule bound to QFI 2 carries `refChgData = "chg-a"` (via set_flows).
        let mut prev = SmPolicyDecision {
            charging_descs: HashMap::from([("chg-a".into(), chg(100)), ("chg-b".into(), chg(200))]),
            ..Default::default()
        };
        prev.set_flows([flow(2, Some("chg-a")), flow(3, None)]);
        // The flow's rating group resolves via the PCC rule's refChgData → chgDecs.
        assert_eq!(prev.rating_group_for(2), Some(100), "resolved from the charging decision");
        assert_eq!(prev.rating_group_for(3), None, "no refChgData → caller falls back");
        assert_eq!(prev.rating_group_for(9), None, "unknown QFI");

        // Next: re-rate "chg-a" (100→150), remove "chg-b", add "chg-c" — flows unchanged.
        let next = SmPolicyDecision {
            pcc_rules: prev.pcc_rules.clone(),
            qos_descs: prev.qos_descs.clone(),
            charging_descs: HashMap::from([("chg-a".into(), chg(150)), ("chg-c".into(), chg(300))]),
            ..Default::default()
        };
        let delta = prev.diff(&next).expect("charging changed");
        assert!(delta.pcc_rules.is_empty() && delta.qos_descs.is_empty(), "flows unchanged → omitted");
        assert_eq!(delta.charging_descs.len(), 3, "chg-a (changed), chg-b (removed), chg-c (added)");
        assert_eq!(delta.charging_descs.get("chg-a").unwrap().as_ref().unwrap().rating_group, 150);
        assert_eq!(*delta.charging_descs.get("chg-b").unwrap(), None, "removed → null");
        assert!(delta.charging_descs.get("chg-c").unwrap().is_some(), "added");
        // On the wire, chgDecs carries the removal as null.
        let wire = serde_json::to_value(&delta).unwrap();
        assert!(wire.pointer("/chgDecs/chg-b").unwrap().is_null(), "removed charging decision is null");

        // apply merges the delta → exactly next; the re-rated group now resolves.
        let mut merged = prev.clone();
        merged.apply(&delta);
        assert_eq!(merged, next, "merge reconstructs next");
        assert_eq!(merged.rating_group_for(2), Some(150), "re-rated group after merge");
    }

    /// SMF QoS-flow **binding** (TS 23.501 §5.7.1.7): PCC rules are bound to QoS flows by
    /// their `refQosData`, so rules sharing a QoS decision share one flow (one QFI). The
    /// flow resolves its QFI/5QI/ARP/GBR from the QoS decision, and its filter + charging
    /// from the highest-precedence bound rule.
    #[test]
    fn pcc_rules_bind_to_qos_flows() {
        let mut d = SmPolicyDecision::default();
        // One QoS flow (QFI 5) with GBR.
        d.qos_descs.insert(
            "qos-gbr".into(),
            QosData {
                qfi: 5,
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
        );
        d.charging_descs.insert(
            "chg".into(),
            ChargingData { rating_group: 42, metering_method: None, online: None, offline: None },
        );
        // TWO PCC rules both binding to that QoS flow (same refQosData) — they bind to one
        // QFI. The lower-precedence-number rule (pcc-hi) wins the flow's filter + charging.
        d.pcc_rules.insert(
            "pcc-hi".into(),
            PccRule {
                precedence: 10,
                flow_info: Some(PacketFilterPolicy { protocol: 17, port_low: 5000, port_high: 5010 }),
                ref_qos_data: Some("qos-gbr".into()),
                ref_chg_data: Some("chg".into()),
            },
        );
        d.pcc_rules.insert(
            "pcc-lo".into(),
            PccRule {
                precedence: 20,
                flow_info: Some(PacketFilterPolicy { protocol: 6, port_low: 80, port_high: 80 }),
                ref_qos_data: Some("qos-gbr".into()),
                ref_chg_data: None,
            },
        );
        // Binding: two rules → ONE QoS flow (QFI 5), not two.
        let flows = d.qos_flows();
        assert_eq!(flows.len(), 1, "both rules bound to one QoS flow");
        let f = &flows[0];
        assert_eq!((f.qfi, f.five_qi, f.arp_priority), (5, 1, 5), "QFI + QoS from the QoS decision");
        assert!(f.pre_empt_cap && f.gbr.is_some(), "pre-emption + GBR from the QoS decision");
        assert_eq!(f.filter.unwrap().port_low, 5000, "filter from the highest-precedence rule");
        // The rating group resolves via a bound rule's refChgData.
        assert_eq!(d.rating_group_for(5), Some(42));

        // A QoS decision that no rule binds to yields no flow; a rule with an unknown
        // refQosData binds to nothing — neither produces a flow.
        d.qos_descs.insert("qos-idle".into(), QosData { qfi: 9, five_qi: 9, arp_priority: 8, pre_empt_cap: false, pre_empt_vuln: false, gbr: None });
        d.pcc_rules.insert("pcc-dangling".into(), PccRule { precedence: 30, flow_info: None, ref_qos_data: Some("missing".into()), ref_chg_data: None });
        let flows = d.qos_flows();
        assert_eq!(flows.iter().map(|f| f.qfi).collect::<Vec<_>>(), vec![5], "unbound QoS + dangling rule → still one flow");
    }

    /// Session rules (`sessRules`) are a keyed partial map carrying the session AMBR:
    /// `diff`/`apply` install, modify and remove rules; `session_ambr` reads the
    /// effective AMBR without knowing the rule ids.
    #[test]
    fn session_rules_partial_map_and_ambr() {
        let rule = |ul: &str, dl: &str| SessionRule {
            auth_sess_ambr: Some(SessionAmbrPolicy { uplink: ul.into(), downlink: dl.into() }),
        };
        let prev = SmPolicyDecision {
            session_rules: HashMap::from([("default".to_string(), rule("1 Gbps", "2 Gbps"))]),
            ..Default::default()
        };
        // The accessor reads the AMBR from the default rule.
        let ambr = prev.session_ambr().expect("effective AMBR");
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("1 Gbps", "2 Gbps"));

        // Next: re-rate the default rule (2 Gbps → 5 Gbps), add an AMBR-less "rule-2"
        // (a session rule carrying no session AMBR — so the effective AMBR stays
        // unambiguous).
        let next = SmPolicyDecision {
            session_rules: HashMap::from([
                ("default".to_string(), rule("1 Gbps", "5 Gbps")),
                ("rule-2".to_string(), SessionRule { auth_sess_ambr: None }),
            ]),
            ..Default::default()
        };
        let delta = prev.diff(&next).expect("session rules changed");
        assert_eq!(delta.session_rules.len(), 2, "default (changed) + rule-2 (added)");
        assert!(delta.session_rules.get("default").unwrap().is_some(), "default re-rated");
        assert!(delta.session_rules.get("rule-2").unwrap().is_some(), "rule-2 added");
        // On the wire, sessRules carries authSessAmbr under each rule id.
        let wire = serde_json::to_value(&delta).unwrap();
        assert_eq!(
            wire.pointer("/sessRules/default/authSessAmbr/downlink").and_then(|v| v.as_str()),
            Some("5 Gbps")
        );

        // apply merges → next; the effective AMBR reflects the re-rate.
        let mut merged = prev.clone();
        merged.apply(&delta);
        assert_eq!(merged, next, "merge reconstructs next");
        assert_eq!(merged.session_ambr().unwrap().downlink, "5 Gbps", "re-rated AMBR after merge");

        // Removing the default rule → it maps to null; the effective AMBR is then gone.
        let removed = SmPolicyDecision::default();
        let delta = prev.diff(&removed).expect("rule removed");
        assert_eq!(*delta.session_rules.get("default").unwrap(), None, "removed → null");
        let mut merged = prev.clone();
        merged.apply(&delta);
        assert_eq!(merged.session_ambr(), None, "no rule → no effective AMBR");
    }
}
