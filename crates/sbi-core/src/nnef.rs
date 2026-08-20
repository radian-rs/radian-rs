//! NEF — Network Exposure Function, `Nnef_TrafficInfluence` (TS 29.522).
//!
//! The northbound front door for an **AF traffic-influence** request: "route traffic for
//! this app, for this UE on this DNN, to this edge (DNAI)." That is a local-breakout /
//! uplink-classifier insertion, which the SMF already performs on a live session
//! (design/134 Phase 3e). The NEF is a thin translator (design/135): it turns a
//! `TrafficInfluSub` into the SMF's breakout trigger and tracks the subscription so a
//! delete undoes the insert.
//!
//! DNAI→UPF resolution stays in the SMF's topology (as free5gc keeps it in the userplane
//! config), so the NEF passes the DNAI through untouched — it never learns the UP topology.
//! The first slice is AF → NEF → SMF **direct**; the PCF-mediated path is design/135 Phase 2.

use crate::otel::Traced;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

/// An AF traffic-influence subscription (TS 29.522 `TrafficInfluSub`) — the subset radian
/// acts on. The AF targets a UE (`supi`/`gpsi`) on a `dnn`, matches traffic with
/// `trafficFilters` (IPFilterRule flow descriptions), and steers it to `trafficRoutes[].dnai`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficInfluSub {
    /// The target subscriber. radian accepts a `supi` directly, or a `gpsi` used as one.
    #[serde(default)]
    pub supi: Option<String>,
    #[serde(default)]
    pub gpsi: Option<String>,
    #[serde(default)]
    pub dnn: Option<String>,
    /// Traffic to steer — each entry's `flowDescriptions` are IPFilterRule strings whose
    /// destination is the breakout prefix.
    #[serde(default)]
    pub traffic_filters: Vec<FlowInfo>,
    /// Where to steer it — each `RouteToLocation` names a `dnai` (the breakout edge).
    #[serde(default)]
    pub traffic_routes: Vec<RouteToLocation>,
    /// radian convenience: a destination prefix (CIDR) directly, in place of a flow
    /// description — the same value the SMF's classifier ultimately matches on.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Apply to **any** UE (TS 29.522 `anyUeInd`) — a group influence, stored in the UDR
    /// rather than authorized per session (design/135 Phase 3).
    #[serde(default)]
    pub any_ue_ind: bool,
    /// An external group identifier — the group form of the same thing. Membership is
    /// carried by `supis` here; a real deployment resolves it at the UDM/UDR.
    #[serde(default)]
    pub external_group_id: Option<String>,
    /// The SUPIs a group influence covers.
    #[serde(default)]
    pub supis: Vec<String>,
}

/// One IP flow filter: a set of IPFilterRule `flowDescriptions`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowInfo {
    #[serde(default)]
    pub flow_descriptions: Vec<String>,
}

/// A route target — an abstract edge named by its DNAI (TS 23.501 §5.6.7).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteToLocation {
    pub dnai: String,
}

/// The create response — a link to the resource the AF can later delete.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubCreated {
    #[serde(rename = "self")]
    self_link: String,
}

/// How a subscription was applied — which decides how a delete withdraws it.
#[derive(Debug, Clone)]
enum Applied {
    /// Authorized at the PCF as an app-session (design/135 Phase 2b).
    Pcf(String),
    /// Applied straight at the SMF's breakout trigger — no PCF deployed (Phase 1).
    Smf,
    /// Stored in the UDR as group / any-UE influence data (Phase 3).
    Udr(String),
}

impl Applied {
    fn label(&self) -> &'static str {
        match self {
            Applied::Pcf(_) => "pcf",
            Applied::Smf => "smf-direct",
            Applied::Udr(_) => "udr-influence-data",
        }
    }
}

/// What a live subscription steers, remembered so a delete can reverse it — and *how* it
/// was applied, since that decides how it is withdrawn.
struct Subscription {
    /// The `af_id` that created it — a delete is honored only for the owning AF, so one AF
    /// cannot withdraw another's influence (design/137 F2).
    af_id: String,
    supi: String,
    dnn: Option<String>,
    applied: Applied,
}

/// A per-AF **service-level agreement** — the scope of traffic-influence an authenticated
/// AF is contracted for (design/137 F2). Authentication (the API key) proves *who* the AF
/// is; the SLA bounds *what* it may do, so an AF cannot steer subscribers, DNNs, or edges
/// outside its contract even with a valid key.
///
/// Every allow-list is **deny-by-default**: an empty set permits nothing in that dimension,
/// and the wildcard `"*"` permits anything. An AF that is authenticated but has no SLA entry
/// is refused outright (see [`NefState::authorize_request`]).
#[derive(Debug, Clone, Default)]
pub struct AfSla {
    /// DNNs the AF may influence. A request naming a DNN outside this set — or omitting the
    /// DNN under anything but a `"*"` contract — is refused.
    pub dnns: HashSet<String>,
    /// DNAIs (breakout edges) the AF may steer traffic to. **Every** `trafficRoutes[].dnai`
    /// must be permitted, so an AF cannot smuggle an attacker-chosen edge past the first.
    pub dnais: HashSet<String>,
    /// SUPIs the AF may target, matched as **prefixes**: an IMSI/PLMN prefix scopes a whole
    /// range, an exact SUPI scopes one UE. Applies to the single-UE `supi`/`gpsi` target and
    /// to each explicit member of a group influence.
    pub supis: HashSet<String>,
    /// Whether the AF may create **group / any-UE** influences (`anyUeInd` / `externalGroupId`),
    /// which write UDR influence data every PCF applies network-wide. Off by default — the
    /// broadest, most dangerous verb, so it must be granted explicitly.
    pub allow_group: bool,
}

impl AfSla {
    /// Membership with a `"*"` wildcard escape.
    fn permits(set: &HashSet<String>, value: &str) -> bool {
        set.contains("*") || set.contains(value)
    }

    fn permits_dnn(&self, dnn: Option<&str>) -> bool {
        match dnn {
            Some(d) => Self::permits(&self.dnns, d),
            // An unspecified DNN can't be checked against a specific contract, so it is
            // allowed only under a wildcard grant.
            None => self.dnns.contains("*"),
        }
    }

    /// A SUPI is in scope if the contract is `"*"`, or the SUPI starts with a listed prefix.
    /// (Empty prefixes are dropped at parse time so they can't match everything by accident.)
    fn permits_supi(&self, supi: &str) -> bool {
        self.supis.contains("*") || self.supis.iter().any(|p| supi.starts_with(p.as_str()))
    }
}

/// Parse the `RADIAN_NEF_AF_SLA` grammar into a per-AF SLA map. AFs are separated by `;`,
/// and each AF is five `|`-separated fields:
/// `af_id | dnns | dnais | supis | group`, where the three list fields are comma-separated
/// (or `*` for any, empty for none) and `group` is `yes`/`true`/`1` for group-influence
/// permission (anything else, including empty, is `false`). Malformed AF entries (missing
/// fields, empty id) are skipped. Example:
/// `app1|internet,ims|mec,edge1|imsi-99970|no;app2|*|edge2|*|yes`.
pub fn parse_af_slas(spec: &str) -> HashMap<String, AfSla> {
    let set = |field: &str| -> HashSet<String> {
        field
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    spec.split(';')
        .filter_map(|entry| {
            let mut fields = entry.split('|');
            let af_id = fields.next()?.trim();
            let (dnns, dnais, supis, group) =
                (fields.next()?, fields.next()?, fields.next()?, fields.next()?);
            if af_id.is_empty() {
                return None;
            }
            let allow_group = matches!(group.trim(), "yes" | "true" | "1");
            Some((
                af_id.to_string(),
                AfSla { dnns: set(dnns), dnais: set(dnais), supis: set(supis), allow_group },
            ))
        })
        .collect()
}

/// NEF runtime: how to reach the PCF/SMF, plus the live subscriptions.
#[derive(Clone)]
pub struct NefState {
    /// NRF base for discovering the PCF/SMF; `None` when explicit bases are set.
    nrf_base: Option<String>,
    /// An explicit SMF base URL, overriding discovery (an env escape hatch / tests).
    smf_base: Option<String>,
    /// An explicit PCF base URL. When a PCF is reachable — set here or discovered — an AF
    /// influence is authorized **through it** (design/135 Phase 2b), so the route lands in
    /// the SM policy and composes with QoS. Without a PCF the NEF falls back to driving
    /// the SMF directly (Phase 1).
    pcf_base: Option<String>,
    /// An explicit UDR base URL. A **group / any-UE** influence is stored there as
    /// application influence data (design/135 Phase 3) rather than authorized per session,
    /// so every PCF picks it up — including for sessions established later.
    udr_base: Option<String>,
    /// Per-AF API keys (`af_id` → key) authenticating the **northbound** AF requests
    /// (design/137 F2). `None` ⇒ the northbound is open (dev default); when set, a request
    /// must carry the key provisioned for the `af_id` it targets, so an unauthenticated (or
    /// wrong) AF cannot steer subscribers' traffic. The NEF is the external trust boundary,
    /// so — unlike the intra-core OAuth mesh — the AF is authenticated by a shared key.
    af_keys: Option<Arc<HashMap<String, String>>>,
    /// Per-AF SLAs (`af_id` → [`AfSla`]) authorizing the **content** of a request — the DNN,
    /// DNAIs, subscribers, and group scope the AF is contracted for (design/137 F2). `None` ⇒
    /// authorization is disabled (dev default); when set, an authenticated AF may only
    /// influence what its SLA permits, and an AF with no SLA entry is refused.
    af_slas: Option<Arc<HashMap<String, AfSla>>>,
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    next_id: AtomicU64,
    subs: HashMap<String, Subscription>,
}

impl NefState {
    /// Discover the PCF/SMF via the NRF at `nrf_base`.
    pub fn new(nrf_base: impl Into<String>) -> Self {
        Self::build(Some(nrf_base.into()), None, None)
    }

    /// Reach the SMF at an explicit base URL, bypassing NRF discovery (deployments without
    /// an NRF, or tests). No PCF ⇒ the Phase-1 direct path.
    pub fn with_smf_base(smf_base: impl Into<String>) -> Self {
        Self::build(None, Some(smf_base.into()), None)
    }

    /// Authorize influences through an explicit PCF (design/135 Phase 2b).
    pub fn with_pcf_base(mut self, pcf_base: impl Into<String>) -> Self {
        self.pcf_base = Some(pcf_base.into());
        self
    }

    /// Store group / any-UE influences at an explicit UDR (design/135 Phase 3).
    pub fn with_udr_base(mut self, udr_base: impl Into<String>) -> Self {
        self.udr_base = Some(udr_base.into());
        self
    }

    /// Require a per-AF API key on northbound requests (design/137 F2): a request must
    /// carry `Authorization: Bearer <key>` matching the key provisioned here for its
    /// `af_id`. An empty map is treated as "no keys configured" (open).
    pub fn with_af_keys(mut self, keys: HashMap<String, String>) -> Self {
        self.af_keys = (!keys.is_empty()).then(|| Arc::new(keys));
        self
    }

    /// Authorize each AF request against a per-AF SLA (design/137 F2): once set, an
    /// authenticated AF may only influence the DNNs/DNAIs/subscribers — and the group scope —
    /// its [`AfSla`] grants, and an AF with no SLA entry is refused. An empty map is treated
    /// as "no SLAs configured" (authorization disabled). See [`parse_af_slas`] for the env
    /// grammar. Pair this with [`with_af_keys`](Self::with_af_keys): without authentication
    /// the `af_id` is only an unverified path segment, so the SLA it selects is spoofable.
    pub fn with_af_slas(mut self, slas: HashMap<String, AfSla>) -> Self {
        self.af_slas = (!slas.is_empty()).then(|| Arc::new(slas));
        self
    }

    fn build(
        nrf_base: Option<String>,
        smf_base: Option<String>,
        pcf_base: Option<String>,
    ) -> Self {
        Self {
            nrf_base,
            smf_base,
            pcf_base,
            udr_base: None,
            af_keys: None,
            af_slas: None,
            inner: Arc::new(Mutex::new(Inner {
                next_id: AtomicU64::new(1),
                subs: HashMap::new(),
            })),
        }
    }

    /// Authenticate + authorize the calling AF (design/137 F2). With no AF keys
    /// configured the northbound is open (dev default); otherwise the request must carry
    /// `Authorization: Bearer <key>` whose key is the one provisioned for this `af_id` —
    /// so an unauthenticated AF, or an AF acting under another's identifier, is refused.
    /// `Err` carries the 401 response to return; the same status is used for every failure
    /// so a caller can't enumerate provisioned `af_id`s.
    fn authorize_af(&self, af_id: &str, headers: &HeaderMap) -> Result<(), axum::response::Response> {
        let Some(keys) = &self.af_keys else {
            return Ok(()); // no AF keys configured — open (dev)
        };
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("");
        let ok = keys
            .get(af_id)
            .is_some_and(|expected| ct_eq(presented.as_bytes(), expected.as_bytes()));
        if ok {
            Ok(())
        } else {
            tracing::warn!(%af_id, "NEF rejected an AF request: missing or invalid API key");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(crate::ProblemDetails {
                    status: Some(401),
                    title: Some("Unauthorized".into()),
                    cause: Some("UNAUTHORIZED".into()),
                    detail: Some("AF authentication failed".into()),
                    ..Default::default()
                }),
            )
                .into_response())
        }
    }

    /// Authorize the **content** of an AF request against the AF's SLA (design/137 F2): the
    /// authenticated AF may only influence DNNs/DNAIs/subscribers it is contracted for, and
    /// may only create network-wide group / any-UE influences if its SLA permits it. This is
    /// what stops an AF — even one holding a valid API key — from steering an arbitrary
    /// subscriber to an attacker-chosen edge or reprogramming routing network-wide.
    ///
    /// With no SLA map configured this is a no-op (authorization disabled — the dev default).
    /// With a map configured, enforcement is **deny-by-default**: an AF absent from the map is
    /// refused. Failures return `403` (authenticated but not authorized — distinct from the
    /// `401` of [`authorize_af`](Self::authorize_af)); the reason is echoed to the AF (which
    /// knows its own contract) and logged.
    fn authorize_request(
        &self,
        af_id: &str,
        sub: &TrafficInfluSub,
    ) -> Result<(), axum::response::Response> {
        let Some(slas) = &self.af_slas else {
            return Ok(()); // no SLAs configured — authorization disabled (dev)
        };
        let deny = |reason: &str| -> axum::response::Response {
            tracing::warn!(%af_id, reason, "NEF refused an AF request: outside SLA");
            (
                StatusCode::FORBIDDEN,
                Json(crate::ProblemDetails {
                    status: Some(403),
                    title: Some("Forbidden".into()),
                    cause: Some("AF_NOT_AUTHORIZED".into()),
                    detail: Some(format!("request outside AF SLA: {reason}")),
                    ..Default::default()
                }),
            )
                .into_response()
        };
        let Some(sla) = slas.get(af_id) else {
            return Err(deny("no SLA provisioned for this AF"));
        };
        if !sla.permits_dnn(sub.dnn.as_deref()) {
            return Err(deny("DNN not permitted"));
        }
        // Every route target must be in scope — not just the first one the handler applies.
        for route in &sub.traffic_routes {
            if !AfSla::permits(&sla.dnais, &route.dnai) {
                return Err(deny("DNAI not permitted"));
            }
        }
        // UE scope. A group / any-UE influence is the broadest verb, gated by `allow_group`;
        // a bounded group (explicit SUPIs, not any-UE) must additionally stay within scope.
        if sub.any_ue_ind || sub.external_group_id.is_some() {
            if !sla.allow_group {
                return Err(deny("group / any-UE influence not permitted"));
            }
            if !sub.any_ue_ind {
                for supi in &sub.supis {
                    if !sla.permits_supi(supi) {
                        return Err(deny("group member SUPI outside scope"));
                    }
                }
            }
        } else if sub.supi.as_deref().or(sub.gpsi.as_deref()).is_some_and(|t| !sla.permits_supi(t)) {
            return Err(deny("target SUPI outside scope"));
        }
        Ok(())
    }

    /// The SMF base URL — the explicit override, else NRF discovery.
    async fn smf_base(&self) -> Option<String> {
        self.peer_base(self.smf_base.as_ref(), "SMF").await
    }

    /// The PCF base URL — the explicit override, else NRF discovery. `None` ⇒ no PCF is
    /// deployed, so influences are applied straight at the SMF.
    async fn pcf_base(&self) -> Option<String> {
        self.peer_base(self.pcf_base.as_ref(), "PCF").await
    }

    /// The UDR base URL — the explicit override, else NRF discovery.
    async fn udr_base(&self) -> Option<String> {
        self.peer_base(self.udr_base.as_ref(), "UDR").await
    }

    async fn peer_base(&self, explicit: Option<&String>, nf_type: &str) -> Option<String> {
        if let Some(base) = explicit {
            return Some(base.clone());
        }
        let nrf = self.nrf_base.as_ref()?;
        crate::nnrf::NrfClient::new(nrf.clone())
            .discover(nf_type, "NEF")
            .await
            .ok()?
            .into_iter()
            .next()?
            .service_base()
    }

    fn record(&self, af_id: String, supi: String, dnn: Option<String>, applied: Applied) -> String {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("sub-{id}");
        inner.subs.insert(sub_id.clone(), Subscription { af_id, supi, dnn, applied });
        sub_id
    }

    /// Remove and return a subscription **only if `af_id` owns it**. A caller asking to
    /// delete an unknown subscription, or one owned by another AF, gets `None` (and the
    /// subscription is left untouched) — so a delete neither withdraws another AF's influence
    /// nor reveals that the id exists.
    fn take_owned(&self, sub_id: &str, af_id: &str) -> Option<Subscription> {
        let mut inner = self.inner.lock().unwrap();
        if inner.subs.get(sub_id).is_some_and(|s| s.af_id == af_id) {
            inner.subs.remove(sub_id)
        } else {
            None
        }
    }

    /// Number of live subscriptions (test/introspection).
    pub fn subscription_count(&self) -> usize {
        self.inner.lock().unwrap().subs.len()
    }
}

/// `Nnef_TrafficInfluence`: create + delete an AF traffic-influence subscription.
pub fn router(state: NefState) -> Router {
    Router::new()
        .route(
            "/3gpp-traffic-influence/v1/{af_id}/subscriptions",
            post(create_subscription),
        )
        .route(
            "/3gpp-traffic-influence/v1/{af_id}/subscriptions/{sub_id}",
            axum::routing::delete(delete_subscription),
        )
        .with_state(state)
}

/// The destination prefix an AF steers, from a `TrafficInfluSub`: a direct `prefix`, else
/// the destination CIDR of the first IPFilterRule flow description (`… to <cidr> …`).
fn steer_prefix(sub: &TrafficInfluSub) -> Option<String> {
    if let Some(p) = &sub.prefix {
        return Some(p.clone());
    }
    sub.traffic_filters
        .iter()
        .flat_map(|f| &f.flow_descriptions)
        .find_map(|d| dst_from_flow_description(d))
}

/// Extract the destination CIDR from an IPFilterRule (`permit out ip from <src> to <dst>
/// [ports]`) — the token after `to`, if it looks like a prefix (`a.b.c.d/len`).
fn dst_from_flow_description(desc: &str) -> Option<String> {
    let mut toks = desc.split_whitespace();
    while let Some(t) = toks.next() {
        if t == "to" {
            let dst = toks.next()?;
            return dst.contains('/').then(|| dst.to_string());
        }
    }
    None
}

/// Constant-time byte-slice equality — the AF API key must not be compared with an
/// early-exit `==` that leaks its bytes via timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

async fn create_subscription(
    State(nef): State<NefState>,
    Path(af_id): Path<String>,
    headers: HeaderMap,
    Json(sub): Json<TrafficInfluSub>,
) -> axum::response::Response {
    if let Err(resp) = nef.authorize_af(&af_id, &headers) {
        return resp;
    }
    // Authentication proved *who* the AF is; the SLA bounds *what* it may steer, before we
    // translate anything to the SMF/PCF/UDR (design/137 F2).
    if let Err(resp) = nef.authorize_request(&af_id, &sub) {
        return resp;
    }
    let Some(prefix) = steer_prefix(&sub) else {
        return (StatusCode::BAD_REQUEST, "no traffic prefix (prefix or a filter destination)")
            .into_response();
    };
    let Some(dnai) = sub.traffic_routes.first().map(|r| r.dnai.clone()) else {
        return (StatusCode::BAD_REQUEST, "no trafficRoutes[].dnai").into_response();
    };
    let single_ue = sub.supi.clone().or_else(|| sub.gpsi.clone());
    let group = sub.any_ue_ind || sub.external_group_id.is_some();

    // A **group / any-UE** influence isn't tied to one live session, so it is stored in the
    // UDR as application influence data (design/135 Phase 3): every PCF reads it when it
    // authorizes a session, so it applies to sessions established later too. A **single-UE**
    // influence targets a session that already exists, so it is authorized at the PCF
    // (Phase 2b) or, with no PCF, applied straight at the SMF (Phase 1). Either way the NEF
    // passes the DNAI through — the SMF resolves it to a UP node via its topology (§D2).
    let applied = if group {
        match nef.udr_base().await {
            Some(udr) => store_group_influence(&udr, &sub, &prefix, &dnai).await,
            None => Err("no UDR discovered for a group influence".to_string()),
        }
    } else {
        let Some(supi) = single_ue.clone() else {
            return (StatusCode::BAD_REQUEST, "no UE identity (supi/gpsi/anyUeInd/group)")
                .into_response();
        };
        match nef.pcf_base().await {
            Some(pcf) => authorize_at_pcf(&pcf, &supi, sub.dnn.as_deref(), &prefix, &dnai)
                .await
                .map(Applied::Pcf),
            None => match nef.smf_base().await {
                Some(smf) => steer_at_smf(&smf, &supi, sub.dnn.as_deref(), &prefix, &dnai)
                    .await
                    .map(|()| Applied::Smf),
                None => Err("no PCF or SMF discovered".to_string()),
            },
        }
    };
    match applied {
        Ok(applied) => {
            let sub_id =
                nef.record(af_id.clone(), single_ue.unwrap_or_default(), sub.dnn.clone(), applied.clone());
            let self_link = format!("/3gpp-traffic-influence/v1/{af_id}/subscriptions/{sub_id}");
            tracing::info!(%af_id, %sub_id, %prefix, %dnai, how = applied.label(), "AF traffic influence authorized");
            (
                StatusCode::CREATED,
                [(header::LOCATION, self_link.clone())],
                Json(SubCreated { self_link }),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, e).into_response(),
    }
}

/// Store a group / any-UE influence in the UDR as application influence data.
async fn store_group_influence(
    udr: &str,
    sub: &TrafficInfluSub,
    prefix: &str,
    dnai: &str,
) -> Result<Applied, String> {
    // A stable id derived from the AF's target, so re-submitting replaces rather than
    // duplicating (the UDR document is keyed by influence id).
    let influence_id = format!(
        "{}-{}",
        sub.external_group_id.as_deref().unwrap_or("any-ue"),
        prefix.replace(['.', '/', ':'], "_")
    );
    let doc = serde_json::json!({
        "dnn": sub.dnn,
        "anyUeInd": sub.any_ue_ind,
        "supis": sub.supis,
        "externalGroupId": sub.external_group_id,
        "routeToLocs": [{ "dnai": dnai }],
        "trafficPrefix": prefix,
    });
    crate::nudr::UdrClient::new(udr.to_string())
        .put_influence_data(&influence_id, &doc)
        .await
        .map_err(|e| format!("UDR influence-data store failed: {e}"))?;
    Ok(Applied::Udr(influence_id))
}

/// Authorize the influence at the PCF as an application session; returns its id.
async fn authorize_at_pcf(
    pcf: &str,
    supi: &str,
    dnn: Option<&str>,
    prefix: &str,
    dnai: &str,
) -> Result<String, String> {
    let body = serde_json::json!({ "ascReqData": {
        "supi": supi,
        "dnn": dnn,
        "afRoutReq": { "routeToLocs": [{ "dnai": dnai }] },
        "trafficPrefix": prefix,
    }});
    let resp = crate::sbi_client()
        .post(format!("{pcf}/npcf-policyauthorization/v1/app-sessions"))
        .json(&body)
        .traced()
        .send()
        .await
        .map_err(|e| format!("PCF unreachable: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("PCF refused the influence: {}", resp.status()));
    }
    // The app-session id is the last segment of the Location header.
    let id = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|loc| loc.rsplit('/').next())
        .unwrap_or_default()
        .to_string();
    Ok(id)
}

/// Drive the SMF's breakout trigger directly (no PCF deployed).
async fn steer_at_smf(
    smf: &str,
    supi: &str,
    dnn: Option<&str>,
    prefix: &str,
    dnai: &str,
) -> Result<(), String> {
    let body = serde_json::json!({ "supi": supi, "dnn": dnn, "prefix": prefix, "dnai": dnai });
    match crate::sbi_client().post(format!("{smf}/oam/v1/breakout")).json(&body).traced().send().await {
        Ok(r) if r.status().is_success() => Ok(()),
        Ok(r) => Err(format!("SMF refused the breakout: {}", r.status())),
        Err(e) => Err(format!("SMF unreachable: {e}")),
    }
}

async fn delete_subscription(
    State(nef): State<NefState>,
    Path((af_id, sub_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Err(resp) = nef.authorize_af(&af_id, &headers) {
        return resp;
    }
    // Idempotent, and scoped to the owner: an unknown subscription — or one belonging to a
    // different AF — is treated as already gone, so an AF can neither withdraw another's
    // influence nor probe for foreign subscription ids (design/137 F2).
    let Some(sub) = nef.take_owned(&sub_id, &af_id) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    // Withdraw the way it was authorized: delete the PCF app-session (the PCF drops the
    // route from the policy and re-authorizes the SMF), delete the UDR influence data (a
    // group influence — it then no longer applies to sessions authorized after this), or
    // remove at the SMF directly.
    match &sub.applied {
        Applied::Pcf(app_session) => {
            let Some(pcf) = nef.pcf_base().await else {
                return (StatusCode::BAD_GATEWAY, "no PCF discovered").into_response();
            };
            let url = format!("{pcf}/npcf-policyauthorization/v1/app-sessions/{app_session}");
            let _ = crate::sbi_client().delete(url).traced().send().await;
        }
        Applied::Udr(influence_id) => {
            let Some(udr) = nef.udr_base().await else {
                return (StatusCode::BAD_GATEWAY, "no UDR discovered").into_response();
            };
            let _ = crate::nudr::UdrClient::new(udr).delete_influence_data(influence_id).await;
        }
        Applied::Smf => {
            let Some(smf) = nef.smf_base().await else {
                return (StatusCode::BAD_GATEWAY, "no SMF discovered").into_response();
            };
            let body = serde_json::json!({ "supi": sub.supi, "dnn": sub.dnn, "remove": true });
            let _ =
                crate::sbi_client().post(format!("{smf}/oam/v1/breakout")).json(&body).traced().send().await;
        }
    }
    tracing::info!(%sub_id, how = sub.applied.label(), "AF traffic influence withdrawn");
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_destination_prefix() {
        // A direct prefix wins; else the IPFilterRule destination is used.
        let direct = TrafficInfluSub { prefix: Some("10.99.0.0/16".into()), ..Default::default() };
        assert_eq!(steer_prefix(&direct).as_deref(), Some("10.99.0.0/16"));

        let filtered = TrafficInfluSub {
            traffic_filters: vec![FlowInfo {
                flow_descriptions: vec!["permit out ip from 10.0.0.0/8 to 10.60.0.0/16".into()],
            }],
            ..Default::default()
        };
        assert_eq!(steer_prefix(&filtered).as_deref(), Some("10.60.0.0/16"));

        // A rule with no CIDR destination yields nothing.
        let vague = TrafficInfluSub {
            traffic_filters: vec![FlowInfo {
                flow_descriptions: vec!["permit out ip from any to any".into()],
            }],
            ..Default::default()
        };
        assert_eq!(steer_prefix(&vague), None);
    }

    /// The NEF translates an AF subscription into the SMF's breakout trigger, and a delete
    /// reverses it — verified against a mock SMF that records the bodies it receives.
    #[tokio::test]
    async fn af_subscription_drives_the_smf_breakout_trigger() {
        use axum::routing::post;

        // A mock SMF recording every /oam/v1/breakout body.
        let recorder: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let rec = recorder.clone();
        let smf = Router::new()
            .route(
                "/oam/v1/breakout",
                post(|axum::extract::State(rec): axum::extract::State<Arc<Mutex<Vec<serde_json::Value>>>>,
                      Json(b): Json<serde_json::Value>| async move {
                    rec.lock().unwrap().push(b);
                    StatusCode::OK
                }),
            )
            .with_state(rec);
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(smf_l, smf).await.unwrap() });

        let nef = NefState::with_smf_base(format!("http://{smf_addr}"));
        let nef_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nef_addr = nef_l.local_addr().unwrap();
        let served = nef.clone();
        tokio::spawn(async move { crate::run_on(nef_l, router(served)).await.unwrap() });

        let client = crate::sbi_client();
        let base = format!("http://{nef_addr}/3gpp-traffic-influence/v1/af1/subscriptions");
        // AF POSTs an influence subscription: UE by supi, on "internet", to the "mec" DNAI.
        let created = client
            .post(&base)
            .json(&serde_json::json!({
                "supi": "imsi-1", "dnn": "internet",
                "trafficFilters": [{ "flowDescriptions": ["permit out ip from 10.0.0.0/8 to 10.99.0.0/16"] }],
                "trafficRoutes": [{ "dnai": "mec" }]
            }))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let self_link = created.headers().get("location").unwrap().to_str().unwrap().to_string();
        assert_eq!(nef.subscription_count(), 1);

        // The SMF saw a breakout insert with the translated fields.
        {
            let seen = recorder.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0]["supi"], "imsi-1");
            assert_eq!(seen[0]["dnn"], "internet");
            assert_eq!(seen[0]["prefix"], "10.99.0.0/16");
            assert_eq!(seen[0]["dnai"], "mec");
        }

        // Delete the subscription → the SMF sees a remove for the same UE/DNN.
        let del = client.delete(format!("http://{nef_addr}{self_link}")).traced().send().await.unwrap();
        assert_eq!(del.status(), StatusCode::NO_CONTENT);
        assert_eq!(nef.subscription_count(), 0);
        let seen = recorder.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1]["supi"], "imsi-1");
        assert_eq!(seen[1]["dnn"], "internet");
        assert_eq!(seen[1]["remove"], true);
    }

    /// A mock SMF recording every `/oam/v1/breakout` body; returns its base URL and the buffer.
    async fn spawn_mock_smf() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
        use axum::routing::post;
        let recorder: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let rec = recorder.clone();
        let smf = Router::new()
            .route(
                "/oam/v1/breakout",
                post(
                    |State(rec): State<Arc<Mutex<Vec<serde_json::Value>>>>,
                     Json(b): Json<serde_json::Value>| async move {
                        rec.lock().unwrap().push(b);
                        StatusCode::OK
                    },
                ),
            )
            .with_state(rec);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(l, smf).await.unwrap() });
        (format!("http://{addr}"), recorder)
    }

    /// Serve `state` as a NEF; returns its base URL.
    async fn spawn_nef(state: NefState) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { crate::run_on(l, router(state)).await.unwrap() });
        format!("http://{addr}")
    }

    /// A minimal single-UE influence body, targeting `supi`/`dnn` and steering to `dnai`.
    fn influence(supi: &str, dnn: &str, dnai: &str) -> serde_json::Value {
        serde_json::json!({
            "supi": supi, "dnn": dnn, "prefix": "10.99.0.0/16",
            "trafficRoutes": [{ "dnai": dnai }]
        })
    }

    /// The `RADIAN_NEF_AF_SLA` grammar parses per-AF scopes, with `*` = any and empty = none;
    /// malformed entries are skipped.
    #[test]
    fn parse_af_slas_reads_the_env_grammar() {
        let map = parse_af_slas("app1|internet,ims|mec,edge1|imsi-99970|no;app2|*|edge2|*|yes");
        assert_eq!(map.len(), 2);

        let a1 = &map["app1"];
        assert!(a1.permits_dnn(Some("internet")) && a1.permits_dnn(Some("ims")));
        assert!(!a1.permits_dnn(Some("operator")));
        assert!(!a1.permits_dnn(None), "a bare DNN needs a wildcard grant");
        assert!(AfSla::permits(&a1.dnais, "mec") && AfSla::permits(&a1.dnais, "edge1"));
        assert!(!AfSla::permits(&a1.dnais, "edge2"));
        assert!(a1.permits_supi("imsi-999700000000001"), "IMSI prefix match");
        assert!(!a1.permits_supi("imsi-001010000000001"));
        assert!(!a1.allow_group);

        let a2 = &map["app2"];
        assert!(a2.permits_dnn(Some("anything")) && a2.permits_dnn(None), "wildcard DNN");
        assert!(a2.permits_supi("imsi-anything"), "wildcard SUPI");
        assert!(!AfSla::permits(&a2.dnais, "mec"), "app2 is scoped to edge2 only");
        assert!(a2.allow_group);

        // Too few fields, or an empty id, are skipped rather than half-parsed.
        assert!(parse_af_slas("bad|only|three").is_empty());
        assert!(parse_af_slas("|a|b|c|yes").is_empty());
    }

    /// design/137 F2 (authentication): with per-AF keys configured, the NEF refuses a request
    /// that carries no key, a wrong key, or another AF's key reused under a foreign `af_id`;
    /// the AF's own key on its own path is accepted.
    #[tokio::test]
    async fn api_key_authenticates_the_af() {
        let (smf, _rec) = spawn_mock_smf().await;
        let nef = NefState::with_smf_base(smf)
            .with_af_keys(HashMap::from([("app1".to_string(), "s3cret-key".to_string())]));
        let base = spawn_nef(nef.clone()).await;
        let client = crate::sbi_client();
        let url = format!("{base}/3gpp-traffic-influence/v1/app1/subscriptions");
        let body = influence("imsi-1", "internet", "mec");

        // No Authorization header → 401.
        let anon = client.post(&url).json(&body).traced().send().await.unwrap();
        assert_eq!(anon.status(), StatusCode::UNAUTHORIZED, "a keyless request is rejected");

        // Wrong key → 401.
        let wrong =
            client.post(&url).bearer_auth("nope").json(&body).traced().send().await.unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        // app1's key presented under app2's path → 401: a key can't be reused under another id.
        let cross = format!("{base}/3gpp-traffic-influence/v1/app2/subscriptions");
        let reused =
            client.post(&cross).bearer_auth("s3cret-key").json(&body).traced().send().await.unwrap();
        assert_eq!(reused.status(), StatusCode::UNAUTHORIZED, "a key is bound to its af_id");

        // The right key on the right path → accepted.
        let ok =
            client.post(&url).bearer_auth("s3cret-key").json(&body).traced().send().await.unwrap();
        assert_eq!(ok.status(), StatusCode::CREATED);
        assert_eq!(nef.subscription_count(), 1);
    }

    /// design/137 F2 (authorization): a per-AF SLA confines an authenticated AF to the DNN,
    /// DNAI, subscriber, and group scope it is contracted for — every out-of-scope request is
    /// refused `403` and never reaches the SMF, and an AF with no SLA at all is denied.
    #[tokio::test]
    async fn sla_confines_an_af_to_its_contracted_scope() {
        let (smf, rec) = spawn_mock_smf().await;
        let sla = AfSla {
            dnns: ["internet"].into_iter().map(String::from).collect(),
            dnais: ["mec"].into_iter().map(String::from).collect(),
            supis: ["imsi-9997"].into_iter().map(String::from).collect(),
            allow_group: false,
        };
        let nef = NefState::with_smf_base(smf)
            .with_af_slas(HashMap::from([("app1".to_string(), sla)]));
        let base = spawn_nef(nef.clone()).await;
        let client = crate::sbi_client();
        let url = format!("{base}/3gpp-traffic-influence/v1/app1/subscriptions");

        // In scope: DNN internet, DNAI mec, an imsi-9997… subscriber → created, reaches the SMF.
        let ok = client
            .post(&url)
            .json(&influence("imsi-999700000000001", "internet", "mec"))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::CREATED);
        assert_eq!(rec.lock().unwrap().len(), 1, "the in-scope influence reached the SMF");

        // Each out-of-scope dimension is refused with 403.
        let cases = [
            (influence("imsi-999700000000001", "internet", "attacker-edge"), "DNAI"),
            (influence("imsi-999700000000001", "ims", "mec"), "DNN"),
            (influence("imsi-001010000000001", "internet", "mec"), "SUPI"),
            (
                serde_json::json!({
                    "anyUeInd": true, "dnn": "internet", "prefix": "10.99.0.0/16",
                    "trafficRoutes": [{ "dnai": "mec" }]
                }),
                "any-UE",
            ),
        ];
        for (body, which) in cases {
            let resp = client.post(&url).json(&body).traced().send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{which} out of scope must be 403");
        }

        // An AF with no SLA entry is denied outright (deny-by-default).
        let other = format!("{base}/3gpp-traffic-influence/v1/app2/subscriptions");
        let no_sla = client
            .post(&other)
            .json(&influence("imsi-999700000000001", "internet", "mec"))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(no_sla.status(), StatusCode::FORBIDDEN, "an AF with no SLA is refused");

        // Only the single in-scope influence was ever translated to the SMF.
        assert_eq!(rec.lock().unwrap().len(), 1, "no denied influence reached the SMF");
        assert_eq!(nef.subscription_count(), 1);
    }

    /// design/137 F2: a subscription is owned by the AF that created it — another AF's delete
    /// is a no-op (and non-revealing), only the owner can withdraw it.
    #[tokio::test]
    async fn an_af_cannot_delete_another_afs_subscription() {
        let (smf, _rec) = spawn_mock_smf().await;
        let nef = NefState::with_smf_base(smf); // ownership holds even with auth/authz off
        let base = spawn_nef(nef.clone()).await;
        let client = crate::sbi_client();

        // app1 creates a subscription.
        let created = client
            .post(format!("{base}/3gpp-traffic-influence/v1/app1/subscriptions"))
            .json(&influence("imsi-1", "internet", "mec"))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let self_link =
            created.headers().get("location").unwrap().to_str().unwrap().to_string();
        let sub_id = self_link.rsplit('/').next().unwrap();
        assert_eq!(nef.subscription_count(), 1);

        // app2 tries to delete it by id → 204, but nothing is withdrawn.
        let foreign = client
            .delete(format!("{base}/3gpp-traffic-influence/v1/app2/subscriptions/{sub_id}"))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::NO_CONTENT);
        assert_eq!(nef.subscription_count(), 1, "a foreign delete must not withdraw the influence");

        // The owner deletes it → gone.
        let owner =
            client.delete(format!("{base}{self_link}")).traced().send().await.unwrap();
        assert_eq!(owner.status(), StatusCode::NO_CONTENT);
        assert_eq!(nef.subscription_count(), 0);
    }
}
