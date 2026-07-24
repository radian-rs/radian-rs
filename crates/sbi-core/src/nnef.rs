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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
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
    supi: String,
    dnn: Option<String>,
    applied: Applied,
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
            inner: Arc::new(Mutex::new(Inner {
                next_id: AtomicU64::new(1),
                subs: HashMap::new(),
            })),
        }
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

    fn record(&self, supi: String, dnn: Option<String>, applied: Applied) -> String {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("sub-{id}");
        inner.subs.insert(sub_id.clone(), Subscription { supi, dnn, applied });
        sub_id
    }

    fn take(&self, sub_id: &str) -> Option<Subscription> {
        self.inner.lock().unwrap().subs.remove(sub_id)
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

async fn create_subscription(
    State(nef): State<NefState>,
    Path(af_id): Path<String>,
    Json(sub): Json<TrafficInfluSub>,
) -> axum::response::Response {
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
            let sub_id = nef.record(single_ue.unwrap_or_default(), sub.dnn.clone(), applied.clone());
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
    match crate::sbi_client().post(format!("{smf}/oam/v1/breakout")).json(&body).send().await {
        Ok(r) if r.status().is_success() => Ok(()),
        Ok(r) => Err(format!("SMF refused the breakout: {}", r.status())),
        Err(e) => Err(format!("SMF unreachable: {e}")),
    }
}

async fn delete_subscription(
    State(nef): State<NefState>,
    Path((_af_id, sub_id)): Path<(String, String)>,
) -> axum::response::Response {
    // Idempotent: an unknown subscription is already gone.
    let Some(sub) = nef.take(&sub_id) else {
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
            let _ = crate::sbi_client().delete(url).send().await;
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
                crate::sbi_client().post(format!("{smf}/oam/v1/breakout")).json(&body).send().await;
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
        let del = client.delete(format!("http://{nef_addr}{self_link}")).send().await.unwrap();
        assert_eq!(del.status(), StatusCode::NO_CONTENT);
        assert_eq!(nef.subscription_count(), 0);
        let seen = recorder.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1]["supi"], "imsi-1");
        assert_eq!(seen[1]["dnn"], "internet");
        assert_eq!(seen[1]["remove"], true);
    }
}
