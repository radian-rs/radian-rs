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

/// What a live subscription steers, remembered so a delete can reverse it.
struct Subscription {
    supi: String,
    dnn: Option<String>,
}

/// NEF runtime: how to reach the SMF, plus the live subscriptions.
#[derive(Clone)]
pub struct NefState {
    /// NRF base for discovering the SMF; `None` when an explicit SMF base is set.
    nrf_base: Option<String>,
    /// An explicit SMF base URL, overriding discovery (an env escape hatch / tests).
    smf_base: Option<String>,
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    next_id: AtomicU64,
    subs: HashMap<String, Subscription>,
}

impl NefState {
    /// Discover the SMF via the NRF at `nrf_base`.
    pub fn new(nrf_base: impl Into<String>) -> Self {
        Self::build(Some(nrf_base.into()), None)
    }

    /// Reach the SMF at an explicit base URL, bypassing NRF discovery (deployments without
    /// an NRF, or tests).
    pub fn with_smf_base(smf_base: impl Into<String>) -> Self {
        Self::build(None, Some(smf_base.into()))
    }

    fn build(nrf_base: Option<String>, smf_base: Option<String>) -> Self {
        Self {
            nrf_base,
            smf_base,
            inner: Arc::new(Mutex::new(Inner {
                next_id: AtomicU64::new(1),
                subs: HashMap::new(),
            })),
        }
    }

    /// The SMF base URL — the explicit override, else NRF discovery.
    async fn smf_base(&self) -> Option<String> {
        if let Some(base) = &self.smf_base {
            return Some(base.clone());
        }
        let nrf = self.nrf_base.as_ref()?;
        crate::nnrf::NrfClient::new(nrf.clone())
            .discover("SMF", "NEF")
            .await
            .ok()?
            .into_iter()
            .next()?
            .service_base()
    }

    fn record(&self, supi: String, dnn: Option<String>) -> String {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("sub-{id}");
        inner.subs.insert(sub_id.clone(), Subscription { supi, dnn });
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
    let Some(supi) = sub.supi.clone().or_else(|| sub.gpsi.clone()) else {
        return (StatusCode::BAD_REQUEST, "no UE identity (supi/gpsi)").into_response();
    };
    let Some(prefix) = steer_prefix(&sub) else {
        return (StatusCode::BAD_REQUEST, "no traffic prefix (prefix or a filter destination)")
            .into_response();
    };
    let Some(dnai) = sub.traffic_routes.first().map(|r| r.dnai.clone()) else {
        return (StatusCode::BAD_REQUEST, "no trafficRoutes[].dnai").into_response();
    };
    let Some(smf) = nef.smf_base().await else {
        return (StatusCode::BAD_GATEWAY, "no SMF discovered").into_response();
    };

    // Drive the SMF's breakout trigger. The NEF passes the DNAI through — the SMF resolves
    // it to a UP node via its topology (design/135 D2).
    let body = serde_json::json!({ "supi": supi, "dnn": sub.dnn, "prefix": prefix, "dnai": dnai });
    match crate::sbi_client().post(format!("{smf}/oam/v1/breakout")).json(&body).send().await {
        Ok(r) if r.status().is_success() => {
            let sub_id = nef.record(supi, sub.dnn.clone());
            let self_link =
                format!("/3gpp-traffic-influence/v1/{af_id}/subscriptions/{sub_id}");
            tracing::info!(%af_id, %sub_id, %prefix, %dnai, "AF traffic influence: breakout inserted");
            (
                StatusCode::CREATED,
                [(header::LOCATION, self_link.clone())],
                Json(SubCreated { self_link }),
            )
                .into_response()
        }
        Ok(r) => (StatusCode::BAD_GATEWAY, format!("SMF refused the breakout: {}", r.status()))
            .into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("SMF unreachable: {e}")).into_response(),
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
    let Some(smf) = nef.smf_base().await else {
        return (StatusCode::BAD_GATEWAY, "no SMF discovered").into_response();
    };
    let body = serde_json::json!({ "supi": sub.supi, "dnn": sub.dnn, "remove": true });
    let _ = crate::sbi_client().post(format!("{smf}/oam/v1/breakout")).json(&body).send().await;
    tracing::info!(%sub_id, "AF traffic influence: breakout removed");
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
