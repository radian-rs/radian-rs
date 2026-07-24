//! `Nnssf` — Network Slice Selection (TS 29.531), the NSSF's service surface.
//!
//! Two services:
//!
//! - **Nnssf_NSSelection** — the AMF asks which of a UE's requested slices it may
//!   grant, given the subscription *and the UE's tracking area*. The answer differs
//!   from a plain `requested ∩ subscribed` intersection exactly when a subscribed
//!   slice is **not deployed in that TA** — the capability an AMF-local check
//!   structurally cannot provide (design/133).
//! - **Nnssf_NSSAIAvailability** — publishes/updates which slices each tracking area
//!   supports, so the availability table is dynamic rather than a compile-time list.
//!
//! Encoding note (design/133 D4): TS 29.531 models NSSelection as a `GET` with deeply
//! nested query parameters. This stack uses `POST` + a JSON body — the same
//! simplification `Nsmf_PDUSession` already makes. The semantics follow the spec.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::SbiError;

/// An S-NSSAI on the wire: SST plus an optional 3-byte SD as lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snssai {
    pub sst: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd: Option<String>,
}

/// Hex-encode a 3-byte slice differentiator.
fn sd_to_hex(sd: [u8; 3]) -> String {
    format!("{:02x}{:02x}{:02x}", sd[0], sd[1], sd[2])
}

/// Decode a 6-char lowercase-hex slice differentiator.
fn sd_from_hex(s: &str) -> Option<[u8; 3]> {
    if s.len() != 6 {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(s.get(i..i + 2)?, 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

impl Snssai {
    /// From the `(SST, optional SD)` form the AMF and NGAP use.
    pub fn from_parts(sst: u8, sd: Option<[u8; 3]>) -> Self {
        Self { sst, sd: sd.map(sd_to_hex) }
    }

    /// Back to `(SST, optional SD)`. `None` if the SD is present but malformed.
    pub fn to_parts(&self) -> Option<(u8, Option<[u8; 3]>)> {
        match &self.sd {
            Some(sd) => Some((self.sst, Some(sd_from_hex(sd)?))),
            None => Some((self.sst, None)),
        }
    }
}

/// An `Nnssf_NSSelection` request: what the UE asked for, what it is subscribed to,
/// and where it is (the tracking area availability is evaluated against).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NsSelectionRequest {
    /// The requesting NF type — `AMF` in practice.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nf_type: String,
    /// The UE's current tracking area code (lowercase hex). Absent ⇒ availability is
    /// not constrained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tac: Option<String>,
    /// What the UE requested. Empty ⇒ grant the subscribed default.
    #[serde(default)]
    pub requested: Vec<Snssai>,
    /// What the subscription permits — subscription stays authoritative.
    #[serde(default)]
    pub subscribed: Vec<Snssai>,
}

/// The slice decision: what the UE may use, and what it asked for but cannot have.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NsSelectionResponse {
    #[serde(default)]
    pub allowed_nssai: Vec<Snssai>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_nssai: Vec<Snssai>,
}

/// The slices one tracking area supports (an `Nnssf_NSSAIAvailability` entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaAvailability {
    /// Tracking area code, lowercase hex.
    pub tac: String,
    pub supported_snssai_list: Vec<Snssai>,
}

/// The NSSF's starting per-TA availability table.
#[derive(Debug, Clone, Default)]
pub struct NssfConfig {
    per_tac: BTreeMap<String, Vec<Snssai>>,
}

impl NssfConfig {
    /// An empty table — every tracking area supports every subscribed slice.
    pub fn permissive() -> Self {
        Self::default()
    }

    /// The demo deployment. The tracking areas the demo gNB serves (`000001`,
    /// `000002`) deploy the subscribed default slice, so the NSSF's answer there
    /// matches the AMF's old local intersection exactly — existing slicing behaviour
    /// is preserved. `000007` is a tracking area where **no slice is deployed**: a UE
    /// registering there is refused even a slice it *is* subscribed to, which an
    /// AMF-local intersection would have wrongly allowed (design/133).
    pub fn demo() -> Self {
        let default_slice = Snssai::from_parts(1, Some([0x01, 0x02, 0x03]));
        let mut per_tac = BTreeMap::new();
        per_tac.insert("000001".to_string(), vec![default_slice.clone()]);
        per_tac.insert("000002".to_string(), vec![default_slice]);
        per_tac.insert("000007".to_string(), Vec::new());
        Self { per_tac }
    }
}

/// The NSSF's runtime: the per-TA availability table, mutable via
/// `Nnssf_NSSAIAvailability`.
#[derive(Clone)]
pub struct NssfState {
    availability: Arc<Mutex<BTreeMap<String, Vec<Snssai>>>>,
}

impl NssfState {
    pub fn new(config: NssfConfig) -> Self {
        Self { availability: Arc::new(Mutex::new(config.per_tac)) }
    }

    /// Decide the allowed/rejected NSSAI. A slice is granted when it is **subscribed**
    /// *and* **available in the UE's tracking area**. A tracking area with no
    /// provisioned entry supports everything (fail-open: an unprovisioned TA must not
    /// silently black-hole slicing).
    pub fn select(&self, req: &NsSelectionRequest) -> NsSelectionResponse {
        let table = self.availability.lock().unwrap();
        let supported = req.tac.as_deref().and_then(|tac| table.get(tac)).cloned();
        let available = |s: &Snssai| supported.as_ref().is_none_or(|list| list.contains(s));

        // The UE requested nothing: grant the subscribed default, still filtered by
        // what this tracking area actually deploys. Nothing is "rejected" — it asked
        // for nothing.
        if req.requested.is_empty() {
            return NsSelectionResponse {
                allowed_nssai: req.subscribed.iter().filter(|s| available(s)).cloned().collect(),
                rejected_nssai: Vec::new(),
            };
        }
        let (allowed_nssai, rejected_nssai) = req
            .requested
            .iter()
            .cloned()
            .partition(|s| req.subscribed.contains(s) && available(s));
        NsSelectionResponse { allowed_nssai, rejected_nssai }
    }

    /// Replace the supported slices for the given tracking areas.
    pub fn set_availability(&self, tas: &[TaAvailability]) {
        let mut table = self.availability.lock().unwrap();
        for ta in tas {
            table.insert(ta.tac.clone(), ta.supported_snssai_list.clone());
        }
    }

    /// The current table, as availability entries (test / observability hook).
    pub fn availability(&self) -> Vec<TaAvailability> {
        self.availability
            .lock()
            .unwrap()
            .iter()
            .map(|(tac, list)| TaAvailability { tac: tac.clone(), supported_snssai_list: list.clone() })
            .collect()
    }
}

/// The `Nnssf_NSSelection` + `Nnssf_NSSAIAvailability` router (TS 29.531).
pub fn router(state: NssfState) -> Router {
    Router::new()
        .route("/nnssf-nsselection/v2/network-slice-information", post(ns_selection))
        .route(
            "/nnssf-nssaiavailability/v1/nssai-availability/{nf_id}",
            put(put_availability).get(get_availability),
        )
        .with_state(state)
}

async fn ns_selection(
    State(state): State<NssfState>,
    Json(req): Json<NsSelectionRequest>,
) -> Json<NsSelectionResponse> {
    let decision = state.select(&req);
    tracing::info!(
        tac = ?req.tac,
        requested = req.requested.len(),
        allowed = decision.allowed_nssai.len(),
        rejected = decision.rejected_nssai.len(),
        "Nnssf_NSSelection"
    );
    Json(decision)
}

async fn put_availability(
    State(state): State<NssfState>,
    Path(nf_id): Path<String>,
    Json(tas): Json<Vec<TaAvailability>>,
) -> StatusCode {
    state.set_availability(&tas);
    tracing::info!(%nf_id, tas = tas.len(), "Nnssf_NSSAIAvailability updated");
    StatusCode::NO_CONTENT
}

async fn get_availability(
    State(state): State<NssfState>,
    Path(_nf_id): Path<String>,
) -> Json<Vec<TaAvailability>> {
    Json(state.availability())
}

/// Client the AMF uses to reach the NSSF.
pub struct NssfClient {
    base: String,
    http: reqwest::Client,
}

impl NssfClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into(), http: crate::sbi_client() }
    }

    /// Ask which of `requested` the UE may be granted in tracking area `tac`, given
    /// `subscribed`. Returns `(allowed, rejected)` in the AMF's `(SST, SD)` form.
    #[allow(clippy::type_complexity)]
    pub async fn ns_selection(
        &self,
        tac: Option<[u8; 3]>,
        requested: &[(u8, Option<[u8; 3]>)],
        subscribed: &[(u8, Option<[u8; 3]>)],
    ) -> Result<(Vec<(u8, Option<[u8; 3]>)>, Vec<(u8, Option<[u8; 3]>)>), SbiError> {
        let to_wire =
            |v: &[(u8, Option<[u8; 3]>)]| v.iter().map(|(sst, sd)| Snssai::from_parts(*sst, *sd)).collect();
        let req = NsSelectionRequest {
            nf_type: "AMF".into(),
            tac: tac.map(sd_to_hex),
            requested: to_wire(requested),
            subscribed: to_wire(subscribed),
        };
        let resp: NsSelectionResponse = self
            .http
            .post(format!("{}/nnssf-nsselection/v2/network-slice-information", self.base))
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let from_wire = |v: Vec<Snssai>| v.iter().filter_map(Snssai::to_parts).collect();
        Ok((from_wire(resp.allowed_nssai), from_wire(resp.rejected_nssai)))
    }

    /// Publish the slices a set of tracking areas supports.
    pub async fn put_availability(&self, nf_id: &str, tas: &[TaAvailability]) -> Result<(), SbiError> {
        self.http
            .put(format!("{}/nnssf-nssaiavailability/v1/nssai-availability/{nf_id}", self.base))
            .json(tas)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn serve(config: NssfConfig) -> (NssfState, NssfClient) {
        let state = NssfState::new(config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = router(state.clone());
        tokio::spawn(async move { crate::run_on(listener, router).await.unwrap() });
        (state, NssfClient::new(format!("http://{addr}")))
    }

    const SLICE1: (u8, Option<[u8; 3]>) = (1, Some([0x01, 0x02, 0x03]));
    const SLICE2: (u8, Option<[u8; 3]>) = (2, None);
    const TAC1: [u8; 3] = [0, 0, 1];
    const TAC2: [u8; 3] = [0, 0, 2];

    #[test]
    fn snssai_parts_round_trip() {
        let s = Snssai::from_parts(1, Some([0x01, 0x02, 0x03]));
        assert_eq!(s.sd.as_deref(), Some("010203"));
        assert_eq!(s.to_parts(), Some(SLICE1));
        assert_eq!(Snssai::from_parts(2, None).to_parts(), Some(SLICE2));
        assert_eq!(sd_from_hex("nothex"), None, "malformed SD is rejected");
    }

    /// The capability that justifies the NF: a slice that is subscribed but not
    /// deployed in the UE's tracking area is rejected — an AMF-local intersection
    /// would have allowed it (design/133).
    #[tokio::test]
    async fn per_ta_availability_rejects_a_subscribed_but_undeployed_slice() {
        let (state, nssf) = serve(NssfConfig::permissive()).await;
        // TAC 000001 deploys both slices; TAC 000002 only slice 1.
        state.set_availability(&[
            TaAvailability {
                tac: "000001".into(),
                supported_snssai_list: vec![
                    Snssai::from_parts(1, Some([1, 2, 3])),
                    Snssai::from_parts(2, None),
                ],
            },
            TaAvailability {
                tac: "000002".into(),
                supported_snssai_list: vec![Snssai::from_parts(1, Some([1, 2, 3]))],
            },
        ]);
        let subscribed = [SLICE1, SLICE2];

        let (allowed, rejected) =
            nssf.ns_selection(Some(TAC1), &[SLICE1, SLICE2], &subscribed).await.expect("select");
        assert_eq!(allowed, vec![SLICE1, SLICE2], "both deployed here");
        assert!(rejected.is_empty());

        let (allowed, rejected) =
            nssf.ns_selection(Some(TAC2), &[SLICE1, SLICE2], &subscribed).await.expect("select");
        assert_eq!(allowed, vec![SLICE1], "only the deployed slice is granted");
        assert_eq!(rejected, vec![SLICE2], "subscribed but not available in this TA");
    }

    /// The demo table preserves existing behaviour in the TAs the demo gNB serves,
    /// and denies everything in the undeployed one.
    #[tokio::test]
    async fn demo_table_preserves_served_tas_and_denies_the_undeployed_one() {
        let (_state, nssf) = serve(NssfConfig::demo()).await;
        for tac in [TAC1, TAC2] {
            let (allowed, rejected) =
                nssf.ns_selection(Some(tac), &[SLICE1], &[SLICE1]).await.expect("select");
            assert_eq!(allowed, vec![SLICE1], "the served TAs deploy the subscribed slice");
            assert!(rejected.is_empty());
        }
        // TAC 000007 deploys nothing: even a subscribed slice is refused.
        let (allowed, rejected) =
            nssf.ns_selection(Some([0, 0, 7]), &[SLICE1], &[SLICE1]).await.expect("select");
        assert!(allowed.is_empty(), "no slice is deployed in this tracking area");
        assert_eq!(rejected, vec![SLICE1], "subscribed, but unavailable here");
    }

    #[tokio::test]
    async fn subscription_stays_authoritative_and_empty_request_takes_the_default() {
        let (_state, nssf) = serve(NssfConfig::demo()).await;

        // Available in the TA but NOT subscribed → still rejected.
        let (allowed, rejected) =
            nssf.ns_selection(Some(TAC1), &[SLICE2], &[SLICE1]).await.expect("select");
        assert!(allowed.is_empty());
        assert_eq!(rejected, vec![SLICE2]);

        // No requested NSSAI → the subscribed set, filtered by availability, nothing
        // rejected (the UE asked for nothing).
        let (allowed, rejected) =
            nssf.ns_selection(Some(TAC1), &[], &[SLICE1, SLICE2]).await.expect("select");
        assert_eq!(allowed, vec![SLICE1], "slice 2 is not deployed in this TA");
        assert!(rejected.is_empty());

        // An unprovisioned TA supports everything (fail-open).
        let (allowed, _) =
            nssf.ns_selection(Some([9, 9, 9]), &[SLICE2], &[SLICE2]).await.expect("select");
        assert_eq!(allowed, vec![SLICE2]);
    }

    #[tokio::test]
    async fn nssai_availability_updates_the_table() {
        let (_state, nssf) = serve(NssfConfig::permissive()).await;
        // Permissive to start: slice 2 is granted anywhere.
        let (allowed, _) = nssf.ns_selection(Some(TAC2), &[SLICE2], &[SLICE2]).await.unwrap();
        assert_eq!(allowed, vec![SLICE2]);

        // Publish an availability entry that excludes it from TAC 000002.
        nssf.put_availability(
            "gnb-1",
            &[TaAvailability {
                tac: "000002".into(),
                supported_snssai_list: vec![Snssai::from_parts(1, Some([1, 2, 3]))],
            }],
        )
        .await
        .expect("put availability");

        let (allowed, rejected) = nssf.ns_selection(Some(TAC2), &[SLICE2], &[SLICE2]).await.unwrap();
        assert!(allowed.is_empty(), "the update took effect");
        assert_eq!(rejected, vec![SLICE2]);
    }
}
