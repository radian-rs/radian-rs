//! Nchf_ConvergedCharging — the CHF's charging service (TS 32.290 / 32.291),
//! trimmed to the converged-charging session lifecycle this core drives:
//!
//! - **Create** — the SMF (as CTF) opens a charging data session at PDU-session
//!   establishment; the CHF opens a CDR and returns its resource id.
//! - **Update** — mid-session usage (a UPF volume-threshold report relayed by the
//!   SMF) appends a used-unit container to the CDR.
//! - **Release** — session teardown carries the final usage; the CDR closes.
//!
//! The CDR store is in-memory (the CHF analogue of the NRF's registry); real
//! quota management (granted units, Requested-Service-Unit) and CDR export are
//! deferred. Rating-group convention: **0** is session-level (non-flow) traffic,
//! a non-zero value is the QoS flow's QFI.

use crate::otel::Traced;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::SbiError;

/// One used-unit container (TS 32.291 §6.1.6.2.24, trimmed): the volume **and packet
/// count** consumed under one rating group since the previous report. The UPF measures
/// both (design/155, G18); packet counts default to `0` for a peer that omits them.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsedUnitContainer {
    /// `0` = session-level (non-flow) traffic; otherwise the QoS flow's QFI.
    pub rating_group: u32,
    pub uplink_volume: u64,
    pub downlink_volume: u64,
    pub total_volume: u64,
    #[serde(default)]
    pub uplink_packets: u64,
    #[serde(default)]
    pub downlink_packets: u64,
    #[serde(default)]
    pub total_packets: u64,
}

/// PDU-session identity on a charging session (TS 32.291, trimmed).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionChargingInformation {
    pub pdu_session_id: u8,
    pub dnn: String,
}

/// `ChargingDataRequest` — the body of create/update/release alike (usage empty
/// on create).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingDataRequest {
    pub subscriber_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdu_session_charging_information: Option<PduSessionChargingInformation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub used_unit_containers: Vec<UsedUnitContainer>,
}

/// `FinalUnitIndication` (TS 32.291 §6.1.6.2.1.13, trimmed): the CHF telling the SMF
/// what to do once the granted quota is spent. radian signals `TERMINATE` — the SMF
/// tears the PDU session down (online-charging enforcement, design/157, G14).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalUnitIndication {
    /// `TERMINATE` | `REDIRECT` | `RESTRICT_ACCESS` (radian issues `TERMINATE`).
    pub final_unit_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingDataResponse {
    pub invocation_result: String,
    /// Present when the session's granted quota is exhausted — the SMF must stop the
    /// session (TS 32.291 online charging). Absent while quota remains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_unit_indication: Option<FinalUnitIndication>,
}

impl ChargingDataResponse {
    fn success() -> Self {
        Self { invocation_result: "SUCCESS".into(), final_unit_indication: None }
    }

    /// The quota is spent — carry a `TERMINATE` final-unit action.
    fn quota_exhausted() -> Self {
        Self {
            invocation_result: "SUCCESS".into(),
            final_unit_indication: Some(FinalUnitIndication { final_unit_action: "TERMINATE".into() }),
        }
    }
}

/// A charging data record: the accumulated usage of one PDU session, per rating
/// group. Closed (`released`) at session teardown.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cdr {
    pub subscriber_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdu_session_charging_information: Option<PduSessionChargingInformation>,
    /// Accumulated usage per rating group (updates and the final release sum in).
    pub usage: BTreeMap<u32, UsedUnitContainer>,
    pub released: bool,
}

impl Cdr {
    /// Total volume (bytes) accumulated across all rating groups — measured against the
    /// CHF's granted quota to decide online-charging exhaustion (design/157).
    fn total_volume(&self) -> u64 {
        self.usage.values().map(|u| u.total_volume).sum()
    }

    fn absorb(&mut self, containers: &[UsedUnitContainer]) {
        for c in containers {
            let e = self.usage.entry(c.rating_group).or_insert(UsedUnitContainer {
                rating_group: c.rating_group,
                ..Default::default()
            });
            e.uplink_volume += c.uplink_volume;
            e.downlink_volume += c.downlink_volume;
            e.total_volume += c.total_volume;
            e.uplink_packets += c.uplink_packets;
            e.downlink_packets += c.downlink_packets;
            e.total_packets += c.total_packets;
        }
    }
}

/// The CHF's in-memory CDR store.
#[derive(Clone, Default)]
pub struct ChfState {
    cdrs: Arc<Mutex<std::collections::HashMap<String, Cdr>>>,
    next: Arc<AtomicU64>,
    /// The per-session volume quota (bytes) this CHF grants. Once a session's total usage
    /// reaches it, the next update answers with `FinalUnitIndication: TERMINATE` so the
    /// SMF stops the session. `None` ⇒ unlimited (the CHF stays a pure accumulator).
    quota_bytes: Option<u64>,
}

impl ChfState {
    pub fn new() -> Self {
        Self::default()
    }

    /// A CHF that grants `bytes` of volume per session and enforces it via
    /// `FinalUnitIndication` when the session's usage reaches it (design/157, G14).
    pub fn with_quota(bytes: u64) -> Self {
        Self { quota_bytes: Some(bytes), ..Default::default() }
    }

    /// Number of open (unreleased) charging sessions — test/observability hook.
    pub fn open_sessions(&self) -> usize {
        self.cdrs.lock().unwrap().values().filter(|c| !c.released).count()
    }

    /// A CDR by charging-data reference — test/observability hook.
    pub fn cdr(&self, charging_ref: &str) -> Option<Cdr> {
        self.cdrs.lock().unwrap().get(charging_ref).cloned()
    }
}

/// The Nchf_ConvergedCharging router (TS 32.291 §5): create / update / release,
/// plus a (non-standard, read-only) CDR fetch for observability.
pub fn router(state: ChfState) -> Router {
    Router::new()
        .route("/nchf-convergedcharging/v3/chargingdata", post(create))
        .route("/nchf-convergedcharging/v3/chargingdata/{ref}/update", post(update))
        .route("/nchf-convergedcharging/v3/chargingdata/{ref}/release", post(release))
        .route("/nchf-convergedcharging/v3/chargingdata/{ref}", get(get_cdr))
        .with_state(state)
}

async fn create(
    State(chf): State<ChfState>,
    Json(req): Json<ChargingDataRequest>,
) -> (StatusCode, [(axum::http::HeaderName, String); 1], Json<ChargingDataResponse>) {
    let id = chf.next.fetch_add(1, Ordering::Relaxed).to_string();
    let mut cdr = Cdr {
        subscriber_identifier: req.subscriber_identifier.clone(),
        pdu_session_charging_information: req.pdu_session_charging_information.clone(),
        ..Default::default()
    };
    cdr.absorb(&req.used_unit_containers);
    chf.cdrs.lock().unwrap().insert(id.clone(), cdr);
    tracing::info!(supi = %req.subscriber_identifier, charging_ref = %id, "charging session opened");
    let location = format!("/nchf-convergedcharging/v3/chargingdata/{id}");
    (
        StatusCode::CREATED,
        [(axum::http::header::LOCATION, location)],
        Json(ChargingDataResponse::success()),
    )
}

async fn update(
    State(chf): State<ChfState>,
    Path(charging_ref): Path<String>,
    Json(req): Json<ChargingDataRequest>,
) -> Result<Json<ChargingDataResponse>, StatusCode> {
    let mut cdrs = chf.cdrs.lock().unwrap();
    let cdr = cdrs.get_mut(&charging_ref).ok_or(StatusCode::NOT_FOUND)?;
    if cdr.released {
        return Err(StatusCode::CONFLICT);
    }
    cdr.absorb(&req.used_unit_containers);
    // Online charging (design/157, G14): once the session's accumulated usage reaches the
    // granted quota, answer with FinalUnitIndication: TERMINATE so the SMF stops it.
    let exhausted = chf.quota_bytes.is_some_and(|q| cdr.total_volume() >= q);
    tracing::info!(
        charging_ref = %charging_ref,
        containers = req.used_unit_containers.len(),
        total_bytes = cdr.total_volume(),
        exhausted,
        "charging session updated (mid-session usage)"
    );
    Ok(Json(if exhausted {
        ChargingDataResponse::quota_exhausted()
    } else {
        ChargingDataResponse::success()
    }))
}

async fn release(
    State(chf): State<ChfState>,
    Path(charging_ref): Path<String>,
    Json(req): Json<ChargingDataRequest>,
) -> StatusCode {
    let mut cdrs = chf.cdrs.lock().unwrap();
    let Some(cdr) = cdrs.get_mut(&charging_ref) else {
        return StatusCode::NOT_FOUND;
    };
    cdr.absorb(&req.used_unit_containers);
    cdr.released = true;
    let total: u64 = cdr.usage.values().map(|u| u.total_volume).sum();
    tracing::info!(charging_ref = %charging_ref, total_bytes = total, "charging session released — CDR closed");
    StatusCode::NO_CONTENT
}

async fn get_cdr(
    State(chf): State<ChfState>,
    Path(charging_ref): Path<String>,
) -> Result<Json<Cdr>, StatusCode> {
    chf.cdr(&charging_ref).map(Json).ok_or(StatusCode::NOT_FOUND)
}

/// Client the SMF (as CTF) uses to reach the CHF's Nchf_ConvergedCharging.
pub struct ChfClient {
    base: String,
    http: reqwest::Client,
    tokens: Option<std::sync::Arc<crate::oauth::TokenSource>>,
}

/// The CHF service a `CHF`-audience token authorizes.
const CHF_SCOPE: &str = "nchf-convergedcharging";

impl ChfClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: crate::sbi_client(),
            tokens: None,
        }
    }

    /// Like [`new`], but attaches an NRF-issued `CHF` access token on every request —
    /// required once the CHF is protected (SBI security on, design/149).
    pub fn with_tokens(
        base: impl Into<String>,
        tokens: std::sync::Arc<crate::oauth::TokenSource>,
    ) -> Self {
        Self { base: base.into(), http: crate::sbi_client(), tokens: Some(tokens) }
    }

    /// Attach a `CHF` Bearer token to a request when a token source is configured.
    async fn bearer(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.tokens {
            Some(ts) => match ts.token_for("CHF", CHF_SCOPE).await {
                Some(tok) => rb.bearer_auth(tok),
                None => rb,
            },
            None => rb,
        }
    }

    /// Open a charging data session; returns the charging-data reference
    /// (from `Location`).
    pub async fn create(&self, req: &ChargingDataRequest) -> Result<String, SbiError> {
        let resp = self
            .bearer(
                self.http
                    .post(format!("{}/nchf-convergedcharging/v3/chargingdata", self.base))
                    .json(req),
            )
            .await
            .traced()
            .send()
            .await?
            .error_for_status()?;
        resp.headers()
            .get(axum::http::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|l| l.rsplit('/').next())
            .map(str::to_owned)
            .ok_or_else(|| {
                SbiError::Io(std::io::Error::other("Nchf create response missing Location"))
            })
    }

    /// Report mid-session usage.
    /// Report mid-session usage and return the CHF's decision — a `FinalUnitIndication`
    /// is present once the granted quota is spent (design/157, G14).
    pub async fn update(
        &self,
        charging_ref: &str,
        req: &ChargingDataRequest,
    ) -> Result<ChargingDataResponse, SbiError> {
        let resp = self
            .bearer(
                self.http
                    .post(format!(
                        "{}/nchf-convergedcharging/v3/chargingdata/{charging_ref}/update",
                        self.base
                    ))
                    .json(req),
            )
            .await
            .traced()
            .send()
            .await?
            .error_for_status()?
            .json::<ChargingDataResponse>()
            .await?;
        Ok(resp)
    }

    /// Close the charging session with the final usage.
    pub async fn release(
        &self,
        charging_ref: &str,
        req: &ChargingDataRequest,
    ) -> Result<(), SbiError> {
        self.bearer(
            self.http
                .post(format!(
                    "{}/nchf-convergedcharging/v3/chargingdata/{charging_ref}/release",
                    self.base
                ))
                .json(req),
        )
        .await
        .traced()
        .send()
        .await?
        .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn serve_with(state: ChfState) -> (ChfState, ChfClient) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = router(state.clone());
        tokio::spawn(async move { crate::run_on(listener, router).await.unwrap() });
        (state, ChfClient::new(format!("http://{addr}")))
    }

    async fn serve() -> (ChfState, ChfClient) {
        serve_with(ChfState::new()).await
    }

    fn usage(rating_group: u32, ul: u64, dl: u64, ulp: u64, dlp: u64) -> UsedUnitContainer {
        UsedUnitContainer {
            rating_group,
            uplink_volume: ul,
            downlink_volume: dl,
            total_volume: ul + dl,
            uplink_packets: ulp,
            downlink_packets: dlp,
            total_packets: ulp + dlp,
        }
    }

    /// The converged-charging lifecycle: create → mid-session update → release,
    /// with usage accumulating per rating group into the CDR.
    #[tokio::test]
    async fn charging_session_lifecycle_accumulates_the_cdr() {
        let (state, client) = serve().await;

        let mut req = ChargingDataRequest {
            subscriber_identifier: "imsi-999700000000001".into(),
            pdu_session_charging_information: Some(PduSessionChargingInformation {
                pdu_session_id: 4,
                dnn: "internet".into(),
            }),
            used_unit_containers: vec![],
        };
        let charging_ref = client.create(&req).await.expect("Nchf create");
        assert_eq!(state.open_sessions(), 1);

        // Two mid-session usage reports (session-level rating group 0 + QFI 2).
        req.used_unit_containers = vec![usage(0, 1000, 500, 10, 5)];
        client.update(&charging_ref, &req).await.expect("update 1");
        req.used_unit_containers = vec![usage(0, 200, 100, 2, 1), usage(2, 50, 25, 1, 1)];
        client.update(&charging_ref, &req).await.expect("update 2");

        // Release with the final delta; the CDR closes with everything summed.
        req.used_unit_containers = vec![usage(0, 10, 5, 1, 0)];
        client.release(&charging_ref, &req).await.expect("release");

        let cdr = state.cdr(&charging_ref).expect("CDR exists");
        assert!(cdr.released);
        assert_eq!(cdr.subscriber_identifier, "imsi-999700000000001");
        assert_eq!(cdr.usage[&0].uplink_volume, 1210);
        assert_eq!(cdr.usage[&0].downlink_volume, 605);
        assert_eq!(cdr.usage[&2].total_volume, 75);
        // Packet counts accumulate per rating group alongside volume (design/155).
        assert_eq!(cdr.usage[&0].uplink_packets, 13);
        assert_eq!(cdr.usage[&0].total_packets, 19);
        assert_eq!(cdr.usage[&2].total_packets, 2);
        assert_eq!(state.open_sessions(), 0);

        // A released session refuses further updates; unknown refs are 404.
        assert!(client.update(&charging_ref, &req).await.is_err(), "update after release → 409");
        assert!(client.update("999", &req).await.is_err(), "unknown ref → 404");
    }

    /// Online charging (design/157, G14): a quota-enforcing CHF answers updates with a
    /// `FinalUnitIndication: TERMINATE` once the session's usage reaches the granted quota.
    #[tokio::test]
    async fn charging_quota_signals_final_unit_indication() {
        // A CHF that grants 2500 bytes per session.
        let (_, client) = serve_with(ChfState::with_quota(2500)).await;
        let mut req = ChargingDataRequest {
            subscriber_identifier: "imsi-999700000000042".into(),
            pdu_session_charging_information: None,
            used_unit_containers: vec![],
        };
        let charging_ref = client.create(&req).await.expect("Nchf create");

        // 2000 bytes so far — under quota, so the session may continue.
        req.used_unit_containers = vec![usage(0, 1200, 800, 12, 8)];
        let resp = client.update(&charging_ref, &req).await.expect("update 1");
        assert!(resp.final_unit_indication.is_none(), "2000 < 2500 — no FUI yet");

        // Another 1000 bytes → 3000 ≥ 2500 → quota exhausted → TERMINATE.
        req.used_unit_containers = vec![usage(0, 600, 400, 6, 4)];
        let resp = client.update(&charging_ref, &req).await.expect("update 2");
        assert_eq!(
            resp.final_unit_indication.map(|f| f.final_unit_action).as_deref(),
            Some("TERMINATE"),
            "quota reached → FinalUnitIndication TERMINATE"
        );
    }
}
