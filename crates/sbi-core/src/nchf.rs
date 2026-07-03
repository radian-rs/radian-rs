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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::SbiError;

/// One used-unit container (TS 32.291 §6.1.6.2.24, trimmed): the volume consumed
/// under one rating group since the previous report.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsedUnitContainer {
    /// `0` = session-level (non-flow) traffic; otherwise the QoS flow's QFI.
    pub rating_group: u32,
    pub uplink_volume: u64,
    pub downlink_volume: u64,
    pub total_volume: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingDataResponse {
    pub invocation_result: String,
}

impl ChargingDataResponse {
    fn success() -> Self {
        Self { invocation_result: "SUCCESS".into() }
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
    fn absorb(&mut self, containers: &[UsedUnitContainer]) {
        for c in containers {
            let e = self.usage.entry(c.rating_group).or_insert(UsedUnitContainer {
                rating_group: c.rating_group,
                ..Default::default()
            });
            e.uplink_volume += c.uplink_volume;
            e.downlink_volume += c.downlink_volume;
            e.total_volume += c.total_volume;
        }
    }
}

/// The CHF's in-memory CDR store.
#[derive(Clone, Default)]
pub struct ChfState {
    cdrs: Arc<Mutex<std::collections::HashMap<String, Cdr>>>,
    next: Arc<AtomicU64>,
}

impl ChfState {
    pub fn new() -> Self {
        Self::default()
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
    tracing::info!(
        charging_ref = %charging_ref,
        containers = req.used_unit_containers.len(),
        "charging session updated (mid-session usage)"
    );
    Ok(Json(ChargingDataResponse::success()))
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
}

impl ChfClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into(), http: crate::sbi_client() }
    }

    /// Open a charging data session; returns the charging-data reference
    /// (from `Location`).
    pub async fn create(&self, req: &ChargingDataRequest) -> Result<String, SbiError> {
        let resp = self
            .http
            .post(format!("{}/nchf-convergedcharging/v3/chargingdata", self.base))
            .json(req)
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
    pub async fn update(
        &self,
        charging_ref: &str,
        req: &ChargingDataRequest,
    ) -> Result<(), SbiError> {
        self.http
            .post(format!(
                "{}/nchf-convergedcharging/v3/chargingdata/{charging_ref}/update",
                self.base
            ))
            .json(req)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Close the charging session with the final usage.
    pub async fn release(
        &self,
        charging_ref: &str,
        req: &ChargingDataRequest,
    ) -> Result<(), SbiError> {
        self.http
            .post(format!(
                "{}/nchf-convergedcharging/v3/chargingdata/{charging_ref}/release",
                self.base
            ))
            .json(req)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn serve() -> (ChfState, ChfClient) {
        let state = ChfState::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = router(state.clone());
        tokio::spawn(async move { crate::run_on(listener, router).await.unwrap() });
        (state, ChfClient::new(format!("http://{addr}")))
    }

    fn usage(rating_group: u32, ul: u64, dl: u64) -> UsedUnitContainer {
        UsedUnitContainer {
            rating_group,
            uplink_volume: ul,
            downlink_volume: dl,
            total_volume: ul + dl,
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
        req.used_unit_containers = vec![usage(0, 1000, 500)];
        client.update(&charging_ref, &req).await.expect("update 1");
        req.used_unit_containers = vec![usage(0, 200, 100), usage(2, 50, 25)];
        client.update(&charging_ref, &req).await.expect("update 2");

        // Release with the final delta; the CDR closes with everything summed.
        req.used_unit_containers = vec![usage(0, 10, 5)];
        client.release(&charging_ref, &req).await.expect("release");

        let cdr = state.cdr(&charging_ref).expect("CDR exists");
        assert!(cdr.released);
        assert_eq!(cdr.subscriber_identifier, "imsi-999700000000001");
        assert_eq!(cdr.usage[&0].uplink_volume, 1210);
        assert_eq!(cdr.usage[&0].downlink_volume, 605);
        assert_eq!(cdr.usage[&2].total_volume, 75);
        assert_eq!(state.open_sessions(), 0);

        // A released session refuses further updates; unknown refs are 404.
        assert!(client.update(&charging_ref, &req).await.is_err(), "update after release → 409");
        assert!(client.update("999", &req).await.is_err(), "unknown ref → 404");
    }
}
