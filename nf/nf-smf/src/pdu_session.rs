//! `Nsmf_PDUSession` (TS 29.502) over the N4 (PFCP) datapath.
//!
//! The SMF is an SBI **server** (the AMF calls it) and a PFCP **client** (it drives
//! the UPF). On `CreateSMContext` it runs an N4 Session Establishment and returns the
//! UPF-allocated N3 F-TEID (which the AMF puts in the N2 SM info for the gNB); on
//! `UpdateSMContext` — after the gNB's F-TEID comes back in the N2 PDU Session Resource
//! Setup Response — it runs an N4 Session Modification to install the downlink path.
//!
//! Request/response bodies are simplified: TS 29.502 uses multipart with binary N1/N2
//! SM containers, which arrive with the NAS-SM and N2-SM-info slices.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

/// FAR id the downlink Update FAR targets. Establishment provisions FAR 2 (downlink,
/// forward to Access); the Session Modification points it at the gNB with Outer Header
/// Creation. (FAR 1 is the uplink FAR, forward to Core.)
const FAR_ID: u32 = 2;

/// The SMF allocates UE IPv4 addresses from this /16. `.1` is the UPF's N6 gateway
/// (see nf-upf), so UEs start at `.2`. In a real deployment this is DNN/slice-scoped and
/// coordinated with the UPF's N6 subnet; here one pool suffices.
const UE_IP_POOL_START: u32 = 0x0A2D_0002; // 10.45.0.2

/// This SMF's stable NF instance id — the `smfInstanceId` in every UECM
/// smf-registration.
static SMF_INSTANCE_ID: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(sbi_core::new_nf_instance_id);

/// Per-PDU-session SMF state.
struct SmContext {
    /// UP-SEID — addresses the session toward the UPF.
    up_seid: u64,
    /// CP F-SEID — how a UPF-initiated Session Report Request addresses this
    /// session back to us.
    cp_seid: u64,
    /// UPF-allocated uplink N3 F-TEID + its node address — carried to the gNB in the
    /// N2 SM info at establishment and again on a Service Request re-activation.
    n3_teid: u32,
    n3_addr: Ipv4Addr,
    /// The UE's assigned IP (this session's PDU address).
    ue_ip: Ipv4Addr,
    /// The DNN this session is for — carried as the PFCP **Network Instance** on the
    /// forwarding rules (establishment + every downlink re-point), the name an
    /// operator binds to a VRF.
    dnn: String,
    /// The slice serving this session — re-sent in the activate response.
    snssai: Snssai,
    /// gNB downlink target, once `UpdateSMContext` installs it. Cleared on AN
    /// release (deactivation).
    gnb: Option<(u32, Ipv4Addr)>,
    /// An **indirect data forwarding** tunnel's UP-SEID, set up for an N2 handover
    /// (source → UPF → target). `None` when no forwarding is in place; released
    /// when the handover completes or fails.
    indirect_fwd: Option<u64>,
    /// Subscriber + session identity, for the UECM smf-registration teardown.
    supi: String,
    pdu_session_id: u8,
    /// The PCF SM policy association `(pcf_base, policy_id)`, when a PCF drove the
    /// policy — deleted at release (Npcf_SMPolicyControl_Delete), re-authorized on
    /// refresh (Npcf_SMPolicyControl_Update). `None` when the session used the
    /// sm-data fallback.
    sm_policy: Option<(String, String)>,
    /// The current authorized QoS (session AMBR + flows) — the sm-context's policy
    /// record, refreshed by an Update.
    policy: sbi_core::npcf::SmPolicyDecision,
    /// GFBR `(downlink, uplink)` bits/sec this session reserved (GFBR admission) —
    /// released at teardown, adjusted on a mid-session policy change.
    reserved_gfbr: (u64, u64),
    /// The Nchf charging data session `(chf_base, charging_ref)`, when a CHF was
    /// discovered at establishment — updated with each relayed usage report,
    /// released with the final usage at teardown. `None` ⇒ no charging.
    charging: Option<(String, String)>,
}

/// SMF runtime: a PFCP client toward one UPF plus the SM-context table.
pub struct SmfState {
    smf_ip: Ipv4Addr,
    /// NRF base URL — used to discover the UDM for Nudm_SDM subscription fetches.
    nrf_base: String,
    /// Connected N4 socket. A dedicated reader task (spawned by [`connect`]) owns
    /// the receive side: responses are routed to their waiting transaction by
    /// sequence number, and **UPF-initiated** Session Report Requests (usage
    /// thresholds, design/59) land on [`reports_rx`].
    sock: Arc<UdpSocket>,
    /// In-flight transactions: sequence number → the waiting response channel
    /// (shared with the reader task).
    pending: Arc<Mutex<HashMap<u32, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    /// UPF-initiated Session Report Requests, consumed by
    /// [`handle_usage_reports`].
    reports_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    seq: AtomicU32,
    cp_seid: AtomicU64,
    next_ref: AtomicU64,
    /// Next UE IPv4 address to hand out (as a host-order u32), from the pool above.
    next_ue_ip: AtomicU32,
    contexts: Mutex<HashMap<String, SmContext>>,
    /// GFBR admission control: the guaranteed-bit-rate budget `(downlink, uplink)`
    /// in bits/sec and the currently reserved total. A session whose GBR flows'
    /// aggregate GFBR would exceed the remaining budget is refused (5GSM #26).
    gfbr_budget_bps: (u64, u64),
    reserved_gfbr_bps: Mutex<(u64, u64)>,
    /// Usage-reporting volume threshold (bytes): provisioned on each session's URR
    /// so the UPF reports mid-session usage (VOLTH) — the charging trigger.
    /// `None` ⇒ usage is only reported at session deletion.
    usage_threshold_bytes: Option<u64>,
}

impl SmfState {
    /// Bind an N4 client socket and connect it to the UPF's PFCP endpoint. Spawns
    /// the socket's reader task: responses are correlated to their transaction by
    /// sequence number; UPF-initiated Session Report Requests go to the usage
    /// channel (nothing else reads the socket).
    pub async fn connect(
        upf_n4: SocketAddr,
        smf_ip: Ipv4Addr,
        nrf_base: impl Into<String>,
    ) -> std::io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(upf_n4).await?;
        let sock = Arc::new(sock);
        let pending: Arc<Mutex<HashMap<u32, tokio::sync::oneshot::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (reports_tx, reports_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let (sock, pending) = (sock.clone(), pending.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let Ok(n) = sock.recv(&mut buf).await else { break };
                    let datagram = buf[..n].to_vec();
                    // A UPF-initiated Session Report (usage threshold or downlink
                    // data) — hand it to the report handler.
                    if pfcp::parse_session_report_request(&datagram).is_some()
                        || pfcp::parse_dl_data_report(&datagram).is_some()
                    {
                        if reports_tx.send(datagram).is_err() {
                            break;
                        }
                        continue;
                    }
                    // Otherwise a response: wake the transaction waiting on its seq.
                    // (A stale response — e.g. to a timed-out request — is dropped.)
                    if let Some(seq) = pfcp::sequence_of(&datagram) {
                        if let Some(tx) = pending.lock().unwrap().remove(&seq) {
                            let _ = tx.send(datagram);
                        }
                    }
                }
            });
        }
        Ok(Self {
            smf_ip,
            nrf_base: nrf_base.into(),
            sock,
            pending,
            reports_rx: tokio::sync::Mutex::new(reports_rx),
            seq: AtomicU32::new(1),
            cp_seid: AtomicU64::new(1),
            next_ref: AtomicU64::new(1),
            next_ue_ip: AtomicU32::new(UE_IP_POOL_START),
            contexts: Mutex::new(HashMap::new()),
            // Generous default so plain operation isn't gated; override for admission
            // control (config / tests).
            gfbr_budget_bps: (u64::MAX, u64::MAX),
            reserved_gfbr_bps: Mutex::new((0, 0)),
            usage_threshold_bytes: None,
        })
    }

    /// Set the GFBR admission-control budget `(downlink_bps, uplink_bps)`.
    pub fn with_gfbr_budget(mut self, downlink_bps: u64, uplink_bps: u64) -> Self {
        self.gfbr_budget_bps = (downlink_bps, uplink_bps);
        self
    }

    /// Provision a volume threshold (bytes) on every session's URR: the UPF then
    /// reports usage mid-session whenever the threshold is crossed (the charging
    /// trigger toward the CHF).
    pub fn with_usage_threshold(mut self, bytes: u64) -> Self {
        self.usage_threshold_bytes = Some(bytes);
        self
    }

    /// Try to reserve `(dl, ul)` bits/sec of GFBR against the budget. Returns `false`
    /// (and reserves nothing) if either direction would exceed it.
    fn try_reserve_gfbr(&self, (dl, ul): (u64, u64)) -> bool {
        let mut r = self.reserved_gfbr_bps.lock().unwrap();
        if r.0.saturating_add(dl) > self.gfbr_budget_bps.0
            || r.1.saturating_add(ul) > self.gfbr_budget_bps.1
        {
            return false;
        }
        r.0 += dl;
        r.1 += ul;
        true
    }

    /// Release a session's GFBR reservation.
    fn release_gfbr(&self, (dl, ul): (u64, u64)) {
        let mut r = self.reserved_gfbr_bps.lock().unwrap();
        r.0 = r.0.saturating_sub(dl);
        r.1 = r.1.saturating_sub(ul);
    }

    /// Atomically swap a session's GFBR reservation from `old` to `new` (a
    /// mid-session policy change; not admission-checked — the PCF authorized it).
    fn adjust_gfbr(&self, old: (u64, u64), new: (u64, u64)) {
        let mut r = self.reserved_gfbr_bps.lock().unwrap();
        r.0 = r.0.saturating_sub(old.0).saturating_add(new.0);
        r.1 = r.1.saturating_sub(old.1).saturating_add(new.1);
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate the next UE IPv4 address from the pool.
    fn alloc_ue_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.next_ue_ip.fetch_add(1, Ordering::Relaxed))
    }

    /// Send one PFCP request and await *its* response — correlated by sequence number
    /// (PFCP responses echo the request's) via the reader task. 2s overall; on
    /// timeout the pending entry is withdrawn (a late response is then dropped).
    async fn transact(&self, req: &[u8], expect_seq: u32) -> Option<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().unwrap().insert(expect_seq, tx);
        if self.sock.send(req).await.is_err() {
            self.pending.lock().unwrap().remove(&expect_seq);
            return None;
        }
        match tokio::time::timeout(Duration::from_secs(2), rx).await {
            Ok(Ok(resp)) => Some(resp),
            _ => {
                self.pending.lock().unwrap().remove(&expect_seq);
                None
            }
        }
    }

    /// PFCP Association Setup toward the UPF — required before any session.
    pub async fn associate(&self) -> anyhow::Result<()> {
        let seq = self.next_seq();
        let req = pfcp::association_setup_request(self.smf_ip, seq);
        let resp = self
            .transact(&req, seq)
            .await
            .ok_or_else(|| anyhow::anyhow!("no PFCP association response from UPF"))?;
        anyhow::ensure!(pfcp::response_accepted(&resp), "UPF rejected PFCP association");
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct PlmnId {
    mcc: String,
    mnc: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextCreateData {
    supi: String,
    pdu_session_id: u8,
    #[serde(default)]
    dnn: String,
    /// The serving PLMN (TS 29.502) — selects which provisioned dataset applies.
    serving_network: Option<PlmnId>,
    /// The UE's requested slice (TS 29.502 `sNssai`). Absent → the subscribed
    /// slice serving the DNN is used.
    s_nssai: Option<Snssai>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snssai {
    sst: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    sd: Option<String>,
}

impl Snssai {
    /// The `subscribedSnssaiInfos` map key this stack provisions: `sst` or `sst-sd`.
    fn key(&self) -> String {
        match &self.sd {
            Some(sd) => format!("{}-{}", self.sst, sd.to_lowercase()),
            None => self.sst.to_string(),
        }
    }

    /// Slice equality with case-insensitive SD (SDs are hex strings).
    fn matches(&self, other: &Snssai) -> bool {
        self.sst == other.sst
            && match (&self.sd, &other.sd) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                (None, None) => true,
                _ => false,
            }
    }
}

// The session AMBR and authorized QoS-flow shapes are shared with the PCF
// (`sbi_core::npcf`): a PCF `SmPolicyDecision` and the SMF's own sm-data fallback
// build the same types, so either drops straight into the CreateSMContext response.
use sbi_core::npcf::{QosFlowPolicy, SessionAmbrPolicy};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextCreatedData {
    sm_context_ref: String,
    /// The UPF's N3 F-TEID — carried to the gNB in the N2 SM info.
    up_n3_teid: String,
    up_n3_addr: Ipv4Addr,
    /// The UE's assigned IPv4 address (its PDU session address). Delivered to the UE in
    /// the NAS PDU Session Establishment Accept (a later NAS-SM slice); the UPF already
    /// routes downlink traffic to it.
    ue_ipv4_addr: Ipv4Addr,
    /// The subscribed slice serving this DNN (from the UDR sm-data) — the AMF puts it
    /// in the N1 accept.
    s_nssai: Snssai,
    /// The authorized session AMBR for this DNN (TS 29.571 BitRate strings), if any
    /// — from the PCF's SM policy, else the subscribed sm-data. For the N1 accept.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_ambr: Option<SessionAmbrPolicy>,
    /// The authorized QoS flows (default + any GBR flows) — the AMF puts them in
    /// the N2 setup transfer and the N1 accept's QoS flow descriptions.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    qos_flows: Vec<QosFlowPolicy>,
}

/// What the SMF needs out of the subscriber's session-management subscription
/// (the sm-data fallback when no PCF is available).
struct SessionSubscription {
    snssai: Snssai,
    ambr: Option<SessionAmbrPolicy>,
    qos_flows: Vec<QosFlowPolicy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextUpdateData {
    /// The gNB's N3 F-TEID from the N2 PDU Session Resource Setup Response (hex).
    /// Present on an **activation** (downlink install / Service Request resume).
    #[serde(default)]
    gnb_n3_teid: Option<String>,
    #[serde(default)]
    gnb_n3_addr: Option<Ipv4Addr>,
    /// User-plane connection state (TS 29.502): `DEACTIVATED` on AN release tears
    /// the downlink tunnel down; `ACTIVATING` (with the gNB F-TEID) re-installs it.
    #[serde(default)]
    up_cnx_state: Option<String>,
}

/// The `Nsmf_PDUSession` router.
pub fn router(state: Arc<SmfState>) -> Router {
    Router::new()
        .route("/nsmf-pdusession/v1/sm-contexts", post(create_sm_context))
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            post(update_sm_context),
        )
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/release",
            post(release_sm_context),
        )
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/refresh-policy",
            post(refresh_sm_policy),
        )
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/indirect-forwarding",
            post(indirect_forwarding),
        )
        .with_state(state)
}

/// An SBI error response: status + RFC 7807 ProblemDetails with a TS 29.502-style
/// application cause (e.g. `DNN_DENIED`, `SNSSAI_DENIED`).
type SbiProblem = (StatusCode, Json<sbi_core::ProblemDetails>);

fn problem(status: StatusCode, cause: &str, detail: &str) -> SbiProblem {
    (
        status,
        Json(sbi_core::ProblemDetails {
            status: Some(status.as_u16()),
            cause: Some(cause.to_string()),
            detail: Some(detail.to_string()),
            ..Default::default()
        }),
    )
}

/// `Nsmf_PDUSession_CreateSMContext`: authorize the (requested S-NSSAI, DNN) pair
/// against the subscriber's UDR-provisioned data (via Nudm_SDM), establish the N4
/// session, and return the UPF N3 F-TEID plus the serving S-NSSAI / session AMBR.
async fn create_sm_context(
    State(smf): State<Arc<SmfState>>,
    Json(req): Json<SmContextCreateData>,
) -> Result<(StatusCode, Json<SmContextCreatedData>), SbiProblem> {
    if req.dnn.is_empty() {
        return Err(problem(StatusCode::BAD_REQUEST, "MANDATORY_IE_MISSING", "dnn is required"));
    }
    let plmn = req
        .serving_network
        .as_ref()
        .map(|p| format!("{}{}", p.mcc, p.mnc))
        .ok_or_else(|| {
            problem(StatusCode::BAD_REQUEST, "MANDATORY_IE_MISSING", "servingNetwork is required")
        })?;
    // Subscription check BEFORE touching the UPF: a denied (slice, DNN) → 403, no N4 state.
    let sub = fetch_session_subscription(
        &smf.nrf_base,
        &req.supi,
        &plmn,
        &req.dnn,
        req.s_nssai.as_ref(),
    )
    .await?;

    // Ask the PCF for the SM policy (authorized session AMBR + QoS flows). When a
    // PCF is registered it is authoritative (TS 23.503 §6.1.3.5); otherwise fall
    // back to the sm-data policy fetched above. Done before the N4 establishment so
    // the authorized flows are known when the context is built.
    let policy_ctx = sbi_core::npcf::SmPolicyContextData {
        supi: req.supi.clone(),
        pdu_session_id: req.pdu_session_id,
        dnn: req.dnn.clone(),
        snssai_sst: Some(sub.snssai.sst),
        snssai_sd: sub.snssai.sd.clone(),
    };
    let (decision, sm_policy) = match fetch_sm_policy(&smf.nrf_base, &policy_ctx).await {
        Some((pcf_base, created)) => {
            tracing::info!(
                policy_id = %created.policy_id,
                flows = created.decision.qos_flows.len(),
                "SM policy from PCF"
            );
            (created.decision, Some((pcf_base, created.policy_id)))
        }
        None => (
            sbi_core::npcf::SmPolicyDecision { session_ambr: sub.ambr, qos_flows: sub.qos_flows },
            None,
        ),
    };

    // GFBR admission control (before any N4 state): reserve the session's aggregate
    // guaranteed bit rate against the budget, refusing it (503 → 5GSM #26) if the
    // network can't guarantee it.
    let reserved_gfbr = decision_gfbr(&decision);
    if !smf.try_reserve_gfbr(reserved_gfbr) {
        tracing::warn!(
            supi = %masked_supi(&req.supi),
            dnn = %req.dnn,
            gfbr_dl = reserved_gfbr.0, gfbr_ul = reserved_gfbr.1,
            "PDU session refused: GFBR admission control (insufficient resources)"
        );
        return Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "INSUFFICIENT_RESOURCES",
            "GFBR cannot be guaranteed",
        ));
    }

    let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
    let seq = smf.next_seq();
    // The SMF owns UE IP allocation; the address rides into the UPF's downlink PDR so it
    // can route N6 traffic back to this session.
    let ue_ip = smf.alloc_ue_ip();
    // Install the authorized session AMBR (a QER for the aggregate rate) plus a
    // per-flow QER + classifier for each GBR flow, so the UPF polices them.
    let ambr = ambr_bps(&decision);
    let flows = flow_qers(&decision);
    let est_req =
        pfcp::session_establishment_request(
            cp_seid,
            seq,
            smf.smf_ip,
            ue_ip,
            &req.dnn,
            ambr,
            &flows,
            smf.usage_threshold_bytes,
        );
    // Release the GFBR reservation if the N4 establishment doesn't complete.
    let resp = match smf.transact(&est_req, seq).await {
        Some(r) => r,
        None => {
            smf.release_gfbr(reserved_gfbr);
            return Err(problem(
                StatusCode::BAD_GATEWAY,
                "UPF_NOT_RESPONDING",
                "no PFCP response from the UPF",
            ));
        }
    };
    let est = match pfcp::parse_session_establishment_response(&resp) {
        Some(e) => e,
        None => {
            smf.release_gfbr(reserved_gfbr);
            return Err(problem(
                StatusCode::BAD_GATEWAY,
                "UPF_NOT_RESPONDING",
                "PFCP establishment rejected",
            ));
        }
    };

    // Open an Nchf charging data session at the NRF-discovered CHF (the SMF acting
    // as CTF, TS 32.290). Best-effort: no CHF (or a failed create) ⇒ the session
    // runs unbilled, mirroring the PCF fallback.
    let charging = match discover_endpoint(&smf.nrf_base, "CHF").await {
        Ok(chf_base) => {
            let create = sbi_core::nchf::ChargingDataRequest {
                subscriber_identifier: req.supi.clone(),
                pdu_session_charging_information: Some(
                    sbi_core::nchf::PduSessionChargingInformation {
                        pdu_session_id: req.pdu_session_id,
                        dnn: req.dnn.clone(),
                    },
                ),
                used_unit_containers: vec![],
            };
            match sbi_core::nchf::ChfClient::new(chf_base.clone()).create(&create).await {
                Ok(charging_ref) => {
                    tracing::info!(charging_ref = %charging_ref, "charging session opened at the CHF");
                    Some((chf_base, charging_ref))
                }
                Err(e) => {
                    tracing::warn!("Nchf create failed (session runs unbilled): {e}");
                    None
                }
            }
        }
        Err(e) => {
            tracing::debug!("no CHF discovered (session runs unbilled): {e}");
            None
        }
    };

    let sm_ref = smf.next_ref.fetch_add(1, Ordering::Relaxed).to_string();
    smf.contexts.lock().unwrap().insert(
        sm_ref.clone(),
        SmContext {
            up_seid: est.up_seid,
            cp_seid,
            n3_teid: est.n3_teid,
            n3_addr: est.n3_addr,
            ue_ip,
            dnn: req.dnn.clone(),
            snssai: sub.snssai.clone(),
            gnb: None,
            indirect_fwd: None,
            supi: req.supi.clone(),
            pdu_session_id: req.pdu_session_id,
            sm_policy,
            policy: decision.clone(),
            reserved_gfbr,
            charging,
        },
    );
    // Record this SMF as the serving SMF for the session (Nudm_UECM). Best-effort,
    // off the establishment path — the session is up regardless.
    spawn_uecm_register(
        smf.nrf_base.clone(),
        req.supi.clone(),
        req.pdu_session_id,
        req.dnn.clone(),
    );
    // SUPI is a permanent subscriber identifier (PII): log only a masked form.
    tracing::info!(
        supi = %masked_supi(&req.supi),
        pdu_session_id = req.pdu_session_id,
        dnn = %req.dnn,
        snssai = ?sub.snssai,
        up_seid = est.up_seid,
        n3_teid = est.n3_teid,
        %ue_ip,
        "created SM context; N4 session established"
    );
    Ok((
        StatusCode::CREATED,
        Json(SmContextCreatedData {
            sm_context_ref: sm_ref,
            up_n3_teid: format!("{:08x}", est.n3_teid),
            up_n3_addr: est.n3_addr,
            ue_ipv4_addr: ue_ip,
            s_nssai: sub.snssai,
            session_ambr: decision.session_ambr,
            qos_flows: decision.qos_flows,
        }),
    ))
}

/// Whether one smf-select `subscribedSnssaiInfos` entry's `dnnInfos` contains `dnn`.
fn dnn_in_info(info: &serde_json::Value, dnn: &str) -> bool {
    info.get("dnnInfos")
        .and_then(|v| v.as_array())
        .is_some_and(|dnns| dnns.iter().any(|d| d.get("dnn").and_then(|v| v.as_str()) == Some(dnn)))
}

/// Fetch and authorize the session-management subscription for (`supi`, `plmn`,
/// `dnn`, optionally the UE's `requested` S-NSSAI) via the NRF-discovered UDM
/// (Nudm_SDM):
/// - `smf-select-data` must allow the pair: with a requested slice, that slice's
///   entry must exist (else `403 SNSSAI_DENIED`) and list the DNN (else
///   `403 DNN_DENIED`); without one, any subscribed slice listing the DNN counts.
/// - `sm-data` supplies the serving S-NSSAI and session AMBR: with a requested
///   slice, its own entry is used; without one, the first entry configuring the DNN.
///
/// Fails closed: a missing subscription is `403`, an unreachable NRF/UDM is `502`.
async fn fetch_session_subscription(
    nrf_base: &str,
    supi: &str,
    plmn: &str,
    dnn: &str,
    requested: Option<&Snssai>,
) -> Result<SessionSubscription, SbiProblem> {
    let udm = discover_udm(nrf_base).await.map_err(|e| {
        tracing::warn!("UDM discovery failed: {e}");
        problem(StatusCode::BAD_GATEWAY, "UDM_UNREACHABLE", "UDM discovery failed")
    })?;
    let sdm = sbi_core::nudm::NudmClient::new(udm);

    let gateway = |e| {
        tracing::warn!("Nudm_SDM fetch failed: {e}");
        problem(StatusCode::BAD_GATEWAY, "UDM_UNREACHABLE", "Nudm_SDM fetch failed")
    };
    let denied = |cause: &str, why: &str| {
        tracing::warn!(supi = %masked_supi(supi), %dnn, snssai = ?requested, "PDU session rejected ({cause}): {why}");
        problem(StatusCode::FORBIDDEN, cause, why)
    };

    // SMF-selection data: which DNNs this subscriber may use, per subscribed S-NSSAI.
    let select = sdm
        .get_smf_select_data(supi, plmn)
        .await
        .map_err(gateway)?
        .ok_or_else(|| denied("DNN_DENIED", "no smf-selection subscription data"))?;
    let infos = select.get("subscribedSnssaiInfos").and_then(|v| v.as_object());
    match requested {
        Some(slice) => {
            let info = infos
                .and_then(|m| m.get(&slice.key()))
                .ok_or_else(|| denied("SNSSAI_DENIED", "requested S-NSSAI is not subscribed"))?;
            if !dnn_in_info(info, dnn) {
                return Err(denied("DNN_DENIED", "DNN not allowed in the requested slice"));
            }
        }
        None => {
            let allowed = infos.is_some_and(|m| m.values().any(|info| dnn_in_info(info, dnn)));
            if !allowed {
                return Err(denied("DNN_DENIED", "DNN not in smf-selection subscription data"));
            }
        }
    }

    // SM data: session parameters (S-NSSAI, AMBR) for the slice's DNN configuration.
    let sm_data = sdm
        .get_sm_data(supi, plmn)
        .await
        .map_err(gateway)?
        .ok_or_else(|| denied("DNN_DENIED", "no session-management subscription data"))?;
    let entry_snssai = |e: &serde_json::Value| {
        e.get("singleNssai").and_then(|v| serde_json::from_value::<Snssai>(v.clone()).ok())
    };
    let entry = match requested {
        Some(slice) => sm_data
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| entry_snssai(e).is_some_and(|s| s.matches(slice)))
            .ok_or_else(|| denied("SNSSAI_DENIED", "requested S-NSSAI has no sm-data"))?,
        None => sm_data
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| {
                e.get("dnnConfigurations")
                    .and_then(|v| v.as_object())
                    .is_some_and(|c| c.contains_key(dnn))
            })
            .ok_or_else(|| denied("DNN_DENIED", "DNN has no configuration in sm-data"))?,
    };
    let dnn_config = entry
        .get("dnnConfigurations")
        .and_then(|c| c.get(dnn))
        .ok_or_else(|| denied("DNN_DENIED", "DNN has no configuration in the serving slice"))?;

    let snssai = entry_snssai(entry)
        .ok_or_else(|| denied("DNN_DENIED", "sm-data entry has no singleNssai"))?;
    let ambr = dnn_config
        .get("sessionAmbr")
        .and_then(|v| serde_json::from_value::<SessionAmbrPolicy>(v.clone()).ok());

    // Default QoS flow (QFI 1) from the DNN's 5gQosProfile — 5QI 9 / ARP 8 when
    // absent. Additional (e.g. GBR) flows come from the demo `qosFlows` array.
    // This is the fallback when no PCF is registered; with a PCF, its decision
    // replaces these (TS: QoS flows are PCF-driven — see `fetch_sm_policy`).
    let default_5qi = dnn_config.pointer("/5gQosProfile/5qi").and_then(|v| v.as_u64());
    let default_arp = dnn_config
        .pointer("/5gQosProfile/arp/priorityLevel")
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(8);
    let mut qos_flows = vec![QosFlowPolicy {
        qfi: 1,
        five_qi: default_5qi.and_then(|v| u8::try_from(v).ok()).unwrap_or(9),
        arp_priority: default_arp,
        pre_empt_cap: false,
        pre_empt_vuln: false,
        gbr: None,
        filter: None,
    }];
    if let Some(extra) = dnn_config.get("qosFlows").and_then(|v| v.as_array()) {
        qos_flows.extend(
            extra.iter().filter_map(|f| serde_json::from_value::<QosFlowPolicy>(f.clone()).ok()),
        );
    }
    Ok(SessionSubscription { snssai, ambr, qos_flows })
}

/// Discover the base URL of the first registered NF of `nf_type` via the NRF.
async fn discover_endpoint(nrf_base: &str, nf_type: &str) -> Result<String, String> {
    let profile = sbi_core::nnrf::NrfClient::new(nrf_base.to_string())
        .discover(nf_type, "SMF")
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no {nf_type} registered with the NRF"))?;
    // Dial the peer on the transport it advertises (`https` under mTLS).
    profile.service_base().ok_or_else(|| format!("{nf_type} profile has no service endpoint"))
}

/// Discover the UDM's Nudm service endpoint via the NRF.
async fn discover_udm(nrf_base: &str) -> Result<String, String> {
    discover_endpoint(nrf_base, "UDM").await
}

/// Try to obtain the SM policy from a PCF (Npcf_SMPolicyControl). Returns the PCF
/// base + the created decision on success; `None` when no PCF is registered or the
/// call fails — the caller then uses the sm-data policy instead.
async fn fetch_sm_policy(
    nrf_base: &str,
    ctx: &sbi_core::npcf::SmPolicyContextData,
) -> Option<(String, sbi_core::npcf::SmPolicyCreated)> {
    let pcf_base = match discover_endpoint(nrf_base, "PCF").await {
        Ok(base) => base,
        Err(e) => {
            tracing::debug!("no PCF for SM policy ({e}); using sm-data policy");
            return None;
        }
    };
    match sbi_core::npcf::PcfClient::new(pcf_base.clone()).create_sm_policy(ctx).await {
        Ok(created) => Some((pcf_base, created)),
        Err(e) => {
            tracing::warn!("PCF SM policy create failed ({e}); using sm-data policy");
            None
        }
    }
}

/// `Nsmf_PDUSession_UpdateSMContext`: install the downlink path with the gNB's
/// F-TEID (activation), deactivate the UP (AN release), or return the N2 info to
/// re-activate on a Service Request (`upCnxState=ACTIVATING`).
async fn update_sm_context(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
    Json(req): Json<SmContextUpdateData>,
) -> axum::response::Response {
    // AN release (TS 23.502 §4.2.6): deactivate the downlink user-plane connection
    // — the UPF drops downlink toward the released gNB tunnel; the session persists.
    if req.up_cnx_state.as_deref() == Some("DEACTIVATED") {
        return deactivate_up(&smf, &sm_ref).await.into_response();
    }
    // Service Request resume (TS 23.502 §4.2.3.2): return the session's N2 info (the
    // retained UPF N3 F-TEID + current QoS) so the AMF rebuilds the N2 setup. The N4
    // downlink is re-installed by the follow-up activation (gNB F-TEID) below.
    if req.up_cnx_state.as_deref() == Some("ACTIVATING") {
        return match smf.contexts.lock().unwrap().get(&sm_ref) {
            Some(c) => (
                StatusCode::OK,
                Json(SmContextCreatedData {
                    sm_context_ref: sm_ref.clone(),
                    up_n3_teid: format!("{:08x}", c.n3_teid),
                    up_n3_addr: c.n3_addr,
                    ue_ipv4_addr: c.ue_ip,
                    s_nssai: c.snssai.clone(),
                    session_ambr: c.policy.session_ambr.clone(),
                    qos_flows: c.policy.qos_flows.clone(),
                }),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let Some(teid_hex) = req.gnb_n3_teid else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(gnb_addr) = req.gnb_n3_addr else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let gnb_teid = match u32::from_str_radix(teid_hex.trim_start_matches("0x"), 16) {
        Ok(t) => t,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    // Defense-in-depth on the downlink sink: reject an obviously bogus gNB target. The
    // real protection is SBI authorization (only the AMF may call Nsmf) — OAuth2 is
    // deferred (TS 33.501), same posture as the rest of SBI; the gNB F-TEID legitimately
    // comes from the AMF (which learned it from the N2 PDU Session Resource Setup).
    if !valid_gnb_target(gnb_teid, gnb_addr) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (up_seid, dnn, old_gnb) = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => (c.up_seid, c.dnn.clone(), c.gnb),
            None => return StatusCode::NOT_FOUND.into_response(),
        }
    };
    // A handover / path switch (the downlink is re-pointed from an existing gNB
    // tunnel to a *different* one) asks the UPF for a GTP-U End Marker on the old
    // path. A first activation or a Service-Request re-activation (no prior gNB, or
    // the same one) does not.
    let send_end_marker = old_gnb.is_some_and(|g| g != (gnb_teid, gnb_addr));

    let seq = smf.next_seq();
    let mod_req =
        pfcp::session_modification_request(up_seid, seq, FAR_ID, gnb_teid, gnb_addr, &dnn, send_end_marker);
    if send_end_marker {
        tracing::info!(%sm_ref, "downlink re-point across a handover — requesting a GTP-U End Marker");
    }
    let resp = match smf.transact(&mod_req, seq).await {
        Some(r) => r,
        None => return StatusCode::BAD_GATEWAY.into_response(),
    };
    if !pfcp::response_accepted(&resp) {
        return StatusCode::BAD_GATEWAY.into_response();
    }

    if let Some(c) = smf.contexts.lock().unwrap().get_mut(&sm_ref) {
        c.gnb = Some((gnb_teid, gnb_addr));
        tracing::info!(
            %sm_ref,
            ue_ip = %c.ue_ip,
            uplink_teid = c.n3_teid,
            gnb_teid,
            "updated SM context; N4 downlink installed"
        );
    }
    StatusCode::OK.into_response()
}

/// Deactivate a session's downlink user-plane connection (AN release): an N4
/// Session Modification that DROPs downlink at the UPF and clears the stored gNB
/// target. The session and its uplink path persist for a later Service Request.
async fn deactivate_up(smf: &Arc<SmfState>, sm_ref: &str) -> StatusCode {
    let up_seid = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(sm_ref) {
            Some(c) => c.up_seid,
            None => return StatusCode::NOT_FOUND,
        }
    };
    let seq = smf.next_seq();
    let req = pfcp::session_deactivate_request(up_seid, seq, FAR_ID);
    let resp = match smf.transact(&req, seq).await {
        Some(r) => r,
        None => return StatusCode::BAD_GATEWAY,
    };
    if !pfcp::response_accepted(&resp) {
        return StatusCode::BAD_GATEWAY;
    }
    if let Some(c) = smf.contexts.lock().unwrap().get_mut(sm_ref) {
        c.gnb = None;
        tracing::info!(%sm_ref, up_seid, "deactivated UP connection (AN release); downlink buffered at the UPF");
    }
    StatusCode::OK
}

/// Set up (or release) an **indirect data forwarding** tunnel for an N2 handover
/// (TS 23.502 §4.9.1.3.3). With `release`, the forwarding session is deleted;
/// otherwise the SMF establishes a UPF forwarding session toward the target gNB's
/// DL forwarding F-TEID and returns the UPF-allocated ingress F-TEID the source
/// gNB forwards to.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndirectForwardingReq {
    #[serde(default)]
    target_n3_teid: Option<String>,
    #[serde(default)]
    target_n3_addr: Option<Ipv4Addr>,
    #[serde(default)]
    release: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct IndirectForwardingRsp {
    fwd_n3_teid: String,
    fwd_n3_addr: Ipv4Addr,
}

async fn indirect_forwarding(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
    Json(req): Json<IndirectForwardingReq>,
) -> axum::response::Response {
    if req.release {
        // Tear the forwarding session down (idempotent: no tunnel → 204).
        let fwd_seid = smf.contexts.lock().unwrap().get_mut(&sm_ref).and_then(|c| c.indirect_fwd.take());
        let Some(fwd_seid) = fwd_seid else {
            return StatusCode::NO_CONTENT.into_response();
        };
        let seq = smf.next_seq();
        match smf.transact(&pfcp::session_deletion_request(fwd_seid, seq), seq).await {
            Some(r) if pfcp::response_accepted(&r) => {
                tracing::info!(%sm_ref, "released the indirect forwarding tunnel");
                return StatusCode::NO_CONTENT.into_response();
            }
            _ => return StatusCode::BAD_GATEWAY.into_response(),
        }
    }
    // Set up: needs the target gNB's DL forwarding F-TEID.
    let (Some(teid_hex), Some(target_addr)) = (req.target_n3_teid, req.target_n3_addr) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(target_teid) = u32::from_str_radix(teid_hex.trim_start_matches("0x"), 16) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if smf.contexts.lock().unwrap().get(&sm_ref).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
    let seq = smf.next_seq();
    let est = pfcp::session_establishment_request_indirect_forwarding(
        cp_seid,
        seq,
        smf.smf_ip,
        target_teid,
        target_addr,
    );
    let resp = match smf.transact(&est, seq).await {
        Some(r) => r,
        None => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let Some(session) = pfcp::parse_session_establishment_response(&resp) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if let Some(c) = smf.contexts.lock().unwrap().get_mut(&sm_ref) {
        c.indirect_fwd = Some(session.up_seid);
    }
    tracing::info!(
        %sm_ref,
        ingress_teid = format!("{:08x}", session.n3_teid),
        target_teid = format!("{target_teid:08x}"),
        "indirect forwarding tunnel up (source → UPF → target)"
    );
    (
        StatusCode::OK,
        Json(IndirectForwardingRsp {
            fwd_n3_teid: format!("{:08x}", session.n3_teid),
            fwd_n3_addr: session.n3_addr,
        }),
    )
        .into_response()
}

/// `Nsmf_PDUSession_ReleaseSMContext` (TS 29.502 §5.2.2.4): tear the N4 session
/// down at the UPF and drop the SM context. Driven by the AMF on deregistration.
async fn release_sm_context(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
) -> Result<StatusCode, SbiProblem> {
    let (up_seid, supi, psi, sm_policy, reserved_gfbr, charging) = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => (
                c.up_seid,
                c.supi.clone(),
                c.pdu_session_id,
                c.sm_policy.clone(),
                c.reserved_gfbr,
                c.charging.clone(),
            ),
            None => {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "CONTEXT_NOT_FOUND",
                    "unknown SM context",
                ))
            }
        }
    };
    let seq = smf.next_seq();
    let del = pfcp::session_deletion_request(up_seid, seq);
    // Keep the context if the UPF is unreachable (the AMF may retry); a non-accepted
    // answer means the UPF already lost the session — drop our side anyway.
    let resp = smf.transact(&del, seq).await.ok_or_else(|| {
        problem(StatusCode::BAD_GATEWAY, "UPF_NOT_RESPONDING", "no PFCP deletion response")
    })?;
    if !pfcp::response_accepted(&resp) {
        tracing::warn!(%sm_ref, up_seid, "UPF did not accept the N4 deletion (already gone?)");
    }
    // Final usage reports: the session URR plus each per-flow URR. Logged, and —
    // when the session has a charging session — released toward the CHF with the
    // final used-unit containers (best-effort, off the path).
    let usages = pfcp::usages_from_deletion_response(&resp);
    if let Some((total, ul, dl)) = pfcp::usage_from_deletion_response(&resp) {
        tracing::info!(%sm_ref, up_seid, total_bytes = total, uplink_bytes = ul, downlink_bytes = dl, urrs = usages.len(), "session usage report");
    }
    if let Some((chf_base, charging_ref)) = charging {
        let release = sbi_core::nchf::ChargingDataRequest {
            subscriber_identifier: supi.clone(),
            pdu_session_charging_information: None,
            used_unit_containers: usages.iter().map(container_for).collect(),
        };
        tokio::spawn(async move {
            match sbi_core::nchf::ChfClient::new(chf_base).release(&charging_ref, &release).await {
                Ok(()) => tracing::info!(charging_ref = %charging_ref, "charging session released at the CHF"),
                Err(e) => tracing::warn!("Nchf release failed: {e}"),
            }
        });
    }
    smf.contexts.lock().unwrap().remove(&sm_ref);
    // Free the GFBR admission reservation.
    smf.release_gfbr(reserved_gfbr);
    // Purge the serving-SMF registration (Nudm_UECM). Best-effort, off the path.
    spawn_uecm_purge(smf.nrf_base.clone(), supi, psi);
    // Delete the PCF SM policy association (Npcf_SMPolicyControl_Delete), if the
    // session had one. Best-effort, off the path.
    if let Some((pcf_base, policy_id)) = sm_policy {
        spawn_sm_policy_delete(pcf_base, policy_id);
    }
    tracing::info!(%sm_ref, up_seid, "released SM context; N4 session deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// Map one URR usage volume to an Nchf used-unit container. Rating-group
/// convention (see `sbi_core::nchf`): the session-level URR is rating group `0`;
/// a per-flow URR (`PER_FLOW_URR_BASE + qfi`) is rating group `qfi`.
fn container_for(u: &pfcp::UsageVolume) -> sbi_core::nchf::UsedUnitContainer {
    sbi_core::nchf::UsedUnitContainer {
        rating_group: u.urr_id.checked_sub(pfcp::PER_FLOW_URR_BASE).unwrap_or(0),
        uplink_volume: u.uplink,
        downlink_volume: u.downlink,
        total_volume: u.total,
    }
}

/// Consume **UPF-initiated Session Report Requests** (volume-threshold usage
/// reports, design/59): ack each toward the UPF and relay the usage to the CHF as
/// an Nchf update (the mid-session charging trigger). Spawned once alongside the
/// SBI server; ends if the N4 reader closes.
pub async fn handle_usage_reports(smf: Arc<SmfState>) {
    loop {
        let report = { smf.reports_rx.lock().await.recv().await };
        let Some(report) = report else { break };
        // A Downlink Data Report: downlink data arrived for a CM-IDLE UE — ack it
        // and ask the AMF to page the UE (TS 23.502 §4.2.3.3).
        if let Some((cp_seid, seq)) = pfcp::parse_dl_data_report(&report) {
            handle_dl_data_report(&smf, cp_seid, seq).await;
            continue;
        }
        let Some((cp_seid, seq, usage)) = pfcp::parse_session_report_request(&report) else {
            continue;
        };
        // The report addresses the session by OUR (CP) F-SEID.
        let ctx = {
            let ctxs = smf.contexts.lock().unwrap();
            ctxs.values()
                .find(|c| c.cp_seid == cp_seid)
                .map(|c| (c.up_seid, c.supi.clone(), c.charging.clone()))
        };
        let Some((up_seid, supi, charging)) = ctx else {
            tracing::warn!(cp_seid, "usage report for an unknown session — dropped");
            continue;
        };
        // Ack toward the UPF (the usage stands measured either way).
        if let Err(e) = smf.sock.send(&pfcp::session_report_response(up_seid, seq)).await {
            tracing::warn!("session report ack send error: {e}");
        }
        tracing::info!(
            up_seid,
            total_bytes = usage.total,
            uplink_bytes = usage.uplink,
            downlink_bytes = usage.downlink,
            "usage threshold report from the UPF"
        );
        // Relay to the CHF (Nchf update) when the session is billed.
        if let Some((chf_base, charging_ref)) = charging {
            let update = sbi_core::nchf::ChargingDataRequest {
                subscriber_identifier: supi,
                pdu_session_charging_information: None,
                used_unit_containers: vec![container_for(&usage)],
            };
            match sbi_core::nchf::ChfClient::new(chf_base).update(&charging_ref, &update).await {
                Ok(()) => tracing::info!(charging_ref = %charging_ref, "usage relayed to the CHF"),
                Err(e) => tracing::warn!("Nchf update failed: {e}"),
            }
        }
    }
}

/// Downlink Data Report handling: ack the UPF, then ask the serving AMF to page
/// the CM-IDLE UE (Namf_Communication_N1N2MessageTransfer). The UE answers with a
/// Service Request, which re-activates the session — and the UPF flushes the
/// buffered downlink onto the restored tunnel.
async fn handle_dl_data_report(smf: &Arc<SmfState>, cp_seid: u64, seq: u32) {
    let ctx = {
        let ctxs = smf.contexts.lock().unwrap();
        ctxs.values().find(|c| c.cp_seid == cp_seid).map(|c| (c.up_seid, c.supi.clone()))
    };
    let Some((up_seid, supi)) = ctx else {
        tracing::warn!(cp_seid, "downlink data report for an unknown session — dropped");
        return;
    };
    if let Err(e) = smf.sock.send(&pfcp::session_report_response(up_seid, seq)).await {
        tracing::warn!("downlink data report ack send error: {e}");
    }
    tracing::info!(up_seid, "downlink data for a CM-IDLE UE — requesting paging at the AMF");
    // Discover the serving AMF and ask it to page (best-effort, off the path).
    match discover_endpoint(&smf.nrf_base, "AMF").await {
        Ok(amf) => {
            let url = format!("{amf}/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages");
            match sbi_core::sbi_client().post(url).json(&serde_json::json!({})).send().await {
                Ok(r) if r.status().is_success() => tracing::info!("AMF paging requested"),
                Ok(r) => tracing::warn!(status = %r.status(), "AMF paging request refused"),
                Err(e) => tracing::warn!("AMF paging request failed: {e}"),
            }
        }
        Err(e) => tracing::warn!("no AMF to page ({e})"),
    }
}

/// Re-authorize this session's policy at the PCF (`Npcf_SMPolicyControl_Update`)
/// and refresh the sm-context's stored QoS. A trigger for a **mid-session policy
/// change** (e.g. an operator/OAM policy update landing in the UDR): the PCF
/// re-reads the subscriber's Nudr policy-data and returns the current decision.
///
/// When the QoS changed, the SMF propagates it two ways: onto the **user plane**
/// (an N4 Session Modification with an Update QER re-rates the UPF's AMBR policer),
/// and to the **RAN/UE** via the serving AMF (Namf_Communication →
/// N2 PDU Session Resource Modify + N1 PDU Session Modification Command,
/// best-effort). Returns `200` + the (possibly changed) decision; `204` when the
/// session used the sm-data fallback (no PCF association); `404` for an unknown
/// context.
async fn refresh_sm_policy(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
) -> Result<axum::response::Response, SbiProblem> {
    let (sm_policy, up_seid, old_policy, supi, psi) = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => {
                (c.sm_policy.clone(), c.up_seid, c.policy.clone(), c.supi.clone(), c.pdu_session_id)
            }
            None => {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "CONTEXT_NOT_FOUND",
                    "unknown SM context",
                ))
            }
        }
    };
    let Some((pcf_base, policy_id)) = sm_policy else {
        // sm-data fallback session — no PCF association to re-authorize.
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let update = sbi_core::npcf::PcfClient::new(pcf_base)
        .update_sm_policy(&policy_id, &sbi_core::npcf::SmPolicyUpdateContextData::default())
        .await
        .map_err(|e| {
            tracing::warn!(%sm_ref, "PCF SM policy update failed: {e}");
            problem(StatusCode::BAD_GATEWAY, "PCF_UNREACHABLE", "Npcf SM policy update failed")
        })?;
    // The Update response is a partial delta — merge it onto the stored policy to
    // recover the full authorized decision, keeping any attribute the PCF omitted.
    let mut decision = old_policy.clone();
    decision.apply(&update);
    let changed = old_policy != decision;

    // Propagate a changed session AMBR onto the user plane: re-rate the UPF's QER.
    let old_ambr = ambr_bps(&old_policy);
    let new_ambr = ambr_bps(&decision);
    if new_ambr != old_ambr {
        if let Some(ambr) = new_ambr {
            let seq = smf.next_seq();
            let req = pfcp::session_qer_update_request(up_seid, seq, ambr);
            match smf.transact(&req, seq).await {
                Some(resp) if pfcp::response_accepted(&resp) => tracing::info!(
                    %sm_ref, up_seid, "N4 QER re-rated: session AMBR now {}/{} bps",
                    ambr.uplink_bps, ambr.downlink_bps
                ),
                _ => tracing::warn!(%sm_ref, up_seid, "N4 QER update not accepted by the UPF"),
            }
        }
    }
    // Propagate per-flow (GBR) changes onto the user plane: add/re-rate/remove the
    // UPF's per-flow QERs to match the new decision.
    let old_flows = flow_qers(&old_policy);
    let new_flows = flow_qers(&decision);
    let (create, update, remove) = diff_flows(&old_flows, &new_flows);
    if !create.is_empty() || !update.is_empty() || !remove.is_empty() {
        let seq = smf.next_seq();
        let req = pfcp::session_flow_modification_request(up_seid, seq, &create, &update, &remove);
        match smf.transact(&req, seq).await {
            Some(resp) if pfcp::response_accepted(&resp) => tracing::info!(
                %sm_ref, up_seid, added = create.len(), updated = update.len(), removed = remove.len(),
                "N4 per-flow QERs updated"
            ),
            _ => tracing::warn!(%sm_ref, up_seid, "N4 per-flow QER update not accepted by the UPF"),
        }
    }
    // GBR flows fully gone from the new policy — released toward the RAN/UE (distinct
    // from the N4 `remove` above, which also covers filter-changed/re-provisioned QFIs).
    let released_qfis: Vec<u8> = old_flows
        .iter()
        .filter(|o| !new_flows.iter().any(|n| n.qfi == o.qfi))
        .map(|o| o.qfi)
        .collect();
    // Adjust the GFBR reservation to the new decision (best-effort — the PCF already
    // authorized it, so a mid-session increase isn't admission-refused here).
    let new_gfbr = decision_gfbr(&decision);
    // Refresh the sm-context's authoritative QoS record.
    if let Some(c) = smf.contexts.lock().unwrap().get_mut(&sm_ref) {
        if c.reserved_gfbr != new_gfbr {
            smf.adjust_gfbr(c.reserved_gfbr, new_gfbr);
            c.reserved_gfbr = new_gfbr;
        }
        c.policy = decision.clone();
    }
    // Signal the change to the RAN/UE via the serving AMF (Namf_Communication →
    // N2 PDU Session Resource Modify + N1 PDU Session Modification Command).
    // Best-effort, off the response path — only when the QoS actually changed.
    if changed {
        tracing::info!(%sm_ref, flows = decision.qos_flows.len(), released = ?released_qfis, "SM policy refreshed from PCF (QoS changed)");
        spawn_amf_pdu_modify(smf.nrf_base.clone(), supi, psi, decision.clone(), released_qfis);
    }
    Ok((StatusCode::OK, Json(decision)).into_response())
}

/// Push a mid-session QoS change to the serving AMF (Namf_Communication), which
/// signals the RAN/UE (N2 PDU Session Resource Modify + N1 PDU Session Modification
/// Command), including any `released_qfis` (GBR flows to tear down). Best-effort,
/// spawned off the refresh path; the AMF is discovered via the NRF (single-AMF demo
/// — a real deployment would use the UECM serving AMF).
fn spawn_amf_pdu_modify(
    nrf_base: String,
    supi: String,
    psi: u8,
    decision: sbi_core::npcf::SmPolicyDecision,
    released_qfis: Vec<u8>,
) {
    tokio::spawn(async move {
        let amf = match discover_endpoint(&nrf_base, "AMF").await {
            Ok(base) => base,
            Err(e) => {
                tracing::warn!(psi, "PDU modify: no AMF to notify ({e})");
                return;
            }
        };
        let body = serde_json::json!({
            "pduSessionId": psi,
            "sessionAmbr": decision.session_ambr,
            "qosFlows": decision.qos_flows,
            "releasedQfis": released_qfis,
        });
        let url = format!("{amf}/namf-comm/v1/ue-contexts/{supi}/modify");
        match sbi_core::sbi_client().post(url).json(&body).send().await {
            Ok(r) if r.status().is_success() => {
                tracing::info!(psi, "notified serving AMF of the mid-session QoS change")
            }
            Ok(r) => tracing::warn!(psi, status = %r.status(), "AMF PDU modify rejected"),
            Err(e) => tracing::warn!(psi, "AMF PDU modify call failed: {e}"),
        }
    });
}

/// The aggregate GFBR `(downlink_bps, uplink_bps)` a decision's GBR flows require —
/// the input to GFBR admission control. A flow whose GFBR strings don't parse
/// contributes 0 (it can't be admission-checked).
fn decision_gfbr(decision: &sbi_core::npcf::SmPolicyDecision) -> (u64, u64) {
    decision.qos_flows.iter().filter_map(|f| f.gbr.as_ref()).fold((0u64, 0u64), |(dl, ul), g| {
        (
            dl.saturating_add(sbi_core::npcf::bitrate_to_bps(&g.gfbr_dl).unwrap_or(0)),
            ul.saturating_add(sbi_core::npcf::bitrate_to_bps(&g.gfbr_ul).unwrap_or(0)),
        )
    })
}

/// The per-flow GBR QERs (classifier + MFBR) for the UPF, from a decision's GBR
/// flows that carry a packet filter. Non-GBR / filterless flows stay on the session
/// AMBR; a flow whose MFBR strings don't parse is skipped.
fn flow_qers(decision: &sbi_core::npcf::SmPolicyDecision) -> Vec<pfcp::FlowQer> {
    decision
        .qos_flows
        .iter()
        .filter_map(|f| {
            let gbr = f.gbr.as_ref()?;
            let filter = f.filter.as_ref()?;
            Some(pfcp::FlowQer {
                qfi: f.qfi,
                filter: pfcp::FlowFilter {
                    protocol: filter.protocol,
                    port_low: filter.port_low,
                    port_high: filter.port_high,
                },
                mfbr_dl_bps: sbi_core::npcf::bitrate_to_bps(&gbr.mfbr_dl)?,
                mfbr_ul_bps: sbi_core::npcf::bitrate_to_bps(&gbr.mfbr_ul)?,
            })
        })
        .collect()
}

/// Diff the old vs new per-flow QERs into `(create, update, remove_qfis)` for a
/// mid-session flow modification: a new/filter-changed QFI is created (and, if the
/// filter changed, its old flow removed), an MFBR-only change is an update, and a
/// dropped QFI is removed. The UPF applies remove → create → update.
fn diff_flows(
    old: &[pfcp::FlowQer],
    new: &[pfcp::FlowQer],
) -> (Vec<pfcp::FlowQer>, Vec<pfcp::FlowQer>, Vec<u8>) {
    let (mut create, mut update, mut remove) = (Vec::new(), Vec::new(), Vec::new());
    for n in new {
        match old.iter().find(|o| o.qfi == n.qfi) {
            None => create.push(*n),
            Some(o) if o.filter != n.filter => create.push(*n),
            Some(o) if (o.mfbr_dl_bps, o.mfbr_ul_bps) != (n.mfbr_dl_bps, n.mfbr_ul_bps) => {
                update.push(*n)
            }
            Some(_) => {}
        }
    }
    for o in old {
        if !new.iter().any(|n| n.qfi == o.qfi && n.filter == o.filter) {
            remove.push(o.qfi);
        }
    }
    (create, update, remove)
}

/// The session AMBR from a policy decision as a `pfcp::SessionAmbr` (bits/sec) for
/// the UPF's QER — `None` when the decision has no (parseable) session AMBR.
fn ambr_bps(decision: &sbi_core::npcf::SmPolicyDecision) -> Option<pfcp::SessionAmbr> {
    decision
        .session_ambr
        .as_ref()
        .and_then(|a| a.to_bps())
        .map(|(uplink_bps, downlink_bps)| pfcp::SessionAmbr { uplink_bps, downlink_bps })
}

/// Register this SMF as the serving SMF for `(supi, pdu_session_id)` at the UDM
/// (Nudm_UECM). Best-effort, spawned off the signaling path.
fn spawn_uecm_register(nrf_base: String, supi: String, pdu_session_id: u8, dnn: String) {
    tokio::spawn(async move {
        let reg = sbi_core::nudm::SmfRegistration {
            smf_instance_id: SMF_INSTANCE_ID.clone(),
            pdu_session_id,
            dnn,
        };
        match discover_udm(&nrf_base).await {
            Ok(udm) => {
                if let Err(e) =
                    sbi_core::nudm::NudmClient::new(udm).uecm_register_smf(&supi, &reg).await
                {
                    tracing::warn!(psi = pdu_session_id, "UECM SMF registration failed: {e}");
                } else {
                    tracing::info!(psi = pdu_session_id, "UECM: registered as the serving SMF");
                }
            }
            Err(e) => tracing::warn!("UECM SMF registration skipped (no UDM): {e}"),
        }
    });
}

/// Purge this SMF's serving-SMF registration for the PDU session. Best-effort.
fn spawn_uecm_purge(nrf_base: String, supi: String, pdu_session_id: u8) {
    tokio::spawn(async move {
        match discover_udm(&nrf_base).await {
            Ok(udm) => {
                match sbi_core::nudm::NudmClient::new(udm)
                    .uecm_deregister_smf(&supi, pdu_session_id)
                    .await
                {
                    Ok(true) => tracing::info!(psi = pdu_session_id, "UECM: serving-SMF registration purged"),
                    Ok(false) => {} // already gone (e.g. the subscriber was withdrawn)
                    Err(e) => tracing::warn!(psi = pdu_session_id, "UECM SMF purge failed: {e}"),
                }
            }
            Err(e) => tracing::warn!("UECM SMF purge skipped (no UDM): {e}"),
        }
    });
}

/// Delete the PCF SM policy association for a released session. Best-effort.
fn spawn_sm_policy_delete(pcf_base: String, policy_id: String) {
    tokio::spawn(async move {
        match sbi_core::npcf::PcfClient::new(pcf_base).delete_sm_policy(&policy_id).await {
            Ok(()) => tracing::info!(%policy_id, "PCF: SM policy association deleted"),
            Err(e) => tracing::warn!(%policy_id, "PCF SM policy delete failed: {e}"),
        }
    });
}

/// Whether a gNB downlink target is plausibly routable (not a zero TEID, nor an
/// unspecified / broadcast / multicast address).
fn valid_gnb_target(teid: u32, ip: Ipv4Addr) -> bool {
    teid != 0 && !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast()
}

/// Mask a SUPI for logs — keep the scheme + a short prefix, redact the rest (PII).
fn masked_supi(supi: &str) -> String {
    match supi.split_once('-') {
        Some((scheme, rest)) if rest.len() > 5 => format!("{scheme}-{}***", &rest[..5]),
        _ => "***".to_string(),
    }
}

/// The `(sst, optional SD, DNN)` triples this SMF serves — advertised in its NRF
/// profile so the AMF can select it by `(S-NSSAI, DNN)`. Config in production;
/// here the demo slice + DNN, matching the UDR's smf-selection provisioning.
const SERVED_SLICES: &[(u8, Option<&str>, &str)] = &[(1, Some("010203"), "internet")];

/// Register this SMF's `nsmf-pdusession` service with the NRF (advertising the
/// slices/DNNs it serves so the AMF can select it), keeping it alive via the
/// NRF-assigned heartbeat.
pub async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, SmfInfo};
    let mut profile = NfProfile::new(SMF_INSTANCE_ID.clone(), "SMF", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "nsmf-pdusession-1".into(),
        service_name: "nsmf-pdusession".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    profile.smf_info = Some(SmfInfo::from_served(SERVED_SLICES));
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bogus_gnb_targets() {
        assert!(valid_gnb_target(0x5678, Ipv4Addr::new(10, 0, 0, 9)));
        assert!(!valid_gnb_target(0, Ipv4Addr::new(10, 0, 0, 9)), "zero TEID");
        assert!(!valid_gnb_target(0x5678, Ipv4Addr::UNSPECIFIED), "0.0.0.0");
        assert!(!valid_gnb_target(0x5678, Ipv4Addr::BROADCAST), "255.255.255.255");
        assert!(!valid_gnb_target(0x5678, Ipv4Addr::new(224, 0, 0, 1)), "multicast");
    }

    #[test]
    fn masks_supi_for_logging() {
        assert_eq!(masked_supi("imsi-999700000000001"), "imsi-99970***");
        assert_eq!(masked_supi("garbage"), "***");
    }

    /// Spin an NRF + UDR (in-memory, provisioned) + UDM chain; returns the NRF base
    /// the SMF should use. The demo subscriber may use DNN "internet" on slice
    /// sst=1/sd=010203 with a 1/2 Gbps session AMBR.
    /// Returns (nrf_base, udr_base).
    async fn spin_subscription_backend(supi: &str, plmn: &str) -> (String, String) {
        use subscriber_db::{DataSet, ProvisionedDataStore, SubscriberStore};

        let store = Arc::new(subscriber_db::InMemoryStore::new());
        store
            .put_provisioned(
                DataSet::SmfSelection,
                supi,
                plmn,
                &serde_json::json!({
                    "subscribedSnssaiInfos": {
                        "1-010203": { "dnnInfos": [ { "dnn": "internet" } ] }
                    }
                }),
            )
            .unwrap();
        store
            .put_provisioned(
                DataSet::Sm,
                supi,
                plmn,
                &serde_json::json!([{
                    "singleNssai": { "sst": 1, "sd": "010203" },
                    "dnnConfigurations": {
                        "internet": {
                            "sessionAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" },
                            "5gQosProfile": { "5qi": 9, "arp": { "priorityLevel": 8 } },
                            "qosFlows": [{
                                "qfi": 2, "fiveQi": 1, "arpPriority": 5, "preEmptCap": true,
                                "gbr": { "gfbrDl": "100 Mbps", "gfbrUl": "100 Mbps",
                                         "mfbrDl": "200 Mbps", "mfbrUl": "200 Mbps" }
                            }]
                        }
                    }
                }]),
            )
            .unwrap();
        let store: Arc<dyn SubscriberStore> = store;
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udr_l, sbi_core::nudr::router(store)).await.unwrap() });

        let udr_base = format!("http://{udr_addr}");
        let udr = Arc::new(sbi_core::nudr::UdrClient::new(udr_base.clone()));
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udm_l, sbi_core::nudm::router(udr)).await.unwrap() });

        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let nrf_store = sbi_core::nnrf::NrfStore::default();
        tokio::spawn(async move { sbi_core::run_on(nrf_l, sbi_core::nnrf::router(nrf_store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");

        let mut profile = sbi_core::nnrf::NfProfile::new("udm-1", "UDM", udm_addr.ip().to_string());
        profile.nf_services = Some(vec![sbi_core::nnrf::NfService {
            service_instance_id: "nudm-1".into(),
            service_name: "nudm-sdm".into(),
            scheme: "http".into(),
            ip_end_points: vec![sbi_core::nnrf::IpEndPoint {
                ipv4_address: Some(udm_addr.ip().to_string()),
                port: Some(udm_addr.port()),
            }],
        }]);
        sbi_core::nnrf::NrfClient::new(nrf_base.clone()).register(&profile).await.unwrap();
        (nrf_base, udr_base)
    }

    /// Spin an in-process PCF and register it with the NRF at `nrf_base`. With
    /// `udr_base`, the PCF sources policy from that UDR (Nudr policy-data); without,
    /// it uses its local demo policy. Returns its state (to watch the assoc count).
    async fn spin_pcf(nrf_base: &str, udr_base: Option<&str>) -> sbi_core::npcf::PcfState {
        let mut state = sbi_core::npcf::PcfState::new(sbi_core::npcf::PolicyConfig::demo());
        if let Some(udr) = udr_base {
            state = state.with_udr(Arc::new(sbi_core::nudr::UdrClient::new(udr.to_string())));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = state.clone();
        tokio::spawn(async move {
            sbi_core::run_on(listener, sbi_core::npcf::router(served)).await.unwrap()
        });
        let mut profile = sbi_core::nnrf::NfProfile::new("pcf-1", "PCF", addr.ip().to_string());
        profile.nf_services = Some(vec![sbi_core::nnrf::NfService {
            service_instance_id: "npcf-smpolicycontrol-1".into(),
            service_name: "npcf-smpolicycontrol".into(),
            scheme: "http".into(),
            ip_end_points: vec![sbi_core::nnrf::IpEndPoint {
                ipv4_address: Some(addr.ip().to_string()),
                port: Some(addr.port()),
            }],
        }]);
        sbi_core::nnrf::NrfClient::new(nrf_base.to_string()).register(&profile).await.unwrap();
        state
    }

    /// Spin a real CHF (the `sbi_core::nchf` router), registered with the NRF as
    /// nf-type `CHF`. Returns the shared CDR store the test can inspect.
    async fn spin_chf(nrf_base: &str) -> sbi_core::nchf::ChfState {
        let state = sbi_core::nchf::ChfState::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = state.clone();
        tokio::spawn(async move {
            sbi_core::run_on(listener, sbi_core::nchf::router(served)).await.unwrap()
        });
        let mut profile = sbi_core::nnrf::NfProfile::new("chf-1", "CHF", addr.ip().to_string());
        profile.nf_services = Some(vec![sbi_core::nnrf::NfService {
            service_instance_id: "nchf-convergedcharging-1".into(),
            service_name: "nchf-convergedcharging".into(),
            scheme: "http".into(),
            ip_end_points: vec![sbi_core::nnrf::IpEndPoint {
                ipv4_address: Some(addr.ip().to_string()),
                port: Some(addr.port()),
            }],
        }]);
        sbi_core::nnrf::NrfClient::new(nrf_base.to_string()).register(&profile).await.unwrap();
        state
    }

    /// Spin a mock AMF that records `Namf_Communication` PDU-modify posts, registered
    /// with the NRF as nf-type `AMF`. Returns the shared record of received bodies.
    async fn spin_mock_amf(nrf_base: &str) -> Arc<Mutex<Vec<serde_json::Value>>> {
        async fn record(
            State(rec): State<Arc<Mutex<Vec<serde_json::Value>>>>,
            Json(body): Json<serde_json::Value>,
        ) -> StatusCode {
            rec.lock().unwrap().push(body);
            StatusCode::ACCEPTED
        }
        let recorder: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/namf-comm/v1/ue-contexts/{supi}/modify", post(record))
            .with_state(recorder.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(l, app).await.unwrap() });
        let mut profile = sbi_core::nnrf::NfProfile::new("amf-mock", "AMF", addr.ip().to_string());
        profile.nf_services = Some(vec![sbi_core::nnrf::NfService {
            service_instance_id: "namf-callback-1".into(),
            service_name: "namf-callback".into(),
            scheme: "http".into(),
            ip_end_points: vec![sbi_core::nnrf::IpEndPoint {
                ipv4_address: Some(addr.ip().to_string()),
                port: Some(addr.port()),
            }],
        }]);
        sbi_core::nnrf::NrfClient::new(nrf_base.to_string()).register(&profile).await.unwrap();
        recorder
    }

    /// Full Nsmf → N4 spine: an in-process UPF, the SMF as PFCP client + SBI server,
    /// driven over HTTP — with the subscription checked against a real UDR/UDM chain.
    /// CreateSMContext authorizes the DNN and establishes the session (UPF allocates
    /// the uplink TEID); UpdateSMContext installs the gNB downlink target on the UPF.
    #[tokio::test]
    async fn pdu_session_create_then_update_drives_n4() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);

        // In-process UPF: an N4 UDP loop over a shared UpfState the test can inspect.
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;

        // SMF: connect, associate, serve Nsmf.
        let smf =
            Arc::new(SmfState::connect(upf_addr, Ipv4Addr::new(127, 0, 0, 1), nrf_base).await.unwrap());
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        // AMF → SMF: CreateSMContext, with the UE's requested slice.
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(created.up_n3_teid, "00000001", "UPF allocated the first N3 TEID");
        // The SMF recorded itself as the serving SMF for the session (Nudm_UECM).
        // The registration is spawned off the create path — poll briefly.
        let udr = sbi_core::nudr::UdrClient::new(udr_base);
        let mut smf_reg = None;
        for _ in 0..50 {
            smf_reg = udr.get_smf_registration("imsi-999700000000001", 5).await.unwrap();
            if smf_reg.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let reg = smf_reg.expect("serving-SMF registration recorded");
        assert_eq!(reg.get("dnn").and_then(|v| v.as_str()), Some("internet"));
        assert_eq!(reg.get("pduSessionId").and_then(|v| v.as_u64()), Some(5));
        // The serving slice (== validated requested slice) + AMBR ride back for the
        // AMF's N1 accept.
        assert_eq!(created.s_nssai.sst, 1);
        assert_eq!(created.s_nssai.sd.as_deref(), Some("010203"));
        let ambr = created.session_ambr.as_ref().expect("subscribed session AMBR");
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("1 Gbps", "2 Gbps"));
        // The default (QFI 1, 5QI 9) + the provisioned GBR flow (QFI 2, 5QI 1) ride back.
        assert_eq!(created.qos_flows.len(), 2, "default + GBR flow");
        assert_eq!((created.qos_flows[0].qfi, created.qos_flows[0].five_qi), (1, 9));
        assert_eq!((created.qos_flows[1].qfi, created.qos_flows[1].five_qi), (2, 1));
        assert!(created.qos_flows[1].gbr.is_some(), "the second flow is GBR");
        assert_eq!(
            created.ue_ipv4_addr,
            Ipv4Addr::new(10, 45, 0, 2),
            "SMF allocated a UE IP from the pool"
        );
        assert_eq!(upf_state.lock().unwrap().session_count(), 1, "N4 session established");

        // AMF → SMF: UpdateSMContext with the gNB's downlink F-TEID (from N2 setup).
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"00005678","gnbN3Addr":"10.0.0.9"}))
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "UpdateSMContext succeeded");

        // The UPF now has the downlink installed for the session, reachable both by
        // UP-SEID and — the N6 datapath's view — by routing on the UE's assigned IP.
        assert_eq!(
            upf_state.lock().unwrap().downlink_for(1),
            Some((0x5678, Ipv4Addr::new(10, 0, 0, 9))),
            "N4 modification installed the gNB downlink target"
        );
        assert_eq!(
            upf_state.lock().unwrap().route_downlink(Ipv4Addr::new(10, 45, 0, 2)),
            Some((0x5678, Ipv4Addr::new(10, 0, 0, 9))),
            "UPF routes an N6 downlink packet to the gNB by the UE's assigned IP"
        );

        // AMF → SMF: a second UpdateSMContext re-pointing to a DIFFERENT gNB — a
        // handover / path switch. The modification carries a GTP-U End Marker request
        // (PFCPSMReq-Flags SNDEM); the UPF tolerates it and re-points the downlink.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"00009abc","gnbN3Addr":"10.0.0.10"}))
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "re-point UpdateSMContext succeeded");
        assert_eq!(
            upf_state.lock().unwrap().downlink_for(1),
            Some((0x9abc, Ipv4Addr::new(10, 0, 0, 10))),
            "the downlink followed the handover to the new gNB tunnel"
        );

        // AMF → SMF: ReleaseSMContext (deregistration) — the N4 session goes too.
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");
        assert_eq!(upf_state.lock().unwrap().session_count(), 0, "N4 session deleted at the UPF");
        // The serving-SMF registration is purged (spawned off the release path).
        let mut gone = false;
        for _ in 0..50 {
            if udr.get_smf_registration("imsi-999700000000001", 5).await.unwrap().is_none() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(gone, "serving-SMF registration purged on release");

        // A second release of the same context → 404.
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404, "released context is gone");
    }

    /// With a PCF registered, the SMF sources the SM policy from it: a policy
    /// association is created at CreateSMContext and deleted at release. (The demo
    /// PCF returns the same QoS as sm-data, so the association count — not the flow
    /// values — is what distinguishes the PCF path from the fallback.)
    #[tokio::test]
    async fn pcf_drives_sm_policy_and_release_deletes_it() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let pcf = spin_pcf(&nrf_base, None).await;

        let smf = Arc::new(
            SmfState::connect(upf_addr, Ipv4Addr::new(127, 0, 0, 1), nrf_base).await.unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // The PCF's decision drove the response, and its association was created
        // synchronously on the create path.
        assert_eq!(pcf.association_count(), 1, "SMF created a PCF SM policy association");
        let ambr = created.session_ambr.as_ref().expect("PCF session AMBR");
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("1 Gbps", "2 Gbps"));
        assert_eq!(created.qos_flows.len(), 2, "PCF default + GBR flow");
        assert!(created.qos_flows.iter().any(|f| f.gbr.is_some()), "a GBR flow from the PCF");
        // The GBR flow's per-flow QER (classifier + MFBR) was installed at the UPF.
        assert_eq!(
            upf_state.lock().unwrap().flow_qfis(1),
            vec![2],
            "the UPF polices the GBR flow (QFI 2) per-flow"
        );

        // Release deletes the PCF association (spawned off the release path — poll).
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");
        let mut deleted = false;
        for _ in 0..50 {
            if pcf.association_count() == 0 {
                deleted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(deleted, "PCF SM policy association deleted on release");
    }

    /// GFBR admission control: a session whose GBR flow's GFBR exceeds the remaining
    /// budget is refused (503 → 5GSM #26); releasing a session frees the budget.
    #[tokio::test]
    async fn gfbr_admission_control_refuses_when_budget_exhausted() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        // Local demo PCF: its GBR flow has GFBR 100 Mbps each way.
        let _pcf = spin_pcf(&nrf_base, None).await;
        // Budget = exactly one demo GBR flow.
        let smf = Arc::new(
            SmfState::connect(upf_addr, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap()
                .with_gfbr_budget(100_000_000, 100_000_000),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let create = |psi: u8| {
            client
                .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
                .json(&serde_json::json!({
                    "supi": "imsi-999700000000001", "pduSessionId": psi, "dnn": "internet",
                    "servingNetwork": { "mcc": "999", "mnc": "70" },
                    "sNssai": { "sst": 1, "sd": "010203" }
                }))
                .send()
        };

        // First GBR session fits the budget exactly.
        let r1 = create(5).await.unwrap();
        assert_eq!(r1.status().as_u16(), 201, "first GBR session admitted");
        let created: SmContextCreatedData = r1.json().await.unwrap();
        // The second would exceed it → refused (GFBR admission control).
        let r2 = create(6).await.unwrap();
        assert_eq!(r2.status().as_u16(), 503, "second GBR session refused (insufficient resources)");

        // Releasing the first frees the budget, so a new session is admitted again.
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");
        let r3 = create(6).await.unwrap();
        assert_eq!(r3.status().as_u16(), 201, "budget freed on release — new session admitted");
    }

    /// The full charging loop (design/59): CreateSMContext opens an Nchf charging
    /// session at the NRF-discovered CHF; a UPF volume-threshold Session Report
    /// Request is acked and relayed as an Nchf update; release closes the CDR with
    /// the unreported remainder — the CDR totals exactly what moved, no
    /// double-billing.
    #[tokio::test]
    async fn charging_bills_threshold_reports_and_final_usage() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);

        // In-process UPF whose socket the test keeps a handle on, so it can play
        // the nf-upf reporter (send a UPF-initiated Session Report Request).
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upf_addr = upf_sock.local_addr().unwrap();
        let smf_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        {
            let upf_state = upf_state.clone();
            let upf_sock = upf_sock.clone();
            let smf_peer = smf_peer.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    *smf_peer.lock().unwrap() = Some(peer);
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, _udr) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let chf = spin_chf(&nrf_base).await;

        // SMF with a 1000-byte usage threshold + the usage-report handler running.
        let smf = Arc::new(
            SmfState::connect(upf_addr, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap()
                .with_usage_threshold(1000),
        );
        smf.associate().await.unwrap();
        tokio::spawn(handle_usage_reports(smf.clone()));
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        // CreateSMContext → the SMF opened a charging data session at the CHF.
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(chf.open_sessions(), 1, "charging session opened with the PDU session");
        let cdr_ref = "0"; // the CHF's first charging-data allocation
        let cdr = chf.cdr(cdr_ref).expect("CDR opened");
        assert_eq!(cdr.subscriber_identifier, "imsi-999700000000001");
        assert_eq!(
            cdr.pdu_session_charging_information.as_ref().map(|p| (p.pdu_session_id, p.dnn.as_str())),
            Some((5, "internet"))
        );

        // 1500 uplink bytes cross the 1000-byte threshold: the UPF flags a report;
        // the test sends it from the UPF socket (what nf-upf's reporter task does).
        assert!(upf_state.lock().unwrap().admit_uplink(1, 0, &[0u8; 1500]));
        let due = upf_state.lock().unwrap().take_due_report().expect("threshold crossed");
        let peer = smf_peer.lock().unwrap().expect("SMF's N4 address learned");
        upf_sock.send_to(&pfcp::session_report_request(&due, 99), peer).await.unwrap();

        // The SMF acks and relays: the CDR accumulates the mid-session usage.
        let mut billed = None;
        for _ in 0..50 {
            billed = chf.cdr(cdr_ref).and_then(|c| c.usage.get(&0).copied());
            if billed.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let billed = billed.expect("mid-session usage billed at the CHF");
        assert_eq!((billed.uplink_volume, billed.total_volume), (1500, 1500));

        // 400 more bytes (under the threshold), then release: the deletion report
        // carries only the unreported remainder.
        assert!(upf_state.lock().unwrap().admit_uplink(1, 0, &[0u8; 400]));
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");

        // The Nchf release is spawned off the path — poll for the closed CDR.
        let mut closed = None;
        for _ in 0..50 {
            closed = chf.cdr(cdr_ref).filter(|c| c.released);
            if closed.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let closed = closed.expect("CDR closed at release");
        assert_eq!(
            closed.usage[&0].total_volume,
            1900,
            "threshold report (1500) + final remainder (400) = the true total — no double-billing"
        );
        assert_eq!(chf.open_sessions(), 0);
    }

    /// A UDR-backed PCF + the SMF's refresh-policy trigger: a mid-session change to
    /// the subscriber's UDR policy-data is picked up by Npcf_SMPolicyControl_Update
    /// and lands in the SMF's response.
    #[tokio::test]
    async fn refresh_policy_applies_a_mid_session_udr_change() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, udr_base) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;
        // Provision the subscriber's SM policy-data (v1) in the same UDR, and back
        // the PCF with it.
        let udr = sbi_core::nudr::UdrClient::new(udr_base.clone());
        let v1 = serde_json::json!({ "default": {
            "sessionAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" },
            "qosFlows": [ { "qfi": 1, "fiveQi": 9 } ] } });
        udr.put_sm_policy_data("imsi-999700000000001", &v1).await.unwrap();
        let _pcf = spin_pcf(&nrf_base, Some(&udr_base)).await;
        // A mock AMF records the SMF's Namf_Communication PDU-modify notification.
        let amf_modifies = spin_mock_amf(&nrf_base).await;

        let smf = Arc::new(
            SmfState::connect(upf_addr, Ipv4Addr::new(127, 0, 0, 1), nrf_base).await.unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // Initial policy = the UDR's v1 (200/400 Mbps, one flow) — not the local demo.
        let ambr = created.session_ambr.as_ref().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("200 Mbps", "400 Mbps"));
        assert_eq!(created.qos_flows.len(), 1);
        // The AMBR was installed on the user plane as a QER (the UPF's first session
        // is up_seid 1).
        assert_eq!(
            upf_state.lock().unwrap().ambr_for(1),
            Some(pfcp::SessionAmbr { uplink_bps: 200_000_000, downlink_bps: 400_000_000 }),
            "UPF polices the v1 session AMBR"
        );
        assert!(
            upf_state.lock().unwrap().flow_qfis(1).is_empty(),
            "no per-flow QER for the v1 (non-GBR) policy"
        );

        // Mid-session change: reprovision the UDR policy-data (v2) — new session AMBR
        // plus a GBR flow (QFI 2) with a classifier.
        let v2 = serde_json::json!({ "default": {
            "sessionAmbr": { "uplink": "50 Mbps", "downlink": "100 Mbps" },
            "qosFlows": [
                { "qfi": 1, "fiveQi": 9 },
                { "qfi": 2, "fiveQi": 1, "gbr": {
                    "gfbrDl": "10 Mbps", "gfbrUl": "10 Mbps",
                    "mfbrDl": "20 Mbps", "mfbrUl": "20 Mbps" },
                  "filter": { "protocol": 17, "portLow": 5000, "portHigh": 5010 } }
            ] } });
        udr.put_sm_policy_data("imsi-999700000000001", &v2).await.unwrap();

        // refresh-policy re-authorizes via Npcf Update → the changed decision.
        let resp = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/refresh-policy",
                created.sm_context_ref
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "refresh succeeded");
        let updated: sbi_core::npcf::SmPolicyDecision = resp.json().await.unwrap();
        let ambr = updated.session_ambr.as_ref().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("50 Mbps", "100 Mbps"));
        assert_eq!(updated.qos_flows.len(), 2, "the mid-session change added a GBR flow");
        // The change reached the user plane: the SMF re-rated the UPF's QER...
        assert_eq!(
            upf_state.lock().unwrap().ambr_for(1),
            Some(pfcp::SessionAmbr { uplink_bps: 50_000_000, downlink_bps: 100_000_000 }),
            "UPF now polices the v2 session AMBR"
        );
        // ...and installed the newly-authorized GBR flow's per-flow QER mid-session.
        assert_eq!(
            upf_state.lock().unwrap().flow_qfis(1),
            vec![2],
            "the UPF now polices the mid-session-added GBR flow (QFI 2)"
        );
        // And it reached the RAN/UE path: the SMF notified the serving AMF
        // (Namf_Communication) — spawned off the response, so poll briefly.
        let mut notified = None;
        for _ in 0..50 {
            if let Some(b) = amf_modifies.lock().unwrap().first().cloned() {
                notified = Some(b);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let body = notified.expect("SMF notified the AMF of the QoS change");
        assert_eq!(body.get("pduSessionId").and_then(|v| v.as_u64()), Some(5));
        assert_eq!(
            body.pointer("/sessionAmbr/downlink").and_then(|v| v.as_str()),
            Some("100 Mbps")
        );
        assert_eq!(body.get("qosFlows").and_then(|v| v.as_array()).map(|a| a.len()), Some(2));
        assert_eq!(
            body.get("releasedQfis").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(0),
            "nothing released when a flow is added"
        );

        // Second mid-session change: v3 removes the GBR flow (back to non-GBR only).
        let v3 = serde_json::json!({ "default": {
            "sessionAmbr": { "uplink": "50 Mbps", "downlink": "100 Mbps" },
            "qosFlows": [ { "qfi": 1, "fiveQi": 9 } ] } });
        udr.put_sm_policy_data("imsi-999700000000001", &v3).await.unwrap();
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/refresh-policy",
                created.sm_context_ref
            ))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 200, "second refresh succeeded");
        // The UPF dropped the per-flow QER...
        assert!(
            upf_state.lock().unwrap().flow_qfis(1).is_empty(),
            "the UPF removed the GBR flow's per-flow QER"
        );
        // ...and the AMF was told to release QFI 2 toward the RAN/UE.
        let mut released = None;
        for _ in 0..50 {
            if let Some(b) = amf_modifies.lock().unwrap().get(1).cloned() {
                released = Some(b);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let body = released.expect("SMF notified the AMF of the flow removal");
        assert_eq!(
            body.get("releasedQfis").and_then(|v| v.as_array()),
            Some(&vec![serde_json::json!(2)]),
            "QFI 2 released toward the RAN/UE"
        );

        // refresh-policy on an unknown context → 404.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/nope/refresh-policy"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404, "unknown context");
    }

    /// An unsubscribed DNN is rejected with 403 *before* any N4 state is created.
    #[tokio::test]
    async fn unsubscribed_dnn_is_rejected_without_n4_state() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let smf =
            Arc::new(SmfState::connect(upf_addr, Ipv4Addr::new(127, 0, 0, 1), nrf_base).await.unwrap());
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        // POST and return (status, ProblemDetails cause).
        let post = |body: serde_json::Value| {
            let client = client.clone();
            let url = format!("{base}/nsmf-pdusession/v1/sm-contexts");
            async move {
                let resp = client.post(url).json(&body).send().await.unwrap();
                let status = resp.status().as_u16();
                let cause = resp
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|b| b.get("cause").and_then(|c| c.as_str()).map(str::to_owned));
                (status, cause)
            }
        };

        // DNN not in the subscription (no slice requested) → 403 DNN_DENIED.
        let (status, cause) = post(serde_json::json!({
            "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "corporate",
            "servingNetwork": { "mcc": "999", "mnc": "70" }
        }))
        .await;
        assert_eq!((status, cause.as_deref()), (403, Some("DNN_DENIED")));

        // Requested slice not subscribed → 403 SNSSAI_DENIED.
        let (status, cause) = post(serde_json::json!({
            "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
            "servingNetwork": { "mcc": "999", "mnc": "70" },
            "sNssai": { "sst": 2, "sd": "010203" }
        }))
        .await;
        assert_eq!((status, cause.as_deref()), (403, Some("SNSSAI_DENIED")));

        // Subscribed slice, but the DNN isn't allowed in it → 403 DNN_DENIED.
        let (status, cause) = post(serde_json::json!({
            "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "corporate",
            "servingNetwork": { "mcc": "999", "mnc": "70" },
            "sNssai": { "sst": 1, "sd": "010203" }
        }))
        .await;
        assert_eq!((status, cause.as_deref()), (403, Some("DNN_DENIED")));

        // Unknown subscriber → 403 (no smf-selection data at all).
        let (status, _) = post(serde_json::json!({
            "supi": "imsi-999700000000099", "pduSessionId": 5, "dnn": "internet",
            "servingNetwork": { "mcc": "999", "mnc": "70" }
        }))
        .await;
        assert_eq!(status, 403);

        // Missing serving network → 400.
        let (status, cause) = post(serde_json::json!({
            "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet"
        }))
        .await;
        assert_eq!((status, cause.as_deref()), (400, Some("MANDATORY_IE_MISSING")));

        assert_eq!(upf_state.lock().unwrap().session_count(), 0, "no N4 session was created");
    }

    #[tokio::test]
    async fn smf_registers_and_is_discoverable() {
        use sbi_core::nnrf::NrfClient;
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let store = sbi_core::nnrf::NrfStore::default();
        tokio::spawn(async move { sbi_core::run_on(nrf_l, sbi_core::nnrf::router(store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");

        register_with_nrf(&nrf_base, Ipv4Addr::new(127, 0, 0, 1), 8002).await.unwrap();

        let found = NrfClient::new(nrf_base).discover("SMF", "AMF").await.unwrap();
        assert_eq!(found.len(), 1, "SMF is discoverable via the NRF after registration");
    }
}
