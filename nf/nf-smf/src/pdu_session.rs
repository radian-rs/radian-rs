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
    /// UPF-allocated uplink N3 F-TEID.
    n3_teid: u32,
    /// The UE's assigned IP (this session's PDU address).
    ue_ip: Ipv4Addr,
    /// gNB downlink target, once `UpdateSMContext` installs it.
    gnb: Option<(u32, Ipv4Addr)>,
    /// Subscriber + session identity, for the UECM smf-registration teardown.
    supi: String,
    pdu_session_id: u8,
}

/// SMF runtime: a PFCP client toward one UPF plus the SM-context table.
pub struct SmfState {
    smf_ip: Ipv4Addr,
    /// NRF base URL — used to discover the UDM for Nudm_SDM subscription fetches.
    nrf_base: String,
    /// Connected N4 socket. A mutex serializes PFCP request/response transactions.
    sock: tokio::sync::Mutex<UdpSocket>,
    seq: AtomicU32,
    cp_seid: AtomicU64,
    next_ref: AtomicU64,
    /// Next UE IPv4 address to hand out (as a host-order u32), from the pool above.
    next_ue_ip: AtomicU32,
    contexts: Mutex<HashMap<String, SmContext>>,
}

impl SmfState {
    /// Bind an N4 client socket and connect it to the UPF's PFCP endpoint.
    pub async fn connect(
        upf_n4: SocketAddr,
        smf_ip: Ipv4Addr,
        nrf_base: impl Into<String>,
    ) -> std::io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(upf_n4).await?;
        Ok(Self {
            smf_ip,
            nrf_base: nrf_base.into(),
            sock: tokio::sync::Mutex::new(sock),
            seq: AtomicU32::new(1),
            cp_seid: AtomicU64::new(1),
            next_ref: AtomicU64::new(1),
            next_ue_ip: AtomicU32::new(UE_IP_POOL_START),
            contexts: Mutex::new(HashMap::new()),
        })
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate the next UE IPv4 address from the pool.
    fn alloc_ue_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.next_ue_ip.fetch_add(1, Ordering::Relaxed))
    }

    /// Send one PFCP request and await *its* response — correlated by sequence number
    /// (PFCP responses echo the request's), discarding any stale/mismatched datagram
    /// (e.g. a late response to a previously timed-out request). 2s overall.
    async fn transact(&self, req: &[u8], expect_seq: u32) -> Option<Vec<u8>> {
        let sock = self.sock.lock().await;
        sock.send(req).await.ok()?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let mut buf = vec![0u8; 2048];
                let n = sock.recv(&mut buf).await.ok()?;
                buf.truncate(n);
                if pfcp::sequence_of(&buf) == Some(expect_seq) {
                    return Some(buf);
                }
                // Sequence mismatch — not the response to this request; drop it.
            }
        })
        .await
        .ok()
        .flatten()
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionAmbrDto {
    uplink: String,
    downlink: String,
}

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
    /// The subscribed session AMBR for this DNN (TS 29.571 BitRate strings), if
    /// provisioned — likewise for the N1 accept.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_ambr: Option<SessionAmbrDto>,
}

/// What the SMF needs out of the subscriber's session-management subscription.
struct SessionSubscription {
    snssai: Snssai,
    ambr: Option<SessionAmbrDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextUpdateData {
    /// The gNB's N3 F-TEID from the N2 PDU Session Resource Setup Response (hex).
    gnb_n3_teid: String,
    gnb_n3_addr: Ipv4Addr,
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

    let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
    let seq = smf.next_seq();
    // The SMF owns UE IP allocation; the address rides into the UPF's downlink PDR so it
    // can route N6 traffic back to this session.
    let ue_ip = smf.alloc_ue_ip();
    let est_req = pfcp::session_establishment_request(cp_seid, seq, smf.smf_ip, ue_ip);
    let resp = smf.transact(&est_req, seq).await.ok_or_else(|| {
        problem(StatusCode::BAD_GATEWAY, "UPF_NOT_RESPONDING", "no PFCP response from the UPF")
    })?;
    let est = pfcp::parse_session_establishment_response(&resp).ok_or_else(|| {
        problem(StatusCode::BAD_GATEWAY, "UPF_NOT_RESPONDING", "PFCP establishment rejected")
    })?;

    let sm_ref = smf.next_ref.fetch_add(1, Ordering::Relaxed).to_string();
    smf.contexts.lock().unwrap().insert(
        sm_ref.clone(),
        SmContext {
            up_seid: est.up_seid,
            n3_teid: est.n3_teid,
            ue_ip,
            gnb: None,
            supi: req.supi.clone(),
            pdu_session_id: req.pdu_session_id,
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
            session_ambr: sub.ambr,
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
        .and_then(|v| serde_json::from_value::<SessionAmbrDto>(v.clone()).ok());
    Ok(SessionSubscription { snssai, ambr })
}

/// Discover the UDM's Nudm service endpoint via the NRF.
async fn discover_udm(nrf_base: &str) -> Result<String, String> {
    let profile = sbi_core::nnrf::NrfClient::new(nrf_base.to_string())
        .discover("UDM", "SMF")
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?
        .into_iter()
        .next()
        .ok_or("no UDM registered with the NRF")?;
    let endpoint = profile
        .nf_services
        .and_then(|s| s.into_iter().next())
        .and_then(|svc| svc.ip_end_points.into_iter().next())
        .ok_or("UDM profile has no service endpoint")?;
    let ip = endpoint.ipv4_address.ok_or("UDM endpoint missing IP")?;
    let port = endpoint.port.ok_or("UDM endpoint missing port")?;
    Ok(format!("http://{ip}:{port}"))
}

/// `Nsmf_PDUSession_UpdateSMContext`: install the downlink path with the gNB's F-TEID.
async fn update_sm_context(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
    Json(req): Json<SmContextUpdateData>,
) -> StatusCode {
    let gnb_teid = match u32::from_str_radix(req.gnb_n3_teid.trim_start_matches("0x"), 16) {
        Ok(t) => t,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    // Defense-in-depth on the downlink sink: reject an obviously bogus gNB target. The
    // real protection is SBI authorization (only the AMF may call Nsmf) — OAuth2 is
    // deferred (TS 33.501), same posture as the rest of SBI; the gNB F-TEID legitimately
    // comes from the AMF (which learned it from the N2 PDU Session Resource Setup).
    if !valid_gnb_target(gnb_teid, req.gnb_n3_addr) {
        return StatusCode::BAD_REQUEST;
    }
    let up_seid = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => c.up_seid,
            None => return StatusCode::NOT_FOUND,
        }
    };

    let seq = smf.next_seq();
    let mod_req = pfcp::session_modification_request(up_seid, seq, FAR_ID, gnb_teid, req.gnb_n3_addr);
    let resp = match smf.transact(&mod_req, seq).await {
        Some(r) => r,
        None => return StatusCode::BAD_GATEWAY,
    };
    if !pfcp::response_accepted(&resp) {
        return StatusCode::BAD_GATEWAY;
    }

    if let Some(c) = smf.contexts.lock().unwrap().get_mut(&sm_ref) {
        c.gnb = Some((gnb_teid, req.gnb_n3_addr));
        tracing::info!(
            %sm_ref,
            ue_ip = %c.ue_ip,
            uplink_teid = c.n3_teid,
            gnb_teid,
            "updated SM context; N4 downlink installed"
        );
    }
    StatusCode::OK
}

/// `Nsmf_PDUSession_ReleaseSMContext` (TS 29.502 §5.2.2.4): tear the N4 session
/// down at the UPF and drop the SM context. Driven by the AMF on deregistration.
async fn release_sm_context(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
) -> Result<StatusCode, SbiProblem> {
    let (up_seid, supi, psi) = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => (c.up_seid, c.supi.clone(), c.pdu_session_id),
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
    smf.contexts.lock().unwrap().remove(&sm_ref);
    // Purge the serving-SMF registration (Nudm_UECM). Best-effort, off the path.
    spawn_uecm_purge(smf.nrf_base.clone(), supi, psi);
    tracing::info!(%sm_ref, up_seid, "released SM context; N4 session deleted");
    Ok(StatusCode::NO_CONTENT)
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
        scheme: "http".into(),
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
                        "internet": { "sessionAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" } }
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
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s)
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
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s)
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
