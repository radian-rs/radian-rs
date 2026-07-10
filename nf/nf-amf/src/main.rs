//! AMF — Access and Mobility Management Function: **full registration slice**.
//!
//! Terminates N2 (NGAP/SCTP, TS 38.413) and drives a UE through a complete
//! registration, joining the N2 (binary) and SBI (JSON) planes:
//!
//! 1. `InitialUEMessage` → identify from the RegistrationRequest SUCI, resolve a
//!    5G-GUTI re-registration against the GUTI directory, or ask (Identity
//!    Request → Identity Response).
//! 2. Discover the AUSF via NRF, run `Nausf` 5G-AKA, send a NAS Authentication
//!    Request; on the Authentication Response, confirm RES* → K_SEAF.
//! 3. Derive K_AMF + NAS keys, send an integrity-protected **Security Mode Command**;
//!    on **Security Mode Complete**, send a protected **Registration Accept** (5G-GUTI).
//! 4. On **Registration Complete**, the UE is **REGISTERED**.
//!
//! Per-UE context (keyed by AMF-UE-NGAP-ID) holds the NAS security context once
//! established. After that, uplink NAS is verified/deciphered before dispatch.

mod auth;
mod pdu_session;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use anyhow::Context;
use nas::{Nas5gmmMessage, Nas5gmmMessageType, Nas5gsMessage};
use sbi_core::npcf_am::FieldUpdate;
use ngap::{
    InitialUEMessage, InitialUEMessageProtocolIEs_EntryValue, InitiatingMessage,
    InitiatingMessageValue, NGAP_PDU, PDUSessionResourceSetupResponseProtocolIEs_EntryValue,
    SuccessfulOutcome, SuccessfulOutcomeValue, UnsuccessfulOutcome, UnsuccessfulOutcomeValue,
    UplinkNASTransport,
    UplinkNASTransportProtocolIEs_EntryValue,
};
use sctp_rs::{
    ConnectedSocket, NotificationOrData, SendData, SendInfo, Socket, SocketToAssociation,
};
use tracing::{debug, error, info, warn};

/// SCTP Payload Protocol Identifier for NGAP (TS 38.412 §7).
const NGAP_PPID: u32 = 60;
/// Default N2 SCTP port (TS 38.412).
const N2_PORT: u16 = 38412;

const AMF_NAME: &str = "radian-amf";
const PLMN_MCC: &str = "999";
const PLMN_MNC: &str = "70";
/// DNN used when the UE's UL NAS Transport omits the requested-DNN IE (TS 23.501
/// default-DNN selection, simplified to one network-wide default).
const DEFAULT_DNN: &str = "internet";
/// T3396 back-off sent with a subscription-refused PDU session reject (cause #27):
/// retrying can't succeed until provisioning changes, so hold the UE off.
const REJECT_BACKOFF_SECS: u32 = 600;
/// T3346 back-off sent with a #62 Registration Reject: re-registering can't
/// succeed until the slice subscription changes.
const REG_REJECT_BACKOFF_SECS: u32 = 600;
/// UE-AMBR sent to the gNB when am-data carried none (fail-open) — 1 Gbps each way.
const DEFAULT_UE_AMBR_BPS: (u64, u64) = (1_000_000_000, 1_000_000_000);
/// T3512 — the UE's periodic-registration timer, sent in the Registration Accept
/// (default 54 min, TS 24.501 default). The UE re-registers when it expires.
const T3512_SECS: u32 = 54 * 60;
/// After a UE goes CM-IDLE, how long its retained context lingers before the AMF
/// **implicitly deregisters** it (mobile-reachable T3512 + implicit-dereg margin,
/// TS 24.501 §5.3.7). A UE that neither resumes nor periodically re-registers
/// within this window is evicted (PDU sessions released, UECM purged).
const IMPLICIT_DEREG_SECS: u64 = T3512_SECS as u64 + 4 * 60;
/// How often to sweep the retained store for contexts past the deadline.
const RETAINED_SWEEP_SECS: u64 = 60;
/// NRF the AMF uses to discover the AUSF/UDM. Its scheme follows the SBI transport
/// (`https` under mutual TLS) — resolved once the transport is configured in `main`.
const RAW_NRF_BASE: &str = "http://127.0.0.1:8000";
static NRF_BASE: LazyLock<String> = LazyLock::new(|| sbi_core::sbi_base(RAW_NRF_BASE));

// NAS security parameters.
const NGKSI: u8 = 0;
const ABBA: [u8; 2] = [0x00, 0x00];
/// Replayed UE security capabilities (advertises EA0-2 / IA0-2). Used as the
/// fallback when a Registration Request omitted the UE security capability IE.
const UE_SEC_CAP: [u8; 2] = [0xE0, 0xE0];

/// The AMF's NAS **ciphering** algorithms in preference order (TS 33.501 §6.7.1):
/// 128-NEA2 (AES) ≻ 128-NEA1 (SNOW 3G) ≻ 128-NEA3 (ZUC) ≻ NEA0 (null, last resort).
const NEA_PRIORITY: [u8; 4] = [2, 1, 3, 0];
/// The AMF's NAS **integrity** algorithms in preference order. NIA0 (null) is
/// never offered — integrity is mandatory outside unauthenticated emergency
/// (TS 33.501 §5.5.2), so a UE supporting no real integrity algorithm is rejected.
const NIA_PRIORITY: [u8; 3] = [2, 1, 3];

/// Whether a UE security-capability byte advertises algorithm `id` (0..7). The
/// byte is MSB-first: EA0/IA0 is bit 8 (`0x80`), EA1 bit 7, … (TS 24.501 §9.11.3.54).
fn ue_supports_algo(cap: u8, id: u8) -> bool {
    cap & (0x80u8 >> id) != 0
}

/// Select the highest-priority algorithm both the AMF (in `priority` order) and
/// the UE (`cap` byte) support — NAS algorithm negotiation. `None` if there is
/// no common algorithm.
fn select_algo(cap: u8, priority: &[u8]) -> Option<u8> {
    priority.iter().copied().find(|&id| ue_supports_algo(cap, id))
}

/// Allocator for AMF-UE-NGAP-IDs (one per UE the AMF takes context of).
static NEXT_AMF_UE_ID: AtomicU64 = AtomicU64::new(1);

/// SBI port the AMF's callback surface listens on (namf-callback).
const SBI_PORT: u16 = 8001;
/// Address other NFs use to reach this AMF's SBI surface — advertised in the NRF
/// profile and baked into the deregistration callback URI. `RADIAN_AMF_ADVERTISE_ADDR`
/// overrides the loopback default for multi-host deployments.
const ADVERTISE_ENV: &str = "RADIAN_AMF_ADVERTISE_ADDR";
const DEFAULT_ADVERTISE_ADDR: &str = "127.0.0.1";

/// The advertised SBI address (host only), from `RADIAN_AMF_ADVERTISE_ADDR`.
static ADVERTISE_ADDR: LazyLock<String> = LazyLock::new(|| {
    std::env::var(ADVERTISE_ENV).unwrap_or_else(|_| DEFAULT_ADVERTISE_ADDR.to_string())
});

/// T3522 (TS 24.501 §10.2): the Deregistration Request (UE terminated) is
/// retransmitted on each expiry, up to [`T3522_MAX_SENDS`] total transmissions,
/// then the procedure is aborted and the contexts released anyway (§5.5.2.3.4).
/// Override with `RADIAN_AMF_T3522_SECS` (the BDD suite shrinks it).
const T3522_SECS: u64 = 6;
const T3522_ENV: &str = "RADIAN_AMF_T3522_SECS";
const T3522_MAX_SENDS: u8 = 5; // initial + 4 retransmissions

/// The effective T3522 interval: the env override, else [`T3522_SECS`].
fn t3522_secs() -> u64 {
    std::env::var(T3522_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or(T3522_SECS)
}

/// A command delivered to a gNB association's per-UE control channel (from the SBI
/// callback surface into the association task that owns the NAS security context).
#[derive(Debug)]
enum UeCmd {
    /// Begin network-initiated deregistration for this UE (subscription withdrawn).
    Start(u64),
    /// T3522 fired for this UE — retransmit or abort.
    T3522Expiry(u64),
    /// T3555 fired for this UE — retransmit the Configuration Update Command (it
    /// requested acknowledgement) or give up.
    T3555Expiry(u64),
    /// Push a mid-session PDU-session QoS change to the RAN/UE (from the SMF).
    ModifyPolicy(Box<ModifyPolicy>),
    /// Network-initiated release of one or more PDU sessions for this UE (from the
    /// SMF): release each session's RAN resources (N2) and tell the UE (N1 Release
    /// Command per session).
    ReleaseSession { amf_ue_id: u64, psis: Vec<u8>, cause: u8 },
    /// The release guard timer fired: the UE never sent its PDU Session Release
    /// Complete for `psi` — finalise the release at the SMF anyway.
    ReleaseGuardExpiry { amf_ue_id: u64, psi: u8 },
    /// A Nudm_SDM data change: refresh the UE's cached subscription view (the newly
    /// fetched UE-AMBR and allowed NSSAI). `None` fields leave the current value.
    UpdateSubscribedData {
        amf_ue_id: u64,
        ue_ambr: Option<(u64, u64)>,
        allowed_nssai: Option<Vec<(u8, Option<[u8; 3]>)>>,
    },
    /// Page a CM-IDLE UE by 5G-TMSI across its registration area (downlink data or
    /// a pending AM policy change). Sent to the gNB associations serving any of the
    /// area's TAs; each sends an NGAP Paging carrying the full TAI list.
    Page { tmsi: u32, tacs: Vec<[u8; 3]> },
    /// Apply a PCF-notified AM policy change (Npcf_AMPolicyControl_UpdateNotify): a
    /// **partial** delta where each attribute is a [`FieldUpdate`] — omitted keeps the
    /// UE's current value, `Clear` removes it (UE-AMBR falls back to the subscribed
    /// value), `Set` replaces it. The AMF resolves each against the UE context.
    UpdateAmPolicy {
        amf_ue_id: u64,
        ue_ambr: FieldUpdate<(u64, u64)>,
        rfsp: FieldUpdate<u16>,
        area_restriction: FieldUpdate<(Vec<[u8; 3]>, Vec<[u8; 3]>)>,
    },
    /// Hand this association's UE context over to another association (an Xn path
    /// switch landed on the target gNB). The owner removes the context, replies on
    /// the oneshot, and releases its gNB's stale context with a
    /// `UEContextReleaseCommand` (cause *successful-handover*).
    TakeUe {
        amf_ue_id: u64,
        reply: tokio::sync::oneshot::Sender<Option<Box<UeContext>>>,
    },
    /// Send a pre-built NGAP PDU on this association — cross-association
    /// signalling for the N2 handover (the Handover Request to the target, the
    /// Handover Command back to the source).
    Forward { pdu: Box<NGAP_PDU>, label: &'static str },
}

/// A network-initiated PDU-session modification for one UE — the parsed QoS the
/// association task turns into an N1 PDU Session Modification Command + an N2 PDU
/// Session Resource Modify Request.
#[derive(Debug, Clone)]
struct ModifyPolicy {
    amf_ue_id: u64,
    psi: u8,
    /// Session AMBR in NAS wire form (the N1 command) and bits/sec (the N2 transfer).
    ambr_nas: nas::SessionAmbr,
    session_ambr_dl_bps: u64,
    session_ambr_ul_bps: u64,
    ngap_flows: Vec<ngap::QosFlow>,
    nas_flows: Vec<nas::QosFlowDesc>,
    /// QFIs the SMF released — torn down toward the gNB (N2) and UE (N1).
    released_qfis: Vec<u8>,
}

/// This AMF's stable NF instance id — used for the NRF profile and every UECM
/// serving-AMF registration.
static AMF_INSTANCE_ID: LazyLock<String> = LazyLock::new(sbi_core::new_nf_instance_id);

/// Record this AMF as the SUPI's serving AMF at the UDM (Nudm_UECM), carrying
/// the deregistration callback the UDR will use on subscription withdrawal.
/// Best-effort, off the signaling path.
fn spawn_uecm_register(supi: String) {
    tokio::spawn(async move {
        let reg = sbi_core::nudm::Amf3GppAccessRegistration {
            amf_instance_id: AMF_INSTANCE_ID.clone(),
            dereg_callback_uri: format!(
                "{}://{}:{SBI_PORT}/namf-callback/v1/{supi}/dereg-notify",
                sbi_core::sbi_scheme(),
                &*ADVERTISE_ADDR
            ),
        };
        match discover_nf(&NRF_BASE, "UDM").await {
            Ok(udm) => {
                if let Err(e) =
                    sbi_core::nudm::NudmClient::new(udm).uecm_register_amf(&supi, &reg).await
                {
                    warn!(%supi, "UECM serving-AMF registration failed: {e}");
                } else {
                    info!(%supi, "UECM: registered as the serving AMF");
                }
            }
            Err(e) => warn!(%supi, "UECM registration skipped (no UDM): {e}"),
        }
    });
}

/// Purge the SUPI's serving-AMF registration (deregistration of any flavour).
/// Best-effort, off the signaling path.
fn spawn_uecm_purge(supi: String) {
    tokio::spawn(async move {
        match discover_nf(&NRF_BASE, "UDM").await {
            Ok(udm) => match sbi_core::nudm::NudmClient::new(udm).uecm_deregister_amf(&supi).await
            {
                Ok(true) => info!(%supi, "UECM: serving-AMF registration purged"),
                Ok(false) => {} // already gone (e.g. the withdrawal wiped the subscriber)
                Err(e) => warn!(%supi, "UECM purge failed: {e}"),
            },
            Err(e) => warn!(%supi, "UECM purge skipped (no UDM): {e}"),
        }
    });
}

/// Nudm_SDM change subscriptions this AMF holds: SUPI → subscription id — kept so a
/// deregistration can unsubscribe at the UDM.
static SDM_SUBS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Default::default);

/// Subscribe to the SUPI's `Nudm_SDM` subscriber-data changes (TS 29.503 §5.3.2):
/// the UDM will POST our `sdm-notify` callback when the subscriber's provisioned
/// data changes, so we can refresh the cached subscription view. The subscription
/// id is kept for a later unsubscribe. Best-effort, off the signaling path.
fn spawn_sdm_subscribe(supi: String) {
    tokio::spawn(async move {
        let callback = format!(
            "{}://{}:{SBI_PORT}/namf-callback/v1/{supi}/sdm-notify",
            sbi_core::sbi_scheme(),
            &*ADVERTISE_ADDR
        );
        match discover_nf(&NRF_BASE, "UDM").await {
            Ok(udm) => match sbi_core::nudm::NudmClient::new(udm).sdm_subscribe(&supi, &callback).await {
                Ok(sub_id) => {
                    info!(%supi, %sub_id, "Nudm_SDM: subscribed to subscriber-data changes");
                    SDM_SUBS.lock().unwrap().insert(supi, sub_id);
                }
                Err(e) => warn!(%supi, "Nudm_SDM subscribe failed: {e}"),
            },
            Err(e) => warn!(%supi, "Nudm_SDM subscribe skipped (no UDM): {e}"),
        }
    });
}

/// Drop the SUPI's `Nudm_SDM` change subscription (deregistration of any flavour).
/// Best-effort, off the signaling path; a no-op if we held no subscription.
fn spawn_sdm_unsubscribe(supi: String) {
    let Some(sub_id) = SDM_SUBS.lock().unwrap().remove(&supi) else {
        return;
    };
    tokio::spawn(async move {
        match discover_nf(&NRF_BASE, "UDM").await {
            Ok(udm) => {
                if let Err(e) =
                    sbi_core::nudm::NudmClient::new(udm).sdm_unsubscribe(&supi, &sub_id).await
                {
                    warn!(%supi, "Nudm_SDM unsubscribe failed: {e}");
                } else {
                    info!(%supi, %sub_id, "Nudm_SDM: unsubscribed");
                }
            }
            Err(e) => warn!(%supi, "Nudm_SDM unsubscribe skipped (no UDM): {e}"),
        }
    });
}

/// Directory of served UEs: SUPI → (AMF-UE-NGAP-ID, the owning association's
/// deregistration channel). Lets the SBI callback surface (subscription
/// withdrawal) reach a UE that lives inside an SCTP association task.
static UE_DIRECTORY: LazyLock<Mutex<HashMap<String, (u64, UnboundedSender<UeCmd>)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Assigned 5G-GUTIs: 5G-TMSI → SUPI. A returning UE registers with the GUTI its
/// last Registration Accept assigned (TS 24.501 §5.5.1.2 — the SUCI is only for
/// first contact); the AMF resolves it here and **re-authenticates**. Entries
/// survive UE-initiated deregistration (the UE keeps its GUTI in the USIM) and
/// are dropped when a fresh GUTI supersedes them or the subscription is
/// withdrawn.
static GUTI_DIRECTORY: LazyLock<Mutex<HashMap<u32, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// CM-IDLE UE contexts retained across the N2 release, keyed by 5G-TMSI. On AN
/// release the context (registration + NAS security + PDU sessions) is moved here;
/// a Service Request carrying that 5G-S-TMSI restores it into the serving
/// association and re-activates the user plane. AMF-wide (survives the owning SCTP
/// association ending), so a UE can resume on any gNB.
static RETAINED: LazyLock<Mutex<HashMap<u32, UeContext>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A live gNB association's command channel + the tracking areas it serves (from
/// its NG Setup Supported TA List; empty until NG Setup completes).
struct GnbLink {
    tacs: Vec<[u8; 3]>,
    /// The gNB id from the NG Setup's Global RAN Node ID — N2-handover target
    /// resolution is keyed on it. `None` until NG Setup completes.
    gnb_id: Option<u32>,
    tx: UnboundedSender<UeCmd>,
}

/// Command channels into every live gNB association — how the SBI paging surface
/// reaches the N2 tasks. Each `serve_gnb` registers its link; closed ones are
/// swept when paging. Paging is **registration-area-scoped**: only the gNBs whose
/// Supported TA List covers the UE's TAI are paged (see [`page_gnbs`]).
static GNB_LINKS: LazyLock<Mutex<Vec<GnbLink>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// The tracking-area code the AMF pages within when the UE's TAI is unknown
/// (single-TA demo core default).
const AMF_TAC: [u8; 3] = [0x00, 0x00, 0x01];

/// T3513 (TS 24.501 §10.2) — the network-side paging timer: started when a Paging
/// is sent, stopped by the paging response (the Service Request consuming the
/// retained context). On expiry the page is retransmitted, up to
/// [`T3513_MAX_SENDS`] attempts. Override with `RADIAN_AMF_T3513_SECS`.
const T3513_SECS: u64 = 6;
const T3513_ENV: &str = "RADIAN_AMF_T3513_SECS";
const T3513_MAX_SENDS: u32 = 3;

/// The registration area assigned at registration: the serving gNB's Supported TA
/// List (its association found by channel identity) ∪ the UE's own TAI, capped at
/// 16 (one 5GS TAI list partial list).
fn registration_area_for(ue_tac: Option<[u8; 3]>, dereg_tx: &UnboundedSender<UeCmd>) -> Vec<[u8; 3]> {
    let mut area: Vec<[u8; 3]> = GNB_LINKS
        .lock()
        .unwrap()
        .iter()
        .find(|l| l.tx.same_channel(dereg_tx))
        .map(|l| l.tacs.clone())
        .unwrap_or_default();
    if let Some(tac) = ue_tac {
        if !area.contains(&tac) {
            area.push(tac);
        }
    }
    area.truncate(16);
    area
}

/// Page `tmsi` across registration area `area`: the gNB associations serving any
/// of its tracking areas are paged, each with the full area in its TAI List for
/// Paging. A gNB that hasn't completed NG Setup (no TA list yet) is included; an
/// empty area pages every gNB in the default TAC (fail-open). Closed links are
/// swept. Returns how many associations were paged.
fn page_gnbs(tmsi: u32, area: &[[u8; 3]]) -> usize {
    let page_tacs: Vec<[u8; 3]> = if area.is_empty() { vec![AMF_TAC] } else { area.to_vec() };
    let mut paged = 0;
    let mut links = GNB_LINKS.lock().unwrap();
    links.retain(|l| {
        let serving =
            area.is_empty() || l.tacs.is_empty() || l.tacs.iter().any(|t| area.contains(t));
        if !serving {
            return !l.tx.is_closed();
        }
        match l.tx.send(UeCmd::Page { tmsi, tacs: page_tacs.clone() }) {
            Ok(()) => {
                paged += 1;
                true
            }
            Err(_) => false,
        }
    });
    paged
}

/// Page a CM-IDLE UE under **T3513**: page its registration area, wait, and
/// retransmit until the UE resumes (its retained context is consumed by the
/// Service Request) or `max_sends` attempts exhaust.
async fn page_with_retx(supi: String, tmsi: u32, t3513: std::time::Duration, max_sends: u32) {
    for attempt in 1..=max_sends {
        // Resumed (or evicted) — the retained context is gone: stop paging.
        let Some(area) = RETAINED.lock().unwrap().get(&tmsi).map(|c| {
            if c.registration_area.is_empty() {
                c.tac.map(|t| vec![t]).unwrap_or_default()
            } else {
                c.registration_area.clone()
            }
        }) else {
            return;
        };
        let paged = page_gnbs(tmsi, &area);
        info!(%supi, attempt, of = max_sends, gnbs = paged, "paging CM-IDLE UE (T3513 armed)");
        tokio::time::sleep(t3513).await;
        if !RETAINED.lock().unwrap().contains_key(&tmsi) {
            info!(%supi, attempt, "UE answered the page (resumed)");
            return;
        }
    }
    warn!(%supi, "T3513 exhausted after {max_sends} attempts — UE unreachable; context stays retained");
}

/// Spawn the T3513 paging loop for a retained UE (config-driven timer).
fn spawn_paging(supi: &str, tmsi: u32) {
    let t3513 = std::env::var(T3513_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(T3513_SECS);
    tokio::spawn(page_with_retx(
        supi.to_string(),
        tmsi,
        std::time::Duration::from_secs(t3513),
        T3513_MAX_SENDS,
    ));
}

/// Arm T3522: after `secs`, post an expiry for this UE onto its association.
fn arm_t3522(tx: &UnboundedSender<UeCmd>, amf_ue_id: u64, secs: u64) {
    let tx = tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        let _ = tx.send(UeCmd::T3522Expiry(amf_ue_id));
    });
}

/// T3555 (TS 24.501 §10.2) — the Configuration Update Command retransmission timer:
/// started when the AMF sends a command that **requested acknowledgement**, and
/// retransmitted on each expiry up to [`T3555_MAX_SENDS`] total transmissions before
/// the network abandons the procedure (§5.4.4.3). Override with `RADIAN_AMF_T3555_SECS`.
const T3555_SECS: u64 = 6;
const T3555_ENV: &str = "RADIAN_AMF_T3555_SECS";
const T3555_MAX_SENDS: u8 = 5; // initial + 4 retransmissions

/// Arm T3555: after the configured interval, post an expiry for this UE onto its
/// association (the retransmission is driven from the association task).
fn arm_t3555(tx: &UnboundedSender<UeCmd>, amf_ue_id: u64) {
    let secs = std::env::var(T3555_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or(T3555_SECS);
    let tx = tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        let _ = tx.send(UeCmd::T3555Expiry(amf_ue_id));
    });
}

/// The release guard: how long the AMF waits for the UE's PDU Session Release
/// Complete before finalising the release itself. Override with
/// `RADIAN_AMF_RELEASE_GUARD_SECS`.
const RELEASE_GUARD_SECS: u64 = 6;
const RELEASE_GUARD_ENV: &str = "RADIAN_AMF_RELEASE_GUARD_SECS";

/// Arm the release guard: after `secs`, post a guard expiry for `(UE, psi)` onto
/// its association — finalises the release if the UE never answered.
fn arm_release_guard(tx: &UnboundedSender<UeCmd>, amf_ue_id: u64, psi: u8, secs: u64) {
    let tx = tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        let _ = tx.send(UeCmd::ReleaseGuardExpiry { amf_ue_id, psi });
    });
}

/// Where a UE is in the registration flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegState {
    IdentityRequested,
    Identified,
    Authenticating,
    SecurityMode,
    Registered,
}

/// Connection-management state (TS 23.501 §5.3.3): whether the UE has an N2
/// signalling connection. A registered UE goes **CM-IDLE** on AN release (its
/// RAN context is gone, the user plane deactivated) and back to **CM-CONNECTED**
/// on a Service Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmState {
    Connected,
    Idle,
}

/// Per-UE context held by the AMF, keyed by AMF-UE-NGAP-ID.
#[derive(Debug)]
struct UeContext {
    ran_ue_id: u32,
    state: RegState,
    suci: Option<String>,
    auth: Option<auth::PendingAuth>,
    /// NAS security context, present once the Security Mode Command is sent.
    sec: Option<nas::NasSecurityContext>,
    /// K_AMF, retained alongside `sec` to derive **K_gNB** (TS 33.501 Annex A.9)
    /// for the Initial Context Setup's Security Key IE.
    kamf: Option<[u8; 32]>,
    /// The **NH chain** state (TS 33.501 §6.9.2.3.3): `(sync_input, NCC)` — the
    /// sync input is the initial K_gNB before the first hop and the latest NH
    /// after. Each Xn path switch derives a fresh NH from it, increments the NCC
    /// (mod 8), and hands the pair to the target gNB. Seeded whenever an Initial
    /// Context Setup delivers a K_gNB.
    nh_chain: Option<([u8; 32], u8)>,
    /// The UE's advertised 5GS security capabilities `[EA, IA]`, replayed verbatim in the
    /// Security Mode Command (TS 24.501 §8.2.25) so the UE can detect a bidding-down attack.
    replayed_ue_sec_cap: Option<[u8; 2]>,
    /// The UE's PDU sessions keyed by PDU session id: `(SM context ref, serving
    /// SMF base URL)`. The stored base ensures UpdateSMContext / ReleaseSMContext
    /// reach the *same* SMF that created the session (SMF selection, design/44).
    sm_refs: HashMap<u8, (String, String)>,
    /// The serving S-NSSAI `(SST, optional SD)` each PDU session runs on, from the
    /// SMF at establishment — so a subscribed-NSSAI change that removes a slice can
    /// release the sessions on it (design/102 narrowing). A `psi` absent here (a
    /// pre-feature session) is left alone rather than wrongly released.
    session_snssai: HashMap<u8, (u8, Option<[u8; 3]>)>,
    /// The **effective** UE-AMBR `(downlink, uplink)` bits/sec sent to the gNB (N2
    /// setup / UE Context Modification) — a PCF AM-policy value when one is in effect,
    /// otherwise the subscribed value. Derived by [`UeContext::recompute_ue_ambr`]
    /// from the two sources below. `None` → a default is used.
    ue_ambr: Option<(u64, u64)>,
    /// The subscribed UE-AMBR from am-data (Nudm_SDM) — the default, used when no PCF
    /// AM policy overrides it. Refreshed on a subscribed-data change (design/99).
    subscribed_ue_ambr: Option<(u64, u64)>,
    /// The PCF AM-policy UE-AMBR override (TS 23.503) — takes precedence over the
    /// subscribed value while an AM policy association is in effect.
    pcf_ue_ambr: Option<(u64, u64)>,
    /// The AM policy RFSP index (RAT/Frequency Selection Priority, TS 23.501
    /// §5.3.4.3) from the PCF — signalled to the RAN in a UE Context Modification.
    /// `None` when the PCF provided no RFSP.
    rfsp: Option<u16>,
    /// The AM policy service area restriction from the PCF as
    /// `(allowed_tacs, non_allowed_tacs)` (3-octet TACs) — signalled to the RAN as a
    /// Mobility Restriction List on the Registration Accept. `None` = unrestricted.
    area_restriction: Option<(Vec<[u8; 3]>, Vec<[u8; 3]>)>,
    /// The allowed NSSAI granted at registration (from am-data). `None` = the fetch
    /// failed or hasn't happened — slice admission then falls back to the SMF's check.
    allowed_nssai: Option<Vec<(u8, Option<[u8; 3]>)>>,
    /// The NSSAI the UE requested in its Registration Request (empty = IE omitted).
    requested_nssai: Vec<(u8, Option<[u8; 3]>)>,
    /// Network-initiated deregistration in progress: how many Deregistration
    /// Requests have been sent (T3522 governs retransmission). `None` = idle.
    dereg_attempts: Option<u8>,
    /// Whether an SQN resynchronisation was already attempted for this UE — a
    /// second synch failure aborts (TS 33.501: at most one resync per procedure,
    /// so a persistent mismatch can't loop).
    resync_attempted: bool,
    /// CM state — `Connected` while an N2 connection exists, `Idle` after AN
    /// release. A CM-IDLE context is retained (registration + PDU sessions live)
    /// for a Service Request to resume.
    cm_state: CmState,
    /// The 5G-TMSI (from the assigned 5G-GUTI) — the persistent identity a Service
    /// Request presents. Set when the Registration Accept assigns the GUTI; the
    /// retained-context store is keyed by it (stable across CM-IDLE / resume,
    /// unlike the per-N2-connection AMF-UE-NGAP-ID).
    guti_tmsi: Option<u32>,
    /// The UE's current tracking area (from the InitialUEMessage's User Location
    /// Information TAI, refreshed on resume). `None` when the gNB sent no ULI.
    tac: Option<[u8; 3]>,
    /// The UE's assigned **registration area** (TS 23.501 §5.3.2.3): the serving
    /// gNB's Supported TA List ∪ the UE's TAI, capped at 16. Sent to the UE in the
    /// Registration Accept's 5GS TAI list (TS 24.501 §9.11.3.9); paging is scoped
    /// to it. Empty = none assigned (paging falls back to the current TAC).
    registration_area: Vec<[u8; 3]>,
    /// When this context entered CM-IDLE (moved to `RETAINED`). The eviction sweep
    /// implicitly deregisters a UE that lingers past the mobile-reachable /
    /// implicit-deregistration deadline. `None` while CM-CONNECTED.
    retained_at: Option<std::time::Instant>,
    /// The PCF AM policy association `(pcf_base, assoc_id)` created at registration
    /// (Npcf_AMPolicyControl) — deleted at deregistration. `None` when no PCF was
    /// reachable (the registration proceeds with subscribed policy).
    am_policy: Option<(String, String)>,
    /// An AM policy change (UpdateNotify) that arrived while the UE was CM-IDLE —
    /// held in the retained context (latest wins) and applied when the UE resumes
    /// with a Service Request; the UE is paged so it comes back promptly.
    pending_am_policy: Option<PendingAmPolicy>,
    /// PDU sessions with a **network-initiated release** in progress: a Release
    /// Command was sent and the AMF is awaiting the UE's N1 PDU Session Release
    /// Complete before finalising at the SMF (TS 23.502 §4.3.4). A guard timer
    /// finalises anyway if the complete never arrives. Empty = none releasing.
    releasing: std::collections::HashSet<u8>,
    /// An outstanding **Configuration Update Command** that requested acknowledgement:
    /// the plaintext command (re-protected on each retransmit) + how many times it has
    /// been sent. Set when the command goes out, cleared by the UE's Configuration
    /// Update Complete; T3555 retransmits while it's `Some`. `None` = none awaiting ack.
    pending_config_update: Option<PendingConfigUpdate>,
}

/// A service area restriction as `(allowed_tacs, non_allowed_tacs)` — the AMF signals
/// it to the RAN as a Mobility Restriction List.
type AreaRestriction = (Vec<[u8; 3]>, Vec<[u8; 3]>);

/// A Configuration Update Command awaiting the UE's acknowledgement (see
/// `UeContext::pending_config_update`).
#[derive(Debug, Clone)]
struct PendingConfigUpdate {
    /// The plaintext command, re-protected (fresh NAS COUNT) on each retransmission.
    cuc: Nas5gsMessage,
    /// The service area restriction that rides the command's DownlinkNASTransport as a
    /// Mobility Restriction List — re-sent on each retransmission so the RAN keeps
    /// enforcing it. `None` = no MRL (e.g. an NSSAI command, whose payload is in the
    /// NAS itself).
    area_restriction: Option<AreaRestriction>,
    /// Transmissions so far (1 = the initial send); capped at [`T3555_MAX_SENDS`].
    attempts: u8,
}

/// Build the DownlinkNASTransport carrying a (protected) Configuration Update Command,
/// attaching the service area as a Mobility Restriction List when the command has one.
fn config_update_downlink(
    amf_ue_id: u64,
    ran_ue_id: u32,
    cuc_bytes: Vec<u8>,
    area_restriction: &Option<AreaRestriction>,
) -> NGAP_PDU {
    match area_restriction {
        Some((allowed, not_allowed)) => ngap::downlink_nas_transport_with_area_restriction(
            amf_ue_id, ran_ue_id, cuc_bytes, PLMN_MCC, PLMN_MNC, allowed, not_allowed,
        ),
        None => ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, cuc_bytes),
    }
}

/// Protect and send a Configuration Update Command that **requests acknowledgement**,
/// tracking it for T3555 retransmission (store the plaintext + service area, arm the
/// timer). Returns the DownlinkNASTransport to send, or `None` if the UE has no NAS
/// security context.
fn push_tracked_config_update(
    ctx: &mut UeContext,
    amf_ue_id: u64,
    cuc: Nas5gsMessage,
    area_restriction: Option<AreaRestriction>,
    tx: &UnboundedSender<UeCmd>,
) -> Option<(NGAP_PDU, &'static str)> {
    let ran_ue_id = ctx.ran_ue_id;
    let bytes = ctx.sec.as_mut()?.protect(&cuc, nas::sht::INTEGRITY_CIPHERED, 1);
    let dl = config_update_downlink(amf_ue_id, ran_ue_id, bytes, &area_restriction);
    ctx.pending_config_update = Some(PendingConfigUpdate { cuc, area_restriction, attempts: 1 });
    arm_t3555(tx, amf_ue_id);
    Some((dl, "DownlinkNASTransport (ConfigurationUpdateCommand)"))
}

/// An AM policy change awaiting a CM-IDLE UE's return (see
/// `UeContext::pending_am_policy`) — the partial delta held until resume.
#[derive(Debug, Clone, PartialEq)]
struct PendingAmPolicy {
    ue_ambr: FieldUpdate<(u64, u64)>,
    rfsp: FieldUpdate<u16>,
    area_restriction: FieldUpdate<(Vec<[u8; 3]>, Vec<[u8; 3]>)>,
}

/// What an `InitialUEMessage` asks the AMF to do next.
#[derive(Debug)]
enum InitialUeOutcome {
    NeedIdentity(NGAP_PDU),
    Identified { ran_ue_id: u32, supi: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("amf");

    // Mutual TLS (design/57): with RADIAN_SBI_TLS_DIR set, dial every NF over mTLS
    // and serve the callback surface over mTLS; `sbi_scheme()` then yields `https`.
    let tls = sbi_core::tls::TlsIdentity::from_env("amf")?;
    sbi_core::configure_transport(tls.as_ref());

    let amf_auth = Arc::new(auth::AmfAuth::new(NRF_BASE.as_str(), PLMN_MCC, PLMN_MNC));
    let amf_smf = Arc::new(pdu_session::AmfSmf::new(NRF_BASE.as_str(), PLMN_MCC, PLMN_MNC));

    // SBI callback surface (namf-callback): the UDR notifies subscription
    // withdrawals here (design/38). Registered with the NRF so it can be found.
    let sbi_addr: SocketAddr = format!("0.0.0.0:{SBI_PORT}").parse()?;
    tokio::spawn(async move {
        let serve = match tls {
            Some(id) => sbi_core::tls::serve(sbi_addr, namf_callback_router(), id).await,
            None => sbi_core::run(sbi_addr, namf_callback_router()).await,
        };
        if let Err(e) = serve {
            error!("AMF SBI server failed: {e}");
        }
    });
    match register_with_nrf(&NRF_BASE, &ADVERTISE_ADDR, SBI_PORT).await {
        Ok(()) => info!(nrf = %*NRF_BASE, "registered AMF with NRF"),
        Err(e) => warn!("NRF registration failed (continuing without callbacks): {e}"),
    }

    // Implicitly deregister retained CM-IDLE UEs that stay silent past the
    // mobile-reachable / implicit-dereg deadline (TS 24.501 §5.3.7). The deadline
    // is `RADIAN_AMF_IMPLICIT_DEREG_SECS` (default T3512 + 4 min).
    {
        let amf_smf = amf_smf.clone();
        let secs = std::env::var("RADIAN_AMF_IMPLICIT_DEREG_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(IMPLICIT_DEREG_SECS);
        let max_idle = std::time::Duration::from_secs(secs);
        info!(implicit_dereg_secs = secs, "CM-IDLE implicit-deregistration sweep armed");
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(RETAINED_SWEEP_SECS));
            loop {
                tick.tick().await;
                evict_stale_retained(&amf_smf, max_idle).await;
            }
        });
    }

    let addr: SocketAddr = format!("0.0.0.0:{N2_PORT}").parse()?;
    let socket = Socket::new_v4(SocketToAssociation::OneToOne).context("create SCTP socket")?;
    socket.bind(addr).context("bind N2 SCTP")?;
    let listener = socket.listen(64).context("listen N2 SCTP")?;
    info!(%addr, ppid = NGAP_PPID, nrf = %*NRF_BASE, "N2 (NGAP/SCTP) listener up");

    loop {
        let (conn, peer) = listener.accept().await.context("accept SCTP association")?;
        info!(%peer, "gNB associated");
        let amf_auth = amf_auth.clone();
        let amf_smf = amf_smf.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_gnb(conn, amf_auth, amf_smf).await {
                warn!("gNB session ended: {e:#}");
            }
        });
    }
}

/// Receive loop for one gNB SCTP association, owning that association's UE contexts.
async fn serve_gnb(
    conn: ConnectedSocket,
    amf_auth: Arc<auth::AmfAuth>,
    amf_smf: Arc<pdu_session::AmfSmf>,
) -> anyhow::Result<()> {
    let mut ues: HashMap<u64, UeContext> = HashMap::new();
    // The SBI callback surface reaches this association's UEs through this channel.
    let (dereg_tx, mut dereg_rx) = unbounded_channel::<UeCmd>();
    // Register this association so the paging surface can reach its gNB; the
    // served TA list is filled in when the gNB's NG Setup arrives.
    GNB_LINKS.lock().unwrap().push(GnbLink { tacs: Vec::new(), gnb_id: None, tx: dereg_tx.clone() });
    let result = loop {
        tokio::select! {
            received = conn.sctp_recv() => match received {
                Err(e) => break Err(e.into()),
                Ok(NotificationOrData::Notification(n)) => info!("SCTP notification: {n:?}"),
                Ok(NotificationOrData::Data(data)) => {
                    if data.payload.is_empty() {
                        info!("gNB association closed");
                        break Ok(());
                    }
                    handle_ngap(&conn, &mut ues, &amf_auth, &amf_smf, &dereg_tx, &data.payload).await;
                }
            },
            Some(cmd) = dereg_rx.recv() => {
                let downlinks = match cmd {
                    UeCmd::Start(id) => {
                        on_network_deregistration(&mut ues, &amf_smf, id, &dereg_tx, t3522_secs()).await
                    }
                    UeCmd::T3522Expiry(id) => on_t3522_expiry(&mut ues, id, &dereg_tx, t3522_secs()),
                    UeCmd::T3555Expiry(id) => on_t3555_expiry(&mut ues, id, &dereg_tx),
                    UeCmd::ModifyPolicy(m) => on_network_modification(&mut ues, &m),
                    UeCmd::ReleaseSession { amf_ue_id, psis, cause } => {
                        on_network_release(&mut ues, amf_ue_id, &psis, cause, &dereg_tx)
                    }
                    UeCmd::ReleaseGuardExpiry { amf_ue_id, psi } => {
                        if ues.get(&amf_ue_id).map(|c| c.releasing.contains(&psi)) == Some(true) {
                            warn!(
                                "UE {amf_ue_id}: no PDU Session Release Complete for psi {psi} — \
                                 finalising the release on the guard timer"
                            );
                            finalize_release(&mut ues, &amf_smf, amf_ue_id, psi).await;
                        }
                        Vec::new()
                    }
                    UeCmd::UpdateAmPolicy { amf_ue_id, ue_ambr, rfsp, area_restriction } => {
                        on_am_policy_update(&mut ues, amf_ue_id, ue_ambr, rfsp, area_restriction, &dereg_tx)
                    }
                    UeCmd::UpdateSubscribedData { amf_ue_id, ue_ambr, allowed_nssai } => {
                        on_sdm_data_change(&mut ues, amf_ue_id, ue_ambr, allowed_nssai, &dereg_tx)
                    }
                    // Page a CM-IDLE UE on this gNB (non-UE-associated NGAP Paging)
                    // across its registration area.
                    UeCmd::Page { tmsi, tacs } => {
                        info!("paging CM-IDLE UE (5G-TMSI {tmsi:#010x}, area {tacs:02x?}) on this gNB");
                        vec![(ngap::paging(tmsi, PLMN_MCC, PLMN_MNC, &tacs), "Paging")]
                    }
                    // An Xn path switch landed on another association — hand the
                    // context over and release this gNB's stale side.
                    UeCmd::TakeUe { amf_ue_id, reply } => on_take_ue(&mut ues, amf_ue_id, reply),
                    // Cross-association N2-handover signalling for this gNB.
                    UeCmd::Forward { pdu, label } => vec![(*pdu, label)],
                };
                for (dl, label) in downlinks {
                    send_or_log(&conn, &dl, label).await;
                }
            }
        }
    };
    // This association is gone — drop its UEs from the directory (their senders
    // are now closed) so withdrawals for them answer 404 instead of queueing.
    drop(dereg_rx);
    UE_DIRECTORY.lock().unwrap().retain(|_, (_, tx)| !tx.is_closed());
    result
}

/// The AMF's SBI callback router: the UDR posts subscription withdrawals here
/// (`DeregistrationData`), which we turn into a network-initiated deregistration
/// on the UE's owning association.
fn namf_callback_router() -> axum::Router {
    async fn dereg_notify(
        axum::extract::Path(supi): axum::extract::Path<String>,
    ) -> axum::http::StatusCode {
        let entry = UE_DIRECTORY.lock().unwrap().get(&supi).cloned();
        match entry {
            Some((amf_ue_id, tx)) if tx.send(UeCmd::Start(amf_ue_id)).is_ok() => {
                info!(%supi, "subscription withdrawn — deregistering UE {amf_ue_id}");
                axum::http::StatusCode::NO_CONTENT
            }
            _ => axum::http::StatusCode::NOT_FOUND,
        }
    }
    /// `Nudm_SDM_Notification` (TS 29.503 §5.3.2.3): the UDM reports that the
    /// subscriber's provisioned data changed. Re-fetch am-data and refresh the cached
    /// subscription view (UE-AMBR / allowed NSSAI) on the owning association. `204` —
    /// the notification is accepted whether or not the UE is currently connected (a
    /// CM-IDLE UE re-fetches at its next registration).
    async fn sdm_notify(
        axum::extract::Path(supi): axum::extract::Path<String>,
        axum::Json(_note): axum::Json<sbi_core::nudm::ModificationNotification>,
    ) -> axum::http::StatusCode {
        let entry = UE_DIRECTORY.lock().unwrap().get(&supi).cloned();
        let Some((amf_ue_id, tx)) = entry else {
            info!(%supi, "Nudm_SDM data-change for a UE not connected — re-fetched at next registration");
            return axum::http::StatusCode::NO_CONTENT;
        };
        // The notification lists changed resources; we re-read the authoritative data.
        let (allowed_nssai, ue_ambr) = fetch_am_data(&NRF_BASE, &supi).await;
        info!(%supi, ?ue_ambr, "Nudm_SDM data-change — refreshing the cached subscription view");
        let _ = tx.send(UeCmd::UpdateSubscribedData { amf_ue_id, ue_ambr, allowed_nssai });
        axum::http::StatusCode::NO_CONTENT
    }
    /// `Namf_Communication`-style N1N2 message transfer for a network-initiated PDU
    /// session modification: the SMF posts the re-authorized QoS (session AMBR + QoS
    /// flows) for a UE's session; the AMF hands it to the owning association task,
    /// which signals the RAN/UE. `202` if the UE is reachable, `404` otherwise.
    async fn modify_policy(
        axum::extract::Path(supi): axum::extract::Path<String>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::http::StatusCode {
        let Some(psi) =
            body.get("pduSessionId").and_then(|v| v.as_u64()).and_then(|v| u8::try_from(v).ok())
        else {
            return axum::http::StatusCode::BAD_REQUEST;
        };
        // Session AMBR: NAS wire form (for the N1 command) + bits/sec (for the N2 transfer).
        let (ambr_nas, dl_bps, ul_bps) = match body.get("sessionAmbr") {
            Some(a) => {
                let ul = a.get("uplink").and_then(|v| v.as_str());
                let dl = a.get("downlink").and_then(|v| v.as_str());
                match (ul, dl) {
                    (Some(ul), Some(dl)) => (
                        nas::session_ambr_from_bitrates(ul, dl),
                        pdu_session::bitrate_to_bps(dl),
                        pdu_session::bitrate_to_bps(ul),
                    ),
                    _ => (None, None, None),
                }
            }
            None => (None, None, None),
        };
        let (Some(ambr_nas), Some(dl_bps), Some(ul_bps)) = (ambr_nas, dl_bps, ul_bps) else {
            return axum::http::StatusCode::BAD_REQUEST;
        };
        let (ngap_flows, nas_flows) = pdu_session::parse_qos_flows(&body);
        let released_qfis: Vec<u8> = body
            .get("releasedQfis")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_u64()?.try_into().ok()).collect())
            .unwrap_or_default();

        let entry = UE_DIRECTORY.lock().unwrap().get(&supi).cloned();
        match entry {
            Some((amf_ue_id, tx)) => {
                let cmd = UeCmd::ModifyPolicy(Box::new(ModifyPolicy {
                    amf_ue_id,
                    psi,
                    ambr_nas,
                    session_ambr_dl_bps: dl_bps,
                    session_ambr_ul_bps: ul_bps,
                    ngap_flows,
                    nas_flows,
                    released_qfis,
                }));
                if tx.send(cmd).is_ok() {
                    info!(%supi, psi, "PDU session modification requested by the SMF");
                    axum::http::StatusCode::ACCEPTED
                } else {
                    axum::http::StatusCode::NOT_FOUND
                }
            }
            None => axum::http::StatusCode::NOT_FOUND,
        }
    }

    /// `Namf_Communication`-style transfer for a **network-initiated PDU session
    /// release** (TS 23.502 §4.3.4): the SMF asks the AMF to release a UE's session.
    /// A **CM-CONNECTED** UE's owning association sends the N2 Release Command (+ N1);
    /// a **CM-IDLE** UE (no N2 to signal) has the session released at the SMF now and
    /// dropped from its retained context — the UE is told it is gone by the PDU
    /// Session Status reconciliation on its next return (design/90). `202` if
    /// actioned, `404` if the UE holds no such session.
    async fn release_session(
        axum::extract::Path(supi): axum::extract::Path<String>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::http::StatusCode {
        // One or more sessions: `pduSessionIds` (array) or the single `pduSessionId`.
        let psis: Vec<u8> = match body.get("pduSessionIds").and_then(|v| v.as_array()) {
            Some(arr) => {
                arr.iter().filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok())).collect()
            }
            None => body
                .get("pduSessionId")
                .and_then(|v| v.as_u64())
                .and_then(|n| u8::try_from(n).ok())
                .into_iter()
                .collect(),
        };
        if psis.is_empty() {
            return axum::http::StatusCode::BAD_REQUEST;
        }
        // Optional 5GSM release cause; default regular deactivation (#36).
        let cause = body
            .get("cause")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(nas::sm_cause::REGULAR_DEACTIVATION);
        let entry = UE_DIRECTORY.lock().unwrap().get(&supi).cloned();
        if let Some((amf_ue_id, tx)) = entry {
            // CM-CONNECTED: the owning association runs a release procedure per session.
            let cmd = UeCmd::ReleaseSession { amf_ue_id, psis: psis.clone(), cause };
            if tx.send(cmd).is_ok() {
                info!(%supi, ?psis, "PDU session release requested by the SMF");
                return axum::http::StatusCode::ACCEPTED;
            }
            // The association closed between the directory lookup and the send —
            // fall through to the retained-context path (the UE just went idle).
        }
        // CM-IDLE: find each requested session in the retained context and release it
        // at the SMF now. Gather under the lock, release off-lock, then drop the PSIs.
        let (tmsi, targets) = {
            let retained = RETAINED.lock().unwrap();
            match retained.iter().find(|(_, c)| c.suci.as_deref() == Some(supi.as_str())) {
                Some((tmsi, c)) => {
                    let targets: Vec<(u8, (String, String))> = psis
                        .iter()
                        .filter_map(|psi| c.sm_refs.get(psi).map(|r| (*psi, r.clone())))
                        .collect();
                    (*tmsi, targets)
                }
                None => (0, Vec::new()),
            }
        };
        if targets.is_empty() {
            warn!(%supi, ?psis, "release requested but the UE holds none of these sessions");
            return axum::http::StatusCode::NOT_FOUND;
        }
        let amf_smf = pdu_session::AmfSmf::new(NRF_BASE.as_str(), PLMN_MCC, PLMN_MNC);
        for (psi, (sm_ref, smf_base)) in &targets {
            match amf_smf.release_sm_context(smf_base, sm_ref).await {
                Ok(()) => info!(%supi, psi, "released a CM-IDLE UE's PDU session at the SMF"),
                Err(e) => warn!(%supi, psi, "CM-IDLE release at the SMF failed: {e}"),
            }
        }
        // Drop them from the retained context so the PDU Session Status the AMF sends
        // on the UE's next return omits them (design/90 reconciliation informs the UE).
        if let Some(c) = RETAINED.lock().unwrap().get_mut(&tmsi) {
            for (psi, _) in &targets {
                c.sm_refs.remove(psi);
            }
        }
        axum::http::StatusCode::ACCEPTED
    }

    /// `Namf_Communication_N1N2MessageTransfer` (TS 29.518, simplified) — the SMF
    /// asks the AMF to page a UE for which downlink data arrived at the UPF. The AMF
    /// resolves the SUPI to its retained CM-IDLE 5G-TMSI and pages its registration
    /// area under T3513. `202` if paging started; `404` if the UE isn't CM-IDLE /
    /// unknown.
    async fn page_ue(
        axum::extract::Path(supi): axum::extract::Path<String>,
    ) -> axum::http::StatusCode {
        let tmsi = RETAINED
            .lock()
            .unwrap()
            .iter()
            .find(|(_, c)| c.suci.as_deref() == Some(supi.as_str()))
            .map(|(tmsi, _)| *tmsi);
        let Some(tmsi) = tmsi else {
            warn!(%supi, "paging requested but the UE is not CM-IDLE / unknown");
            return axum::http::StatusCode::NOT_FOUND;
        };
        info!(%supi, "downlink data for a CM-IDLE UE — paging under T3513");
        spawn_paging(&supi, tmsi);
        axum::http::StatusCode::ACCEPTED
    }

    /// `Npcf_AMPolicyControl_UpdateNotify` (TS 29.507) — the PCF pushes a changed
    /// AM policy for a UE. The AMF applies the new UE-AMBR and runs the UE
    /// Configuration Update procedure. `204` if delivered over N2; `202` if the UE
    /// is CM-IDLE (the change is held in the retained context and the UE paged —
    /// applied when it resumes); `404` if the UE is unknown.
    async fn am_policy_notify(
        axum::extract::Path(supi): axum::extract::Path<String>,
        axum::Json(policy): axum::Json<sbi_core::npcf_am::PolicyUpdate>,
    ) -> axum::http::StatusCode {
        // A **partial** delta (TS 29.507): each attribute is omitted (keep), cleared,
        // or set. Translate the wire types into the AMF's internal ones, preserving
        // the three-way distinction — an omitted UE-AMBR leaves the override intact,
        // a cleared one removes it (effective falls back to the subscribed value).
        let ue_ambr = match policy.ue_ambr {
            FieldUpdate::Keep => FieldUpdate::Keep,
            FieldUpdate::Clear => FieldUpdate::Clear,
            FieldUpdate::Set(ambr) => match (
                pdu_session::bitrate_to_bps(&ambr.downlink),
                pdu_session::bitrate_to_bps(&ambr.uplink),
            ) {
                (Some(dl), Some(ul)) => FieldUpdate::Set((dl, ul)),
                _ => return axum::http::StatusCode::BAD_REQUEST,
            },
        };
        let rfsp = policy.rfsp;
        // A set service area with no usable TAC (all malformed) resolves to a clear,
        // matching the pre-partial behaviour; omitted stays omitted.
        let area_restriction = match policy.serv_area_res {
            FieldUpdate::Keep => FieldUpdate::Keep,
            FieldUpdate::Clear => FieldUpdate::Clear,
            FieldUpdate::Set(sar) => match area_restriction_tacs(&sar) {
                Some(tacs) => FieldUpdate::Set(tacs),
                None => FieldUpdate::Clear,
            },
        };
        match UE_DIRECTORY.lock().unwrap().get(&supi).cloned() {
            Some((amf_ue_id, tx))
                if tx
                    .send(UeCmd::UpdateAmPolicy {
                        amf_ue_id,
                        ue_ambr: ue_ambr.clone(),
                        rfsp: rfsp.clone(),
                        area_restriction: area_restriction.clone(),
                    })
                    .is_ok() =>
            {
                info!(%supi, "AM policy update (UpdateNotify) delivered to the association");
                return axum::http::StatusCode::NO_CONTENT;
            }
            _ => {}
        }
        // Not CM-CONNECTED — a retained CM-IDLE context instead? Hold the change
        // there (latest wins) and page the UE under T3513 (network-triggered
        // Service Request, TS 23.502 §4.2.3.3); the resume path applies it.
        let tmsi = {
            let mut retained = RETAINED.lock().unwrap();
            let entry =
                retained.iter_mut().find(|(_, c)| c.suci.as_deref() == Some(supi.as_str()));
            entry.map(|(tmsi, ctx)| {
                ctx.pending_am_policy =
                    Some(PendingAmPolicy { ue_ambr, rfsp, area_restriction });
                *tmsi
            })
        };
        match tmsi {
            Some(tmsi) => {
                info!(%supi, "AM policy update held for CM-IDLE UE — paging under T3513 (applied on resume)");
                spawn_paging(&supi, tmsi);
                axum::http::StatusCode::ACCEPTED
            }
            None => axum::http::StatusCode::NOT_FOUND,
        }
    }

    axum::Router::new()
        .route("/namf-callback/v1/{supi}/dereg-notify", axum::routing::post(dereg_notify))
        .route("/namf-callback/v1/{supi}/sdm-notify", axum::routing::post(sdm_notify))
        .route(
            "/namf-comm/v1/ue-contexts/{supi}/modify",
            axum::routing::post(modify_policy),
        )
        .route(
            "/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages",
            axum::routing::post(page_ue),
        )
        .route(
            "/namf-comm/v1/ue-contexts/{supi}/release",
            axum::routing::post(release_session),
        )
        .route(
            "/npcf-callback/v1/am-policy-notify/{supi}",
            axum::routing::post(am_policy_notify),
        )
}

/// Register the AMF's callback surface with the NRF and keep it alive.
async fn register_with_nrf(nrf_base: &str, host: &str, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService};
    let mut profile = NfProfile::new(AMF_INSTANCE_ID.clone(), "AMF", host.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "namf-callback-1".into(),
        service_name: "namf-callback".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(host.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}

/// Network-initiated deregistration (TS 24.501 §5.5.2.3), triggered by a
/// subscription withdrawal: release the PDU session, send the UE a
/// Deregistration Request (UE terminated, re-registration not required), and
/// start **T3522** — the contexts stay until the UE's Deregistration Accept
/// arrives ([`dispatch_uplink_nas`]) or the retransmissions are exhausted
/// ([`on_t3522_expiry`]).
async fn on_network_deregistration(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    amf_ue_id: u64,
    dereg_tx: &UnboundedSender<UeCmd>,
    t3522_secs: u64,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        warn!("network deregistration for unknown UE {amf_ue_id}");
        return Vec::new();
    };
    if ctx.dereg_attempts.is_some() {
        info!("UE {amf_ue_id}: deregistration already in progress");
        return Vec::new();
    }
    let ran_ue_id = ctx.ran_ue_id;

    for (psi, (sm_ref, smf_base)) in std::mem::take(&mut ctx.sm_refs) {
        match amf_smf.release_sm_context(&smf_base, &sm_ref).await {
            Ok(()) => info!("UE {amf_ue_id}: released SM context {sm_ref} (psi {psi}, network dereg)"),
            Err(e) => warn!("UE {amf_ue_id}: SM context {sm_ref} (psi {psi}) release failed: {e}"),
        }
    }
    // The UE stops being addressable for further withdrawals immediately.
    if let Some(supi) = ctx.suci.clone() {
        UE_DIRECTORY.lock().unwrap().remove(&supi);
    }

    let Some(sec) = ctx.sec.as_mut() else {
        // Can't NAS-signal an unsecured UE — release the RAN side and be done.
        warn!("UE {amf_ue_id}: network dereg before NAS security; releasing without a NAS request");
        ues.remove(&amf_ue_id);
        return vec![(
            ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::DEREGISTER),
            "UEContextReleaseCommand",
        )];
    };
    // Re-registration not required (subscription withdrawn), 3GPP access.
    let req = nas::deregistration_request_to_ue(0x01);
    let bytes = sec.protect(&req, nas::sht::INTEGRITY_CIPHERED, 1);
    ctx.dereg_attempts = Some(1);
    arm_t3522(dereg_tx, amf_ue_id, t3522_secs);
    info!("UE {amf_ue_id}: Deregistration Request sent (attempt 1/{T3522_MAX_SENDS}); T3522 armed");
    vec![(
        ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, bytes),
        "DownlinkNASTransport (DeregistrationRequest)",
    )]
}

/// Apply a PCF-notified AM policy change (Npcf_AMPolicyControl_UpdateNotify): store
/// the new RFSP + UE-AMBR + service area restriction, signal RFSP + UE-AMBR to the
/// **RAN** in a UE Context Modification Request (TS 38.413 §9.2.2.7), and run the
/// Generic UE Configuration Update procedure toward the **UE** (TS 24.501 §5.4.4) —
/// a protected Configuration Update Command that also carries the updated service
/// area restriction to the RAN as a Mobility Restriction List (TS 38.413 §9.2.5.3).
fn on_am_policy_update(
    ues: &mut HashMap<u64, UeContext>,
    amf_ue_id: u64,
    ue_ambr: FieldUpdate<(u64, u64)>,
    rfsp: FieldUpdate<u16>,
    area_restriction: FieldUpdate<(Vec<[u8; 3]>, Vec<[u8; 3]>)>,
    tx: &UnboundedSender<UeCmd>,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        warn!("AM policy update for unknown UE {amf_ue_id}");
        return Vec::new();
    };
    // Resolve each partial delta against the current context: an omitted attribute
    // keeps its value, a cleared one removes it, a set one replaces it. The PCF
    // override takes precedence over the subscribed UE-AMBR; clearing it falls the
    // effective UE-AMBR back to the subscribed value.
    ctx.pcf_ue_ambr = ue_ambr.apply(ctx.pcf_ue_ambr);
    ctx.recompute_ue_ambr();
    ctx.rfsp = rfsp.apply(ctx.rfsp);
    ctx.area_restriction = area_restriction.apply(ctx.area_restriction.take());
    let ran_ue_id = ctx.ran_ue_id;
    let effective_ambr = ctx.ue_ambr;
    let rfsp = ctx.rfsp;
    let area_restriction = ctx.area_restriction.clone();
    info!(
        "UE {amf_ue_id}: AM policy updated — signalling RFSP {rfsp:?}, effective UE-AMBR \
         {effective_ambr:?} (dl/ul) bps, service area {area_restriction:?} to the RAN"
    );
    // Tell the RAN the new UE-context policy (RFSP + UE-AMBR).
    let mut dl = vec![(
        ngap::ue_context_modification_request(amf_ue_id, ran_ue_id, rfsp, effective_ambr),
        "UEContextModificationRequest (RFSP)",
    )];
    // Tell the UE its configuration changed (Generic UE Configuration Update). The
    // command **requests acknowledgement** (a bare indication IE, no NSSAI) and is
    // retransmitted under T3555 until the UE's Configuration Update Complete; the
    // updated service area restriction rides the same DownlinkNASTransport as a
    // Mobility Restriction List (re-sent on each retransmission).
    let cuc = nas::configuration_update_command_with_nssai(&[], false, true);
    if let Some(entry) = push_tracked_config_update(ctx, amf_ue_id, cuc, area_restriction, tx) {
        dl.push(entry);
    }
    dl
}

/// Apply a Nudm_SDM data change: refresh the cached subscription view (subscribed
/// UE-AMBR / allowed NSSAI) and, when a value actually changed, **push it**: a new
/// UE-AMBR updates the RAN's enforcement (UE Context Modification), and any change
/// nudges the UE with a Generic UE Configuration Update (TS 24.501 §5.4.4). A no-op
/// change (or an unknown UE) signals nothing.
fn on_sdm_data_change(
    ues: &mut HashMap<u64, UeContext>,
    amf_ue_id: u64,
    ue_ambr: Option<(u64, u64)>,
    allowed_nssai: Option<Vec<(u8, Option<[u8; 3]>)>>,
    tx: &UnboundedSender<UeCmd>,
) -> Vec<(NGAP_PDU, &'static str)> {
    // The RAN/UE signalling + which sessions the narrowing releases — computed while
    // the context is borrowed, before the network-initiated release runs on `ues`.
    let (mut dl, to_release) = {
        let Some(ctx) = ues.get_mut(&amf_ue_id) else {
            warn!("Nudm_SDM data change for unknown UE {amf_ue_id}");
            return Vec::new();
        };
        let mut ambr_changed = false;
        let mut nssai_changed = false;
        if let Some(ambr) = ue_ambr {
            if ctx.subscribed_ue_ambr != Some(ambr) {
                ctx.subscribed_ue_ambr = Some(ambr);
                let old_effective = ctx.ue_ambr;
                ctx.recompute_ue_ambr();
                // Re-signal only if the *effective* UE-AMBR changed — a PCF override
                // takes precedence, so a subscribed change under it is stored (for when
                // the PCF policy is removed) but not signalled.
                if ctx.ue_ambr != old_effective {
                    info!("UE {amf_ue_id}: effective UE-AMBR updated to {:?} bps (Nudm_SDM)", ctx.ue_ambr);
                    ambr_changed = true;
                } else {
                    info!("UE {amf_ue_id}: subscribed UE-AMBR changed but a PCF override is in effect — not signalled");
                }
            }
        }
        let mut narrowed = false;
        if let Some(nssai) = allowed_nssai {
            if ctx.allowed_nssai.as_ref() != Some(&nssai) {
                info!("UE {amf_ue_id}: subscribed NSSAI updated to {nssai:?} (Nudm_SDM)");
                // A narrowing = a previously-allowed slice is no longer allowed → tell
                // the UE to re-register (its allowed slice set changed).
                narrowed = ctx
                    .allowed_nssai
                    .as_ref()
                    .is_some_and(|old| old.iter().any(|s| !nssai.contains(s)));
                ctx.allowed_nssai = Some(nssai);
                nssai_changed = true;
            }
        }
        if !ambr_changed && !nssai_changed {
            return Vec::new();
        }
        let ran_ue_id = ctx.ran_ue_id;
        let rfsp = ctx.rfsp;
        let effective_ambr = ctx.ue_ambr;
        // Snapshot before the `ctx.sec` mutable borrow below.
        let allowed = ctx.allowed_nssai.clone().unwrap_or_default();
        // A narrowed allowed NSSAI: any PDU session whose serving slice is no longer
        // allowed must be released (TS 23.501 §5.15 — a slice the UE may no longer
        // use). A session with no recorded slice (pre-feature) is left alone.
        let to_release: Vec<u8> = if nssai_changed && !allowed.is_empty() {
            ctx.sm_refs
                .keys()
                .filter(|psi| {
                    ctx.session_snssai.get(psi).is_some_and(|s| !allowed.contains(s))
                })
                .copied()
                .collect()
        } else {
            Vec::new()
        };

        let mut dl = Vec::new();
        // A new UE-AMBR → update the RAN's enforcement (RFSP re-sent unchanged).
        if ambr_changed {
            dl.push((
                ngap::ue_context_modification_request(amf_ue_id, ran_ue_id, rfsp, effective_ambr),
                "UEContextModificationRequest (subscribed UE-AMBR)",
            ));
        }
        // Any subscription change → tell the UE its configuration changed (Generic UE
        // Configuration Update). When the allowed NSSAI changed the command **carries**
        // the new set (TS 24.501 §9.11.3.37) and **requests acknowledgement** — the UE
        // must reply with a Configuration Update Complete, and T3555 retransmits until
        // it does. A plain AMBR nudge needs no ack. A UE with no security context can't
        // be NAS-signalled — skip it (the RAN update still lands).
        if nssai_changed {
            // The NSSAI-carrying command requests acknowledgement (the new slice set is
            // in the NAS itself, so no Mobility Restriction List) → tracked for T3555
            // retransmission.
            let cuc = nas::configuration_update_command_with_nssai(&allowed, narrowed, true);
            if let Some(entry) = push_tracked_config_update(ctx, amf_ue_id, cuc, None, tx) {
                dl.push(entry);
            }
        } else if let Some(sec) = ctx.sec.as_mut() {
            // A plain AMBR nudge — the UE just consumes it, no acknowledgement, not tracked.
            let cuc = sec.protect(&nas::configuration_update_command(), nas::sht::INTEGRITY_CIPHERED, 1);
            dl.push((
                ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, cuc),
                "DownlinkNASTransport (ConfigurationUpdateCommand)",
            ));
        }
        (dl, to_release)
    };
    // Release the sessions on now-disallowed slices (network-initiated release).
    if !to_release.is_empty() {
        info!("UE {amf_ue_id}: releasing PDU session(s) {to_release:?} — their slice is no longer allowed");
        dl.extend(on_network_release(
            ues,
            amf_ue_id,
            &to_release,
            nas::sm_cause::REGULAR_DEACTIVATION,
            tx,
        ));
    }
    dl
}

fn on_network_modification(
    ues: &mut HashMap<u64, UeContext>,
    m: &ModifyPolicy,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(ctx) = ues.get_mut(&m.amf_ue_id) else {
        warn!("PDU session modification for unknown UE {}", m.amf_ue_id);
        return Vec::new();
    };
    if !ctx.sm_refs.contains_key(&m.psi) {
        warn!("UE {}: modification for psi {} with no active session", m.amf_ue_id, m.psi);
        return Vec::new();
    }
    let ran_ue_id = ctx.ran_ue_id;
    let Some(sec) = ctx.sec.as_mut() else {
        warn!("UE {}: PDU session modification before NAS security — skipped", m.amf_ue_id);
        return Vec::new();
    };
    // N1: the PDU Session Modification Command (network-initiated ⇒ PTI 0) — the
    // current flows plus a delete for each released QFI — protected in a DL NAS Transport.
    let cmd =
        nas::pdu_session_modification_command(m.psi, 0, m.ambr_nas, &m.nas_flows, &m.released_qfis);
    let dl = nas::dl_nas_transport_sm(m.psi, cmd);
    let nas_bytes = sec.protect(&dl, nas::sht::INTEGRITY_CIPHERED, 1);
    // N2: the PDU Session Resource Modify Request (new session AMBR + the add-or-modify
    // flows + the released flows + the N1). Pass the flows through as-is (may be empty
    // when the change is only a release or a session-AMBR re-rate).
    let modify = ngap::pdu_session_resource_modify_request(
        m.amf_ue_id,
        ran_ue_id,
        m.psi,
        &m.ngap_flows,
        m.session_ambr_dl_bps,
        m.session_ambr_ul_bps,
        &m.released_qfis,
        nas_bytes,
    );
    info!(
        "UE {}: PDU Session Resource Modify sent (psi {}, released {:?})",
        m.amf_ue_id, m.psi, m.released_qfis
    );
    vec![(modify, "PDUSessionResourceModifyRequest")]
}

/// Network-initiated PDU session release (TS 23.502 §4.3.4): the SMF asked to
/// release `psi`. Build the N1 **PDU Session Release Command** (network-initiated ⇒
/// PTI 0, protected in a DL NAS Transport) and the N2 **PDU Session Resource
/// Release Command** carrying it — the gNB tears down the DRBs, relays the N1 to
/// the UE, and answers a Release Response (finalised in [`on_release_response`]).
fn on_network_release(
    ues: &mut HashMap<u64, UeContext>,
    amf_ue_id: u64,
    psis: &[u8],
    cause: u8,
    tx: &UnboundedSender<UeCmd>,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        warn!("PDU session release for unknown UE {amf_ue_id}");
        return Vec::new();
    };
    let ran_ue_id = ctx.ran_ue_id;
    if ctx.sec.is_none() {
        warn!("UE {amf_ue_id}: PDU session release before NAS security — skipped");
        return Vec::new();
    }
    let secs = std::env::var(RELEASE_GUARD_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(RELEASE_GUARD_SECS);
    // One release procedure per requested session (the N2 command carries a single
    // N1); unknown sessions are skipped. Each finalises independently on its own N1
    // complete or guard expiry (design/92).
    let mut downlinks = Vec::new();
    for &psi in psis {
        if !ctx.sm_refs.contains_key(&psi) {
            warn!("UE {amf_ue_id}: release for psi {psi} with no active session");
            continue;
        }
        // N1 PDU Session Release Command, protected in a DL NAS Transport.
        let cmd = nas::pdu_session_release_command(psi, 0, cause);
        let dl = nas::dl_nas_transport_sm(psi, cmd);
        let nas_bytes = ctx.sec.as_mut().unwrap().protect(&dl, nas::sht::INTEGRITY_CIPHERED, 1);
        let release =
            ngap::pdu_session_resource_release_command(amf_ue_id, ran_ue_id, psi, nas_bytes);
        // Finalised at the SMF only on the UE's N1 complete (§4.3.4); mark releasing
        // and arm a per-session guard so a silent UE doesn't strand the session.
        ctx.releasing.insert(psi);
        arm_release_guard(tx, amf_ue_id, psi, secs);
        info!("UE {amf_ue_id}: PDU Session Resource Release sent (psi {psi}, 5GSM cause {cause})");
        downlinks.push((release, "PDUSessionResourceReleaseCommand"));
    }
    downlinks
}

/// Implicitly deregister a UE the network can no longer reach — the escalation shared
/// by the retransmission procedures that exhaust without a UE response (T3522
/// deregistration, T3555 configuration update). Purge the UE's GUTI, its Nudm state
/// (SDM change subscription + UECM registration), and its PCF AM-policy association;
/// drop the local context; and release the RAN-side context with a
/// UEContextReleaseCommand (cause deregister). A no-op for an unknown UE.
fn implicit_deregister(
    ues: &mut HashMap<u64, UeContext>,
    amf_ue_id: u64,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return Vec::new();
    };
    let ran_ue_id = ctx.ran_ue_id;
    if let Some(supi) = ctx.suci.clone() {
        // The subscription context is gone — its GUTI must not resolve again.
        GUTI_DIRECTORY.lock().unwrap().retain(|_, s| s != &supi);
        spawn_sdm_unsubscribe(supi.clone());
        spawn_uecm_purge(supi);
    }
    spawn_am_policy_delete(ctx.am_policy.take());
    ues.remove(&amf_ue_id);
    vec![(
        ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::DEREGISTER),
        "UEContextReleaseCommand",
    )]
}

/// T3522 fired: retransmit the Deregistration Request while attempts remain;
/// after [`T3522_MAX_SENDS`] transmissions, abort the procedure (§5.5.2.3.4) —
/// release the RAN-side context and drop ours anyway.
fn on_t3522_expiry(
    ues: &mut HashMap<u64, UeContext>,
    amf_ue_id: u64,
    dereg_tx: &UnboundedSender<UeCmd>,
    t3522_secs: u64,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return Vec::new(); // accept already completed the procedure
    };
    let Some(attempts) = ctx.dereg_attempts else {
        return Vec::new(); // stale expiry (procedure not running)
    };
    let ran_ue_id = ctx.ran_ue_id;

    if attempts < T3522_MAX_SENDS {
        let Some(sec) = ctx.sec.as_mut() else {
            return Vec::new();
        };
        let req = nas::deregistration_request_to_ue(0x01);
        let bytes = sec.protect(&req, nas::sht::INTEGRITY_CIPHERED, 1);
        ctx.dereg_attempts = Some(attempts + 1);
        arm_t3522(dereg_tx, amf_ue_id, t3522_secs);
        warn!(
            "UE {amf_ue_id}: T3522 expired — retransmitting Deregistration Request \
             (attempt {}/{T3522_MAX_SENDS})",
            attempts + 1
        );
        return vec![(
            ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, bytes),
            "DownlinkNASTransport (DeregistrationRequest)",
        )];
    }

    warn!(
        "UE {amf_ue_id}: T3522 exhausted after {T3522_MAX_SENDS} transmissions — \
         aborting deregistration and releasing the contexts"
    );
    implicit_deregister(ues, amf_ue_id)
}

/// T3555 fired: retransmit the outstanding Configuration Update Command (re-protected
/// with a fresh NAS COUNT) while transmissions remain; after [`T3555_MAX_SENDS`] the
/// network abandons the procedure (§5.4.4.3). A UE that never acknowledges over the
/// full retransmission run is treated as unreachable and **implicitly deregistered**
/// (the codebase's escalation, mirroring T3522 exhaustion) rather than left in a
/// half-updated state. A stale expiry (the UE already acknowledged, so
/// `pending_config_update` is cleared) is a no-op.
fn on_t3555_expiry(
    ues: &mut HashMap<u64, UeContext>,
    amf_ue_id: u64,
    tx: &UnboundedSender<UeCmd>,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return Vec::new(); // context gone
    };
    let Some(attempts) = ctx.pending_config_update.as_ref().map(|p| p.attempts) else {
        return Vec::new(); // acknowledged already, or none outstanding
    };
    let ran_ue_id = ctx.ran_ue_id;

    if attempts < T3555_MAX_SENDS {
        let (cuc_msg, area_restriction) = {
            let p = ctx.pending_config_update.as_ref().unwrap();
            (p.cuc.clone(), p.area_restriction.clone())
        };
        let Some(sec) = ctx.sec.as_mut() else {
            return Vec::new();
        };
        let bytes = sec.protect(&cuc_msg, nas::sht::INTEGRITY_CIPHERED, 1);
        // Rebuild the DL faithfully — re-attaching the service area (Mobility
        // Restriction List) so the RAN keeps enforcing it across the retransmission.
        let dl = config_update_downlink(amf_ue_id, ran_ue_id, bytes, &area_restriction);
        ctx.pending_config_update =
            Some(PendingConfigUpdate { cuc: cuc_msg, area_restriction, attempts: attempts + 1 });
        arm_t3555(tx, amf_ue_id);
        warn!(
            "UE {amf_ue_id}: T3555 expired — retransmitting Configuration Update Command \
             (attempt {}/{T3555_MAX_SENDS})",
            attempts + 1
        );
        return vec![(dl, "DownlinkNASTransport (ConfigurationUpdateCommand)")];
    }

    warn!(
        "UE {amf_ue_id}: T3555 exhausted after {T3555_MAX_SENDS} transmissions — no \
         acknowledgement from the UE; implicitly deregistering it (unreachable)"
    );
    implicit_deregister(ues, amf_ue_id)
}

/// Decode one NGAP PDU and dispatch it.
async fn handle_ngap(
    conn: &ConnectedSocket,
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_smf: &pdu_session::AmfSmf,
    dereg_tx: &UnboundedSender<UeCmd>,
    bytes: &[u8],
) {
    let pdu = match NGAP_PDU::decode(bytes) {
        Ok(p) => p,
        Err(e) => {
            error!("NGAP decode failed: {e:?}");
            return;
        }
    };
    info!("recv {pdu}");

    match &pdu {
        NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) => match value {
            InitiatingMessageValue::Id_NGSetup(_req) => {
                // Record the tracking areas this gNB serves (Supported TA List) —
                // paging is then scoped to the gNBs covering the UE's registration
                // area — and its gNB id (Global RAN Node ID), which N2-handover
                // target resolution is keyed on.
                let tacs = ngap::supported_tacs_from_ng_setup(&pdu);
                let gnb_id = ngap::gnb_id_from_ng_setup(&pdu);
                if tacs.is_some() || gnb_id.is_some() {
                    info!("gNB {gnb_id:?} serves TACs {tacs:02x?} (paging / handover scope)");
                    if let Some(link) = GNB_LINKS
                        .lock()
                        .unwrap()
                        .iter_mut()
                        .find(|l| l.tx.same_channel(dereg_tx))
                    {
                        if let Some(tacs) = tacs {
                            link.tacs = tacs;
                        }
                        link.gnb_id = gnb_id;
                    }
                }
                let resp = ngap::ng_setup_response(AMF_NAME, PLMN_MCC, PLMN_MNC);
                send_or_log(conn, &resp, "NGSetupResponse").await;
            }
            InitiatingMessageValue::Id_InitialUEMessage(msg) => {
                // A 5G-S-TMSI naming a retained CM-IDLE context → a Service Request
                // resume or a mobility registration update, not a fresh registration.
                let resume = ngap::fiveg_s_tmsi_from_initial_ue(msg)
                    .filter(|tmsi| RETAINED.lock().unwrap().contains_key(tmsi));
                if let Some(tmsi) = resume {
                    for (dl, label) in on_service_request(ues, amf_smf, msg, tmsi, dereg_tx).await {
                        send_or_log(conn, &dl, label).await;
                    }
                    return;
                }
                let amf_ue_id = NEXT_AMF_UE_ID.fetch_add(1, Ordering::Relaxed);
                match on_initial_ue(ues, msg, amf_ue_id, dereg_tx) {
                    Some(InitialUeOutcome::NeedIdentity(dl)) => {
                        send_or_log(conn, &dl, "DownlinkNASTransport (IdentityRequest)").await;
                    }
                    Some(InitialUeOutcome::Identified { ran_ue_id, supi }) => {
                        start_authentication(conn, ues, amf_auth, amf_ue_id, ran_ue_id, &supi).await;
                    }
                    None => warn!("InitialUEMessage missing RAN-UE-NGAP-ID; cannot respond"),
                }
            }
            InitiatingMessageValue::Id_UplinkNASTransport(msg) => {
                for (dl, label) in on_uplink_nas(ues, amf_auth, amf_smf, msg, dereg_tx).await {
                    send_or_log(conn, &dl, label).await;
                }
            }
            InitiatingMessageValue::Id_UEContextReleaseRequest(_) => {
                if let Some(dl) = on_ue_context_release_request(ues, amf_smf, &pdu).await {
                    send_or_log(conn, &dl, "UEContextReleaseCommand").await;
                }
            }
            InitiatingMessageValue::Id_PathSwitchRequest(_) => {
                if let Some((ack, label)) = on_path_switch(ues, amf_smf, &pdu, dereg_tx).await {
                    send_or_log(conn, &ack, label).await;
                }
            }
            InitiatingMessageValue::Id_HandoverPreparation(_) => {
                if let Some((failure, label)) = on_handover_required(ues, amf_smf, &pdu, dereg_tx).await
                {
                    send_or_log(conn, &failure, label).await;
                }
            }
            InitiatingMessageValue::Id_HandoverNotification(_) => {
                on_handover_notify(ues, amf_smf, &pdu, dereg_tx).await;
            }
            InitiatingMessageValue::Id_HandoverCancel(_) => {
                if let Some((ack, label)) = on_handover_cancel(amf_smf, &pdu).await {
                    send_or_log(conn, &ack, label).await;
                }
            }
            _ => info!("unhandled initiating message: {}", pdu.procedure_name()),
        },
        NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
            value: SuccessfulOutcomeValue::Id_PDUSessionResourceSetup(_),
            ..
        }) => {
            on_pdu_session_setup_response(ues, amf_smf, &pdu).await;
        }
        NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
            value: SuccessfulOutcomeValue::Id_UEContextRelease(_),
            ..
        }) => {
            info!("gNB confirmed UE context release (UEContextReleaseComplete)");
        }
        NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
            value: SuccessfulOutcomeValue::Id_PDUSessionResourceModify(_),
            ..
        }) => match ngap::modify_response_result(&pdu) {
            Some((amf_ue_id, _ran, modified)) => {
                info!("gNB applied PDU session modification for UE {amf_ue_id} (psi {modified:?})")
            }
            None => info!("gNB PDUSessionResourceModifyResponse (unparseable)"),
        },
        NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
            value: SuccessfulOutcomeValue::Id_UEContextModification(_),
            ..
        }) => match ngap::ue_context_modification_response_ids(&pdu) {
            Some((amf_ue_id, _ran)) => {
                info!("gNB applied the UE context modification (RFSP / UE-AMBR) for UE {amf_ue_id}")
            }
            None => info!("gNB UEContextModificationResponse (unparseable)"),
        },
        NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
            value: SuccessfulOutcomeValue::Id_HandoverResourceAllocation(_),
            ..
        }) => on_handover_request_ack(amf_smf, &pdu).await,
        NGAP_PDU::UnsuccessfulOutcome(UnsuccessfulOutcome {
            value: UnsuccessfulOutcomeValue::Id_HandoverResourceAllocation(_),
            ..
        }) => on_handover_failure(&pdu),
        NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
            value: SuccessfulOutcomeValue::Id_InitialContextSetup(_),
            ..
        }) => on_initial_context_setup_response(ues, amf_smf, &pdu).await,
        NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
            value: SuccessfulOutcomeValue::Id_PDUSessionResourceRelease(_),
            ..
        }) => on_release_response(ues, &pdu),
        _ => info!("unhandled PDU: {}", pdu.procedure_name()),
    }
}

/// Handle a gNB-initiated `UEContextReleaseRequest` (TS 23.502 §4.2.6 AN release,
/// e.g. RAN user inactivity): deactivate every PDU session's user plane at its SMF
/// (the UPF drops downlink toward the released gNB tunnel), transition the UE to
/// **CM-IDLE** — keeping its 5GMM registration + PDU sessions for a later Service
/// Request — and answer with a `UEContextReleaseCommand`. Returns the command, or
/// `None` if the UE is unknown.
async fn on_ue_context_release_request(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    pdu: &NGAP_PDU,
) -> Option<NGAP_PDU> {
    let (amf_ue_id, ran_ue_id) = ngap::parse_ue_context_release_request(pdu)?;
    let sessions: Vec<(u8, (String, String))> = ues
        .get(&amf_ue_id)
        .map(|c| c.sm_refs.iter().map(|(psi, v)| (*psi, v.clone())).collect())?;

    // Deactivate the user plane for each session (best-effort — the RAN context is
    // released regardless; a failed SMF call just leaves that session's UPF route
    // stale until the next activation).
    for (psi, (sm_ref, smf_base)) in &sessions {
        match amf_smf.deactivate_up(smf_base, sm_ref).await {
            Ok(()) => info!("UE {amf_ue_id}: PDU session {psi} user plane deactivated (AN release)"),
            Err(e) => warn!("UE {amf_ue_id}: PDU session {psi} deactivation failed: {e}"),
        }
    }
    // Move the context to the AMF-wide retained store (keyed by its 5G-TMSI) so a
    // Service Request can resume it; the N2-connection ids and reachability channel
    // are dropped (the UE is unreachable over N2 until it comes back).
    if let Some(mut ctx) = ues.remove(&amf_ue_id) {
        ctx.cm_state = CmState::Idle;
        ctx.retained_at = Some(std::time::Instant::now()); // start the mobile-reachable timer
        if let Some(supi) = &ctx.suci {
            UE_DIRECTORY.lock().unwrap().remove(supi);
        }
        match ctx.guti_tmsi {
            Some(tmsi) => {
                RETAINED.lock().unwrap().insert(tmsi, ctx);
                info!("UE {amf_ue_id}: released RAN context — CM-IDLE, retained by 5G-TMSI {tmsi:#010x} ({} PDU session(s))", sessions.len());
            }
            // No GUTI assigned (shouldn't happen for a registered UE) — nothing to
            // resume by S-TMSI; drop it.
            None => warn!("UE {amf_ue_id}: released with no 5G-GUTI — context dropped, no resume"),
        }
    }
    Some(ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::NORMAL_RELEASE))
}

/// Implicit-deregistration sweep (TS 24.501 §5.3.7): evict retained CM-IDLE
/// contexts whose mobile-reachable / implicit-deregistration deadline
/// (`max_idle`) has passed — the UE neither resumed (Service Request) nor
/// periodically re-registered. Each evicted session's PDU sessions are released
/// at the SMF (freeing the UPF session + any buffered downlink) and its UECM
/// serving-AMF registration is purged. Runs off the N2 path.
async fn evict_stale_retained(amf_smf: &pdu_session::AmfSmf, max_idle: std::time::Duration) {
    // Collect the expired entries under the lock, then release off-lock.
    let expired: Vec<(u32, UeContext)> = {
        let mut retained = RETAINED.lock().unwrap();
        let stale: Vec<u32> = retained
            .iter()
            .filter(|(_, c)| c.retained_at.is_some_and(|t| t.elapsed() >= max_idle))
            .map(|(tmsi, _)| *tmsi)
            .collect();
        stale.into_iter().filter_map(|tmsi| retained.remove(&tmsi).map(|c| (tmsi, c))).collect()
    };
    for (tmsi, ctx) in expired {
        let supi = ctx.suci.clone();
        info!(
            "implicit deregistration: 5G-TMSI {tmsi:#010x} idle past the deadline — evicting ({} PDU session(s))",
            ctx.sm_refs.len()
        );
        for (psi, (sm_ref, smf_base)) in &ctx.sm_refs {
            match amf_smf.release_sm_context(smf_base, sm_ref).await {
                Ok(()) => info!("evicted UE: released PDU session {psi} ({sm_ref})"),
                Err(e) => warn!("evicted UE: PDU session {psi} release failed: {e}"),
            }
        }
        spawn_am_policy_delete(ctx.am_policy.clone());
        if let Some(supi) = supi {
            GUTI_DIRECTORY.lock().unwrap().retain(|_, s| s != &supi);
            spawn_sdm_unsubscribe(supi.clone());
            spawn_uecm_purge(supi);
        }
    }
}

/// Handle a CM-IDLE UE coming back over N2 — a **Service Request** (TS 23.502
/// §4.2.3.2, resume) or a **mobility registration update** (TS 24.501 §5.5.1.3,
/// the UE moved outside its registration area). The `tmsi` (from the
/// InitialUEMessage 5G-S-TMSI) named a retained context: take it, verify the
/// protected NAS with its security context, restore it under a fresh
/// AMF-UE-NGAP-ID, and
/// - **Service Request** → Service Accept + re-activate each PDU session's user
///   plane (Nsmf `ACTIVATING` → N2 PDU Session Resource Setup); a resume from
///   outside the registration area extends it;
/// - **mobility update** → **re-assign** the registration area from the new
///   serving gNB/TAI and send a Registration Accept carrying the new 5GS TAI list
///   (PDU sessions stay established; the user plane stays deactivated until a
///   Service Request — the Uplink Data Status IE is not modelled).
/// Back to CM-CONNECTED either way.
async fn on_service_request(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    msg: &InitialUEMessage,
    tmsi: u32,
    dereg_tx: &UnboundedSender<UeCmd>,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(ran_ue_id) = initial_ue_ran_id(msg) else {
        warn!("CM-IDLE return (tmsi {tmsi:#010x}) without RAN-UE-NGAP-ID");
        return Vec::new();
    };
    let Some(mut ctx) = RETAINED.lock().unwrap().remove(&tmsi) else {
        return Vec::new(); // raced with another resume — the context was already taken
    };

    // Verify the (integrity-protected) NAS with the retained keys — the UE proves
    // it holds the security context — and classify what it asks for. A failure
    // re-retains the context.
    let decoded = initial_ue_nas_pdu(msg)
        .and_then(|raw| ctx.sec.as_mut().and_then(|s| s.unprotect(raw, 0)));
    let is_service_request =
        decoded.as_ref().and_then(nas::service_request_info).is_some();
    let reg_type = decoded.as_ref().and_then(nas::registration_type_from_request);
    let is_mobility_update = reg_type == Some(nas::RegistrationType::MobilityRegistrationUpdate);
    // Periodic registration updating (TS 24.501 §5.5.1.3.2): a CM-IDLE UE proves it
    // is still reachable when T3512 expires — accepted lightweight (no re-auth),
    // which refreshes the retained context so the implicit-deregistration sweep
    // doesn't evict a UE that is still checking in.
    let is_periodic = reg_type == Some(nas::RegistrationType::PeriodicRegistrationUpdate);
    let is_registration_update = is_mobility_update || is_periodic;
    if !is_service_request && !is_registration_update {
        warn!("CM-IDLE return (tmsi {tmsi:#010x}) failed NAS verification — ignored");
        RETAINED.lock().unwrap().insert(tmsi, ctx);
        return Vec::new();
    }

    let amf_ue_id = NEXT_AMF_UE_ID.fetch_add(1, Ordering::Relaxed);
    ctx.ran_ue_id = ran_ue_id;
    ctx.cm_state = CmState::Connected;
    ctx.retained_at = None; // resumed — the mobile-reachable timer stops
    // Refresh the UE's tracking area from where it came back (it may have moved
    // while idle — the next paging round must target the new area).
    ctx.tac = ngap::tac_from_initial_ue(msg).or(ctx.tac);
    if is_mobility_update {
        // Mobility registration update: the UE left its registration area —
        // re-assign it around the new serving gNB/TAI.
        ctx.registration_area = registration_area_for(ctx.tac, dereg_tx);
    } else if is_service_request {
        // Service Request from outside the area: extend it (the UE should have
        // sent a mobility update; tolerate and stay reachable). A periodic update
        // means the UE hasn't moved — its area is unchanged.
        if let Some(tac) = ctx.tac {
            if !ctx.registration_area.is_empty() && !ctx.registration_area.contains(&tac) {
                ctx.registration_area.push(tac);
                ctx.registration_area.truncate(16);
            }
        }
    }
    // GUTI reallocation (TS 24.501 §5.4.1.3): a registration update reassigns the
    // 5G-GUTI — a fresh 5G-TMSI (this connection's AMF-UE-NGAP-ID, as at initial
    // registration). Re-key GUTI_DIRECTORY (SUPI → new TMSI) so a later GUTI
    // re-registration resolves; RETAINED re-keys naturally on the next AN release,
    // which retains under `ctx.guti_tmsi`. A Service Request keeps the GUTI.
    let reg_tmsi = if is_registration_update {
        let new_tmsi = amf_ue_id as u32;
        if let Some(supi) = &ctx.suci {
            let mut gutis = GUTI_DIRECTORY.lock().unwrap();
            gutis.retain(|_, s| s != supi);
            gutis.insert(new_tmsi, supi.clone());
        }
        ctx.guti_tmsi = Some(new_tmsi);
        new_tmsi
    } else {
        tmsi
    };
    // An AM policy change that arrived while the UE was CM-IDLE — applied below,
    // once the context is back in the association map.
    let pending_am_policy = ctx.pending_am_policy.take();
    let supi = ctx.suci.clone();

    // PDU Session Status reconciliation (TS 24.501 §5.6.1.5 / §5.6.2.4): the UE's
    // PDU Session Status IE lists the sessions it still holds. Release any session
    // the AMF tracks that the UE has locally dropped (an absent IE ⇒ the UE
    // reported nothing ⇒ keep everything). Done before the sm_refs snapshot so both
    // the reactivation set and the accept's advertised status reflect the
    // reconciled state.
    if let Some(ue_active) = decoded.as_ref().and_then(nas::pdu_session_status_from_request) {
        let dropped: Vec<(u8, (String, String))> = ctx
            .sm_refs
            .iter()
            .filter(|(psi, _)| !ue_active.contains(psi))
            .map(|(psi, v)| (*psi, v.clone()))
            .collect();
        for (psi, (sm_ref, smf_base)) in dropped {
            ctx.sm_refs.remove(&psi);
            warn!("UE {amf_ue_id}: PDU session {psi} dropped by the UE (PDU Session Status); releasing at the SMF");
            if let Err(e) = amf_smf.release_sm_context(&smf_base, &sm_ref).await {
                warn!("UE {amf_ue_id}: reconcile release for session {psi} failed: {e}");
            }
        }
    }
    // The network's authoritative active-session set for the accept's PDU Session
    // Status IE — the reconciled sm_refs, sorted for a stable bitmap.
    let mut active_psis: Vec<u8> = ctx.sm_refs.keys().copied().collect();
    active_psis.sort_unstable();

    let sm_refs: Vec<(u8, (String, String))> =
        ctx.sm_refs.iter().map(|(psi, v)| (*psi, v.clone())).collect();
    let ue_ambr = ctx.ue_ambr;
    // Protect the accept before the context moves into the association map: a
    // Service Accept for a resume, a Registration Accept (same GUTI, the NEW
    // registration area's 5GS TAI list) for a mobility update. The AN release
    // dropped the gNB's AS context, so the return re-establishes it with an
    // **Initial Context Setup** carrying a **fresh K_gNB** derived from the trigger
    // message's uplink NAS COUNT (TS 33.501 §6.9.2.1.1) — the accept rides as its
    // NAS-PDU.
    let allowed = ctx.allowed_nssai.clone().unwrap_or_default();
    let registration_area = ctx.registration_area.clone();
    let kamf = ctx.kamf;
    let ue_sec_cap = ctx.replayed_ue_sec_cap.unwrap_or(UE_SEC_CAP);
    let rfsp = ctx.rfsp;
    let area_restriction = ctx.area_restriction.clone();
    let accept = ctx.sec.as_mut().map(|s| {
        // `unprotect` already advanced ul_count past the Service Request /
        // mobility Registration Request that triggered this return.
        let kgnb = kamf.map(|k| aka::kgnb(&k, s.ul_count.wrapping_sub(1)));
        let (bytes, ics_label, dl_label) = if is_registration_update {
            // A registration update (mobility or periodic) is answered with a fresh
            // Registration Accept carrying the **reallocated** 5G-GUTI, T3512, and
            // the current registration area.
            let accept = nas::registration_accept(
                PLMN_MCC,
                PLMN_MNC,
                reg_tmsi,
                &allowed,
                &[],
                T3512_SECS,
                &registration_area,
                Some(&active_psis),
            );
            let (ics, dl) = if is_mobility_update {
                (
                    "InitialContextSetupRequest (RegistrationAccept — mobility update)",
                    "DownlinkNASTransport (RegistrationAccept — mobility update)",
                )
            } else {
                (
                    "InitialContextSetupRequest (RegistrationAccept — periodic)",
                    "DownlinkNASTransport (RegistrationAccept — periodic)",
                )
            };
            (s.protect(&accept, nas::sht::INTEGRITY_CIPHERED, 1), ics, dl)
        } else {
            (
                s.protect(&nas::service_accept(Some(&active_psis)), nas::sht::INTEGRITY_CIPHERED, 1),
                "InitialContextSetupRequest (ServiceAccept)",
                "DownlinkNASTransport (ServiceAccept)",
            )
        };
        (bytes, kgnb, ics_label, dl_label)
    });
    // Re-seed the NH chain from the freshly delivered K_gNB (NCC back to 0 — an
    // idle-resume derives a new initial AS key, TS 33.501 §6.9.2.3.3).
    if let Some((_, Some(k), _, _)) = &accept {
        ctx.nh_chain = Some((*k, 0));
    }
    ues.insert(amf_ue_id, ctx);
    if let Some(supi) = &supi {
        UE_DIRECTORY.lock().unwrap().insert(supi.clone(), (amf_ue_id, dereg_tx.clone()));
    }
    if is_mobility_update {
        info!(
            "UE {amf_ue_id}: mobility registration update (tmsi {tmsi:#010x} → {reg_tmsi:#010x}) — \
             registration area re-assigned to {registration_area:02x?}, GUTI reallocated"
        );
    } else if is_periodic {
        info!(
            "UE {amf_ue_id}: periodic registration update (tmsi {tmsi:#010x} → {reg_tmsi:#010x}) — \
             still reachable, GUTI reallocated, retained context refreshed"
        );
    } else {
        info!("UE {amf_ue_id} resuming from CM-IDLE (Service Request, tmsi {tmsi:#010x}); {} session(s)", sm_refs.len());
    }

    // Which PDU sessions get their user plane back: a **Service Request**
    // reactivates everything; a **registration update** reactivates only the
    // sessions the UE listed in its **Uplink Data Status** IE (TS 24.501
    // §9.11.3.57 — pending uplink data), leaving the rest deactivated.
    let uplink_data_psis =
        decoded.as_ref().map(nas::uplink_data_status_from_registration_request).unwrap_or_default();
    let reactivate: Vec<(u8, (String, String))> = if is_service_request {
        sm_refs.clone()
    } else if is_registration_update {
        sm_refs.iter().filter(|(psi, _)| uplink_data_psis.contains(psi)).cloned().collect()
    } else {
        Vec::new()
    };
    if is_registration_update && !reactivate.is_empty() {
        info!(
            "UE {amf_ue_id}: Uplink Data Status — reactivating PDU session(s) {:?}",
            reactivate.iter().map(|(psi, _)| *psi).collect::<Vec<_>>()
        );
    }
    // Fetch each reactivated session's retained UPF N3 F-TEID + QoS from its SMF
    // (Nsmf `ACTIVATING`). These set up **inline** in the Initial Context Setup —
    // one procedure — rather than trailing PDU Session Resource Setup Requests.
    let mut ics_sessions = Vec::new();
    for (psi, (sm_ref, smf_base)) in &reactivate {
        match amf_smf.activate_up_connection(smf_base, sm_ref).await {
            Ok(created) => {
                let flows = if created.ngap_flows.is_empty() {
                    vec![ngap::QosFlow::default_non_gbr()]
                } else {
                    created.ngap_flows.clone()
                };
                ics_sessions.push(ngap::IcsPduSession {
                    psi: *psi,
                    flows,
                    upf_teid: created.up_n3_teid,
                    upf_addr: created.up_n3_addr,
                });
                info!("UE {amf_ue_id}: PDU session {psi} reactivating (inline in the Initial Context Setup)");
            }
            Err(e) => warn!("UE {amf_ue_id}: PDU session {psi} reactivation failed: {e}"),
        }
    }

    let mut downlinks = Vec::new();
    if let Some((bytes, kgnb, ics_label, dl_label)) = accept {
        match kgnb {
            Some(security_key) => {
                let (allowed_tacs, not_allowed_tacs) = area_restriction.unwrap_or_default();
                let ic = ngap::InitialContext {
                    allowed_nssai: allowed,
                    ue_sec_cap,
                    security_key,
                    ue_ambr,
                    rfsp,
                    area_restriction: (!allowed_tacs.is_empty() || !not_allowed_tacs.is_empty())
                        .then_some((allowed_tacs, not_allowed_tacs)),
                    pdu_sessions: ics_sessions,
                    nas: bytes,
                };
                downlinks.push((
                    ngap::initial_context_setup_request(amf_ue_id, ran_ue_id, PLMN_MCC, PLMN_MNC, &ic),
                    ics_label,
                ));
            }
            None => {
                // No K_AMF retained (a pre-K_gNB context) — degrade to the plain
                // NAS transport + trailing PDU setups rather than hand the RAN a
                // bogus key.
                warn!("UE {amf_ue_id}: no K_AMF to derive a fresh K_gNB — accept without a context setup");
                downlinks.push((ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, bytes), dl_label));
                let (ambr_dl, ambr_ul) = ue_ambr.unwrap_or(DEFAULT_UE_AMBR_BPS);
                for s in &ics_sessions {
                    downlinks.push((
                        ngap::pdu_session_resource_setup_request(
                            amf_ue_id, ran_ue_id, s.psi, &s.flows, s.upf_teid, s.upf_addr, ambr_dl, ambr_ul, Vec::new(),
                        ),
                        "PDUSessionResourceSetupRequest (resume)",
                    ));
                }
            }
        }
    }

    // Apply an AM policy change that arrived while the UE was idle: the same
    // signalling as a CM-CONNECTED UpdateNotify (UE Context Modification to the RAN
    // + a Configuration Update Command, with the Mobility Restriction List when the
    // policy carries a service area).
    if let Some(p) = pending_am_policy {
        info!("UE {amf_ue_id}: applying the AM policy change held while CM-IDLE");
        downlinks.extend(on_am_policy_update(
            ues,
            amf_ue_id,
            p.ue_ambr,
            p.rfsp,
            p.area_restriction,
            dereg_tx,
        ));
    }
    downlinks
}

/// Handle an **Xn handover path switch** (TS 38.413 §8.4.4): the target gNB took
/// the UE over the Xn interface and asks the AMF to switch the downlink path. The
/// AMF re-points each switched PDU session's UPF downlink to the target's new DL
/// F-TEID (UpdateSMContext → N4 modify), refreshes the UE's location, rotates the
/// **NH chain** (TS 33.501 §6.9.2.3.3: NH = KDF(K_AMF, sync), NCC+1 mod 8), and
/// answers with a `PathSwitchRequestAcknowledge` carrying the fresh `{NCC, NH}`
/// for the target's vertical key derivation.
/// An N2 handover in flight (TS 23.502 §4.9.1.3), keyed by AMF-UE-NGAP-ID in
/// [`HANDOVERS`]: created at Handover Required, filled by the target's
/// acknowledge, consumed by Handover Notify.
struct PendingHandover {
    /// The source association's command channel (the Handover Command goes back
    /// through it; the context is taken from it at Notify).
    source_tx: UnboundedSender<UeCmd>,
    source_ran_ue_id: u32,
    /// The target association's command channel — cancellation / expiry cleans
    /// the target's side through it.
    target_tx: UnboundedSender<UeCmd>,
    /// The target's RAN-UE-NGAP-ID, known once it acknowledged.
    target_ran_ue_id: Option<u32>,
    /// The Handover Command was sent (the acknowledge arrived) — TNGRELOCprep
    /// stopped, TNGRELOCoverall runs.
    commanded: bool,
    /// The rotated NH-chain pair handed to the target in the Handover Request —
    /// applied to the context when the UE arrives.
    nh: [u8; 32],
    ncc: u8,
    /// Sessions admitted by the target: `(psi, target DL F-TEID, addr)`.
    admitted: Vec<(u8, u32, std::net::Ipv4Addr)>,
    /// The source signalled a direct Xn-U forwarding path. `false` ⇒ the AMF sets
    /// up **indirect forwarding** (source → UPF → target) via the SMFs.
    direct_forwarding: bool,
    /// The handed-over PDU sessions' SM contexts `(psi, (sm_ref, smf_base))` — how
    /// the ack/completion handlers reach the SMFs (the UE context lives on the
    /// source association, out of reach from the target where the ack lands).
    sessions: Vec<(u8, (String, String))>,
    /// Indirect forwarding tunnels were established — released on completion /
    /// cancellation / expiry.
    indirect_active: bool,
}

/// N2 handovers in flight, AMF-wide (the messages arrive on two different gNB
/// associations).
static HANDOVERS: LazyLock<Mutex<HashMap<u64, PendingHandover>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// TNGRELOCprep (TS 38.413 §8.4.1): bounds the preparation phase — armed at
/// Handover Required, stopped by the acknowledge. Expiry fails the handover
/// toward the source. Override with `RADIAN_AMF_TNGRELOCPREP_SECS`.
const TNGRELOCPREP_SECS: u64 = 10;
/// TNGRELOCoverall (TS 38.413 §8.4.2): bounds the whole relocation — armed at the
/// Handover Command, stopped by Handover Notify. Expiry drops the in-flight entry
/// and releases the target's prepared context. Override with
/// `RADIAN_AMF_TNGRELOCOVERALL_SECS`.
const TNGRELOCOVERALL_SECS: u64 = 20;

fn env_secs(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// TNGRELOCprep expiry: an unanswered handover preparation is dropped and failed
/// toward the source gNB.
async fn expire_handover_prep(amf_ue_id: u64, after: std::time::Duration) {
    tokio::time::sleep(after).await;
    let expired = {
        let mut handovers = HANDOVERS.lock().unwrap();
        match handovers.get(&amf_ue_id) {
            Some(p) if !p.commanded => handovers.remove(&amf_ue_id),
            _ => None, // acknowledged (TNGRELOCoverall takes over) or already done
        }
    };
    if let Some(p) = expired {
        warn!("UE {amf_ue_id}: TNGRELOCprep expired — handover preparation abandoned");
        let failure = ngap::handover_preparation_failure(
            amf_ue_id,
            p.source_ran_ue_id,
            ngap::CauseRadioNetwork::TNGRELOCPREP_EXPIRY,
        );
        let _ = p.source_tx.send(UeCmd::Forward {
            pdu: Box::new(failure),
            label: "HandoverPreparationFailure (TNGRELOCprep expiry)",
        });
    }
}

/// TNGRELOCoverall expiry: a commanded handover whose UE never arrived is dropped;
/// the target's prepared context and any indirect forwarding tunnels are released.
async fn expire_handover_overall(
    amf_ue_id: u64,
    amf_smf: pdu_session::AmfSmf,
    after: std::time::Duration,
) {
    tokio::time::sleep(after).await;
    let Some(p) = HANDOVERS.lock().unwrap().remove(&amf_ue_id) else {
        return; // completed (Notify consumed it)
    };
    warn!("UE {amf_ue_id}: TNGRELOCoverall expired — the UE never arrived at the target");
    if let Some(target_ran) = p.target_ran_ue_id {
        let release = ngap::ue_context_release_command_radio(
            amf_ue_id,
            target_ran,
            ngap::CauseRadioNetwork::TNGRELOCOVERALL_EXPIRY,
        );
        let _ = p.target_tx.send(UeCmd::Forward {
            pdu: Box::new(release),
            label: "UEContextReleaseCommand (TNGRELOCoverall expiry)",
        });
    }
    release_indirect_forwarding(&amf_smf, &p).await;
}

/// Handle a **Handover Required** (TS 38.413 §8.4.1, on the SOURCE association):
/// resolve the target gNB by its Global RAN Node ID, rotate the NH chain
/// (TS 33.501 §6.9.2.3.2 — the target derives its K_gNB from the fresh
/// `{NH, NCC}`), collect each PDU session's UL N3 F-TEID + QoS from the SMF, and
/// send the **Handover Request** on the target's association.
async fn on_handover_required(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    pdu: &NGAP_PDU,
    dereg_tx: &UnboundedSender<UeCmd>,
) -> Option<(NGAP_PDU, &'static str)> {
    let Some((amf_ue_id, ran_ue_id, target_gnb_id, psis, direct_forwarding, container)) =
        ngap::handover_required_params(pdu)
    else {
        warn!("HandoverRequired missing mandatory IEs — ignored");
        return None;
    };
    // Preparation-failure shorthand toward the source (this association).
    let prep_failure = |cause: u8| {
        Some((
            ngap::handover_preparation_failure(amf_ue_id, ran_ue_id, cause),
            "HandoverPreparationFailure",
        ))
    };
    let Some(ctx) = ues.get(&amf_ue_id) else {
        warn!("HandoverRequired for unknown UE {amf_ue_id} — preparation failed");
        return prep_failure(ngap::CauseRadioNetwork::UNKNOWN_LOCAL_UE_NGAP_ID);
    };
    let (Some(kamf), Some((sync, ncc))) = (ctx.kamf, ctx.nh_chain) else {
        warn!("UE {amf_ue_id}: handover without a seeded NH chain — preparation failed");
        return prep_failure(ngap::CauseRadioNetwork::UNSPECIFIED);
    };
    // The target gNB's association, by the id it advertised in its NG Setup.
    let Some(target_tx) = GNB_LINKS
        .lock()
        .unwrap()
        .iter()
        .find(|l| l.gnb_id == Some(target_gnb_id) && !l.tx.same_channel(dereg_tx))
        .map(|l| l.tx.clone())
    else {
        warn!("UE {amf_ue_id}: handover target gNB {target_gnb_id} has no N2 association — preparation failed");
        return prep_failure(ngap::CauseRadioNetwork::UNKNOWN_TARGET_ID);
    };
    // Vertical key derivation for the target (burned even if the handover fails).
    let fresh_nh = aka::nh(&kamf, &sync);
    let fresh_ncc = (ncc + 1) % 8;
    // Each session's UL N3 F-TEID + QoS flows, from its serving SMF (the same
    // retained-state fetch the Service Request resume uses).
    let mut sessions = Vec::new();
    let mut sm_contexts: Vec<(u8, (String, String))> = Vec::new();
    for psi in &psis {
        let Some((sm_ref, smf_base)) = ctx.sm_refs.get(psi).cloned() else {
            warn!("UE {amf_ue_id}: handover for PDU session {psi} but no SM context tracked");
            continue;
        };
        match amf_smf.activate_up_connection(&smf_base, &sm_ref).await {
            Ok(created) => {
                let flows = if created.ngap_flows.is_empty() {
                    vec![ngap::QosFlow::default_non_gbr()]
                } else {
                    created.ngap_flows.clone()
                };
                sessions.push((*psi, flows, created.up_n3_teid, created.up_n3_addr));
                sm_contexts.push((*psi, (sm_ref, smf_base)));
            }
            Err(e) => warn!("UE {amf_ue_id}: N3 info fetch for PDU session {psi} failed: {e}"),
        }
    }
    let request = ngap::handover_request(
        amf_ue_id,
        PLMN_MCC,
        PLMN_MNC,
        ctx.ue_ambr.unwrap_or(DEFAULT_UE_AMBR_BPS),
        &ctx.replayed_ue_sec_cap.unwrap_or(UE_SEC_CAP),
        fresh_ncc,
        &fresh_nh,
        &ctx.allowed_nssai.clone().unwrap_or_default(),
        &sessions,
        container,
    );
    info!(
        "UE {amf_ue_id}: N2 handover to gNB {target_gnb_id} — Handover Request sent \
         ({} session(s), NCC {fresh_ncc}, direct forwarding {direct_forwarding})",
        sessions.len()
    );
    HANDOVERS.lock().unwrap().insert(
        amf_ue_id,
        PendingHandover {
            source_tx: dereg_tx.clone(),
            source_ran_ue_id: ran_ue_id,
            target_tx: target_tx.clone(),
            target_ran_ue_id: None,
            commanded: false,
            nh: fresh_nh,
            ncc: fresh_ncc,
            admitted: Vec::new(),
            direct_forwarding,
            sessions: sm_contexts,
            indirect_active: false,
        },
    );
    // Bound the preparation phase (TNGRELOCprep): an unanswered target fails the
    // handover toward the source.
    tokio::spawn(expire_handover_prep(
        amf_ue_id,
        std::time::Duration::from_secs(env_secs("RADIAN_AMF_TNGRELOCPREP_SECS", TNGRELOCPREP_SECS)),
    ));
    let _ = target_tx.send(UeCmd::Forward {
        pdu: Box::new(request),
        label: "HandoverRequest",
    });
    None
}

/// Handle a **Handover Request Acknowledge** (on the TARGET association): record
/// the admitted sessions (the target's DL F-TEIDs, applied at Notify), set up the
/// data-forwarding path, and relay the target's transparent container to the
/// source in a **Handover Command**. With a direct Xn-U path the command carries
/// the target's forwarding F-TEIDs; otherwise the AMF sets up **indirect
/// forwarding** — a UPF forwarding tunnel per session (source → UPF → target) — and
/// the command carries the UPF's ingress F-TEIDs instead (TS 23.502 §4.9.1.3.3).
async fn on_handover_request_ack(amf_smf: &pdu_session::AmfSmf, pdu: &NGAP_PDU) {
    let Some((amf_ue_id, target_ran_ue_id, admitted, container)) =
        ngap::handover_request_ack_params(pdu)
    else {
        warn!("HandoverRequestAcknowledge missing mandatory IEs — ignored");
        return;
    };
    // Snapshot what the forwarding setup needs (the lock can't be held across the
    // await); bail if there's no handover in flight.
    let (source_ran_ue_id, source_tx, direct_forwarding, session_ctx) = {
        let mut handovers = HANDOVERS.lock().unwrap();
        let Some(pending) = handovers.get_mut(&amf_ue_id) else {
            warn!("HandoverRequestAcknowledge for UE {amf_ue_id} with no handover in flight");
            return;
        };
        pending.admitted = admitted.iter().map(|(psi, teid, addr, _)| (*psi, *teid, *addr)).collect();
        pending.target_ran_ue_id = Some(target_ran_ue_id);
        pending.commanded = true;
        (
            pending.source_ran_ue_id,
            pending.source_tx.clone(),
            pending.direct_forwarding,
            pending.sessions.clone(),
        )
    };
    // TNGRELOCprep stops here; TNGRELOCoverall bounds the execution phase.
    tokio::spawn(expire_handover_overall(
        amf_ue_id,
        amf_smf.clone(),
        std::time::Duration::from_secs(env_secs("RADIAN_AMF_TNGRELOCOVERALL_SECS", TNGRELOCOVERALL_SECS)),
    ));

    // Build the Handover Command's forwarding list.
    let mut forwarding = Vec::new();
    let mut indirect_active = false;
    for (psi, _dl_teid, _dl_addr, fwd) in &admitted {
        let Some((target_fwd_teid, target_fwd_addr)) = *fwd else {
            continue; // this session isn't forwarding
        };
        if direct_forwarding {
            // Xn-U path: the source forwards straight to the target's F-TEID.
            forwarding.push((*psi, target_fwd_teid, target_fwd_addr));
        } else if let Some((_, (sm_ref, smf_base))) = session_ctx.iter().find(|(p, _)| p == psi) {
            // No Xn-U: set up a UPF forwarding tunnel and give the source its
            // ingress F-TEID instead.
            match amf_smf
                .setup_indirect_forwarding(smf_base, sm_ref, target_fwd_teid, target_fwd_addr)
                .await
            {
                Ok((upf_teid, upf_addr)) => {
                    forwarding.push((*psi, upf_teid, upf_addr));
                    indirect_active = true;
                }
                Err(e) => warn!("UE {amf_ue_id}: indirect forwarding setup for PDU session {psi} failed: {e}"),
            }
        }
    }
    // The overall-expiry task may already have fired; only record if still pending.
    if let Some(pending) = HANDOVERS.lock().unwrap().get_mut(&amf_ue_id) {
        pending.indirect_active = indirect_active;
    }
    info!(
        "UE {amf_ue_id}: target admitted {} session(s) (target RAN-UE {target_ran_ue_id}, {} \
         {} forwarding tunnel(s)) — Handover Command to the source",
        admitted.len(),
        forwarding.len(),
        if direct_forwarding { "direct" } else { "indirect" }
    );
    let command = ngap::handover_command(amf_ue_id, source_ran_ue_id, &forwarding, container);
    let _ = source_tx.send(UeCmd::Forward { pdu: Box::new(command), label: "HandoverCommand" });
}

/// Release any indirect data-forwarding tunnels a handover set up (idempotent).
async fn release_indirect_forwarding(amf_smf: &pdu_session::AmfSmf, p: &PendingHandover) {
    if !p.indirect_active {
        return;
    }
    for (_psi, (sm_ref, smf_base)) in &p.sessions {
        if let Err(e) = amf_smf.release_indirect_forwarding(smf_base, sm_ref).await {
            warn!("release of indirect forwarding ({sm_ref}) failed: {e}");
        }
    }
}

/// Handle a **Handover Failure** (on the TARGET association): the target cannot
/// allocate resources — drop the in-flight handover and fail it toward the source
/// (Handover Preparation Failure).
fn on_handover_failure(pdu: &NGAP_PDU) {
    let Some((amf_ue_id, cause)) = ngap::handover_failure_params(pdu) else {
        warn!("HandoverFailure missing mandatory IEs — ignored");
        return;
    };
    let Some(pending) = HANDOVERS.lock().unwrap().remove(&amf_ue_id) else {
        warn!("HandoverFailure for UE {amf_ue_id} with no handover in flight");
        return;
    };
    warn!("UE {amf_ue_id}: the target rejected the handover (cause {cause:?}) — failing the source");
    let failure = ngap::handover_preparation_failure(
        amf_ue_id,
        pending.source_ran_ue_id,
        cause.unwrap_or(ngap::CauseRadioNetwork::HO_FAILURE_IN_TARGET_5GC_NGRAN_NODE_OR_TARGET_SYSTEM),
    );
    let _ = pending.source_tx.send(UeCmd::Forward {
        pdu: Box::new(failure),
        label: "HandoverPreparationFailure (target rejected)",
    });
}

/// Handle a **Handover Cancel** (on the SOURCE association): the source aborts
/// the in-flight handover — drop it, release the target's prepared context (when
/// it already acknowledged), and answer with a Handover Cancel Acknowledge.
async fn on_handover_cancel(
    amf_smf: &pdu_session::AmfSmf,
    pdu: &NGAP_PDU,
) -> Option<(NGAP_PDU, &'static str)> {
    let Some((amf_ue_id, ran_ue_id)) = ngap::handover_cancel_params(pdu) else {
        warn!("HandoverCancel missing mandatory IEs — ignored");
        return None;
    };
    let pending = HANDOVERS.lock().unwrap().remove(&amf_ue_id);
    match pending {
        Some(pending) => {
            info!("UE {amf_ue_id}: handover cancelled by the source");
            if let Some(target_ran) = pending.target_ran_ue_id {
                // The target had prepared resources — release its side.
                let release = ngap::ue_context_release_command_radio(
                    amf_ue_id,
                    target_ran,
                    ngap::CauseRadioNetwork::HANDOVER_CANCELLED,
                );
                let _ = pending.target_tx.send(UeCmd::Forward {
                    pdu: Box::new(release),
                    label: "UEContextReleaseCommand (handover cancelled)",
                });
            }
            release_indirect_forwarding(amf_smf, &pending).await;
        }
        None => info!("UE {amf_ue_id}: cancel for no handover in flight — acknowledging anyway"),
    }
    Some((ngap::handover_cancel_acknowledge(amf_ue_id, ran_ue_id), "HandoverCancelAcknowledge"))
}

/// Handle a **Handover Notify** (on the TARGET association): the UE arrived. Take
/// the context over from the source association (which releases its gNB — cause
/// *successful-handover*), apply the rotated NH chain and the new location,
/// re-point each admitted session's UPF downlink to the target's DL F-TEID, and
/// re-point the SBI callback directory at this association.
async fn on_handover_notify(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    pdu: &NGAP_PDU,
    dereg_tx: &UnboundedSender<UeCmd>,
) {
    let Some((amf_ue_id, target_ran_ue_id, tac)) = ngap::handover_notify_params(pdu) else {
        warn!("HandoverNotify missing mandatory IEs — ignored");
        return;
    };
    let Some(pending) = HANDOVERS.lock().unwrap().remove(&amf_ue_id) else {
        warn!("HandoverNotify for UE {amf_ue_id} with no handover in flight");
        return;
    };
    // Take the context from the source association; it releases its gNB's side.
    if !ues.contains_key(&amf_ue_id) {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let _ = pending.source_tx.send(UeCmd::TakeUe { amf_ue_id, reply: reply_tx });
        match tokio::time::timeout(std::time::Duration::from_millis(500), reply_rx).await {
            Ok(Ok(Some(ctx))) => {
                ues.insert(amf_ue_id, *ctx);
            }
            _ => {
                warn!("UE {amf_ue_id}: handover notify but the source no longer owns the context");
                return;
            }
        }
    }
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return; // unreachable
    };
    ctx.ran_ue_id = target_ran_ue_id;
    ctx.tac = tac.or(ctx.tac);
    ctx.nh_chain = Some((pending.nh, pending.ncc));
    if let Some(supi) = &ctx.suci {
        UE_DIRECTORY.lock().unwrap().insert(supi.clone(), (amf_ue_id, dereg_tx.clone()));
    }
    info!(
        "UE {amf_ue_id}: N2 handover complete — at the target gNB (RAN-UE {target_ran_ue_id}, \
         TAC {tac:02x?}, NCC {})",
        pending.ncc
    );
    // Re-point each admitted session's UPF downlink to the target gNB.
    for (psi, gnb_teid, gnb_addr) in &pending.admitted {
        let Some((sm_ref, smf_base)) = ues.get(&amf_ue_id).and_then(|c| c.sm_refs.get(psi).cloned())
        else {
            continue;
        };
        match amf_smf.update_sm_context(&smf_base, &sm_ref, *gnb_teid, *gnb_addr).await {
            Ok(()) => info!("UE {amf_ue_id}: PDU session {psi} switched to the target (F-TEID {gnb_teid:#x})"),
            Err(e) => warn!("UE {amf_ue_id}: handover UpdateSMContext failed for {psi}: {e}"),
        }
    }
    // The UE is on the target: the forwarding tunnels have done their job.
    release_indirect_forwarding(amf_smf, &pending).await;
}

/// Hand a UE context over to the association an Xn path switch landed on: remove
/// it, reply on the oneshot, and — when this task really owned it — command the
/// **source gNB** to release its stale UE context (TS 23.502 §4.9.1.2 completes
/// with the source side released; cause *successful-handover*).
fn on_take_ue(
    ues: &mut HashMap<u64, UeContext>,
    amf_ue_id: u64,
    reply: tokio::sync::oneshot::Sender<Option<Box<UeContext>>>,
) -> Vec<(NGAP_PDU, &'static str)> {
    let ctx = ues.remove(&amf_ue_id);
    let release = ctx.as_ref().map(|c| {
        info!(
            "UE {amf_ue_id}: handed over to another gNB — releasing the source's stale context \
             (RAN-UE {})",
            c.ran_ue_id
        );
        (
            ngap::ue_context_release_command_radio(
                amf_ue_id,
                c.ran_ue_id,
                ngap::CauseRadioNetwork::SUCCESSFUL_HANDOVER,
            ),
            "UEContextReleaseCommand (successful handover)",
        )
    });
    let _ = reply.send(ctx.map(Box::new));
    release.into_iter().collect()
}

async fn on_path_switch(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    pdu: &NGAP_PDU,
    dereg_tx: &UnboundedSender<UeCmd>,
) -> Option<(NGAP_PDU, &'static str)> {
    let Some((amf_ue_id, new_ran_ue_id, tac, sessions)) = ngap::path_switch_params(pdu) else {
        warn!("PathSwitchRequest missing mandatory IEs — ignored");
        return None;
    };
    // The path switch arrives on the TARGET gNB's association, but the UE context
    // lives with the SOURCE gNB's. Take it over: ask every other association to
    // hand it out; the owner replies with the context and releases its gNB's
    // stale side (UEContextReleaseCommand, cause successful-handover).
    if !ues.contains_key(&amf_ue_id) {
        let others: Vec<UnboundedSender<UeCmd>> = GNB_LINKS
            .lock()
            .unwrap()
            .iter()
            .filter(|l| !l.tx.same_channel(dereg_tx))
            .map(|l| l.tx.clone())
            .collect();
        // Ask every other association concurrently (a live select loop answers
        // immediately — the owner with the context, everyone else with None);
        // the overall wait is bounded, not per-link.
        let mut asks = tokio::task::JoinSet::new();
        for tx in others {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if tx.send(UeCmd::TakeUe { amf_ue_id, reply: reply_tx }).is_ok() {
                asks.spawn(async move {
                    tokio::time::timeout(std::time::Duration::from_millis(500), reply_rx)
                        .await
                        .ok()
                        .and_then(|r| r.ok())
                        .flatten()
                });
            }
        }
        let mut taken = None;
        while let Some(res) = asks.join_next().await {
            if let Ok(Some(ctx)) = res {
                taken = Some(ctx);
                break;
            }
        }
        asks.abort_all();
        match taken {
            Some(ctx) => {
                info!("UE {amf_ue_id}: context taken over from the source gNB's association");
                ues.insert(amf_ue_id, *ctx);
            }
            None => {
                warn!("PathSwitchRequest for unknown UE {amf_ue_id} — no association owns it");
                let psis: Vec<u8> = sessions.iter().map(|(psi, _, _)| *psi).collect();
                return Some((
                    ngap::path_switch_request_failure(
                        amf_ue_id,
                        new_ran_ue_id,
                        &psis,
                        ngap::CauseRadioNetwork::UNKNOWN_LOCAL_UE_NGAP_ID,
                    ),
                    "PathSwitchRequestFailure",
                ));
            }
        }
    }
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return None; // unreachable: inserted or present above
    };
    // The NH chain needs K_AMF and a seeded sync input (the ICS-delivered K_gNB).
    let (Some(kamf), Some((sync, ncc))) = (ctx.kamf, ctx.nh_chain) else {
        warn!("UE {amf_ue_id}: path switch without a seeded NH chain — failing it");
        let psis: Vec<u8> = sessions.iter().map(|(psi, _, _)| *psi).collect();
        return Some((
            ngap::path_switch_request_failure(
                amf_ue_id,
                new_ran_ue_id,
                &psis,
                ngap::CauseRadioNetwork::UNSPECIFIED,
            ),
            "PathSwitchRequestFailure",
        ));
    };
    ctx.ran_ue_id = new_ran_ue_id;
    ctx.tac = tac.or(ctx.tac);
    // Vertical key derivation: a fresh NH, NCC incremented (3-bit counter).
    let fresh_nh = aka::nh(&kamf, &sync);
    let fresh_ncc = (ncc + 1) % 8;
    ctx.nh_chain = Some((fresh_nh, fresh_ncc));
    // The SBI callback surface must now reach the UE through THIS association.
    if let Some(supi) = &ctx.suci {
        UE_DIRECTORY.lock().unwrap().insert(supi.clone(), (amf_ue_id, dereg_tx.clone()));
    }
    info!(
        "UE {amf_ue_id}: Xn path switch to RAN-UE {new_ran_ue_id} (TAC {tac:02x?}) — NH chain \
         rotated to NCC {fresh_ncc}, {} session(s) to switch",
        sessions.len()
    );

    // Re-point each switched session's UPF downlink to the target gNB.
    let mut switched = Vec::new();
    for (psi, gnb_teid, gnb_addr) in &sessions {
        let Some((sm_ref, smf_base)) = ues.get(&amf_ue_id).and_then(|c| c.sm_refs.get(psi).cloned())
        else {
            warn!("UE {amf_ue_id}: path switch for PDU session {psi} but no SM context tracked");
            continue;
        };
        match amf_smf.update_sm_context(&smf_base, &sm_ref, *gnb_teid, *gnb_addr).await {
            Ok(()) => {
                info!("UE {amf_ue_id}: PDU session {psi} switched to the target gNB (F-TEID {gnb_teid:#x})");
                switched.push(*psi);
            }
            Err(e) => warn!("UE {amf_ue_id}: path switch UpdateSMContext failed for {psi}: {e}"),
        }
    }

    Some((
        ngap::path_switch_request_acknowledge(amf_ue_id, new_ran_ue_id, fresh_ncc, &fresh_nh, &switched),
        "PathSwitchRequestAcknowledge",
    ))
}

/// Handle a gNB's `PDUSessionResourceSetupResponse`: extract the gNB DL N3 F-TEID and
/// drive UpdateSMContext at the SMF (which runs the N4 Session Modification).
async fn on_pdu_session_setup_response(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    pdu: &NGAP_PDU,
) {
    let Some((psi, gnb_teid, gnb_addr)) = ngap::gnb_fteid_from_setup_response(pdu) else {
        warn!("PDUSessionResourceSetupResponse without a gNB F-TEID");
        return;
    };
    let Some(amf_ue_id) = setup_response_amf_ue_id(pdu) else {
        warn!("PDUSessionResourceSetupResponse without AMF-UE-NGAP-ID");
        return;
    };
    let Some((sm_ref, smf_base)) = ues.get(&amf_ue_id).and_then(|c| c.sm_refs.get(&psi).cloned())
    else {
        warn!("UE {amf_ue_id}: setup response for PDU session {psi} but no SM context tracked");
        return;
    };
    match amf_smf.update_sm_context(&smf_base, &sm_ref, gnb_teid, gnb_addr).await {
        Ok(()) => info!("UE {amf_ue_id}: PDU session {psi} downlink installed (gNB F-TEID {gnb_teid:#x})"),
        Err(e) => warn!("UE {amf_ue_id}: UpdateSMContext failed: {e}"),
    }
}

/// Handle a gNB's `InitialContextSetupResponse`: the UE context is up. When the
/// ICS set up PDU sessions **inline** (Cxt Res list — a Service Request resume,
/// design/88), drive UpdateSMContext with each session's gNB DL N3 F-TEID, exactly
/// as the standalone PDU Session Resource Setup Response path does.
async fn on_initial_context_setup_response(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    pdu: &NGAP_PDU,
) {
    let Some((amf_ue_id, _ran)) = ngap::initial_context_setup_response_ids(pdu) else {
        warn!("gNB InitialContextSetupResponse (unparseable)");
        return;
    };
    let sessions = ngap::initial_context_setup_session_ids(pdu);
    info!(
        "gNB established the UE context (InitialContextSetupResponse) for UE {amf_ue_id} \
         ({} inline session(s))",
        sessions.len()
    );
    for (psi, gnb_teid, gnb_addr) in sessions {
        let Some((sm_ref, smf_base)) = ues.get(&amf_ue_id).and_then(|c| c.sm_refs.get(&psi).cloned())
        else {
            warn!("UE {amf_ue_id}: ICS response for PDU session {psi} but no SM context tracked");
            continue;
        };
        match amf_smf.update_sm_context(&smf_base, &sm_ref, gnb_teid, gnb_addr).await {
            Ok(()) => info!("UE {amf_ue_id}: PDU session {psi} downlink installed (gNB F-TEID {gnb_teid:#x})"),
            Err(e) => warn!("UE {amf_ue_id}: ICS-inline UpdateSMContext failed for {psi}: {e}"),
        }
    }

    // Sessions the gNB could NOT set up (PDUSessionResourceFailedToSetupListCxtRes):
    // the RAN never established them, so release each at the SMF (tearing down the
    // UPF datapath) and drop it from the UE context — otherwise the AMF would keep
    // an orphaned session it would try to reactivate on the next resume.
    for (psi, cause) in ngap::initial_context_setup_failed_session_ids(pdu) {
        let Some((sm_ref, smf_base)) = ues.get(&amf_ue_id).and_then(|c| c.sm_refs.get(&psi).cloned())
        else {
            warn!("UE {amf_ue_id}: ICS response rejects PDU session {psi} (cause {cause}) but no SM context tracked");
            continue;
        };
        warn!("UE {amf_ue_id}: gNB rejected PDU session {psi} in the InitialContextSetup (cause {cause}); releasing at the SMF");
        match amf_smf.release_sm_context(&smf_base, &sm_ref).await {
            Ok(()) => info!("UE {amf_ue_id}: PDU session {psi} released after ICS setup failure"),
            Err(e) => warn!("UE {amf_ue_id}: release after ICS failure for {psi} failed: {e}"),
        }
        if let Some(c) = ues.get_mut(&amf_ue_id) {
            c.sm_refs.remove(&psi);
        }
    }
}

/// The gNB confirmed a network-initiated PDU session release
/// (`PDUSessionResourceReleaseResponse`): the RAN resources (DRBs / N3 tunnel) are
/// torn down. The session is **not** finalised at the SMF yet — that waits for the
/// UE's N1 PDU Session Release Complete (TS 23.502 §4.3.4, [`finalize_release`]),
/// with the guard timer as a backstop.
fn on_release_response(ues: &HashMap<u64, UeContext>, pdu: &NGAP_PDU) {
    let Some((amf_ue_id, _ran, released)) = ngap::release_response_result(pdu) else {
        info!("gNB PDUSessionResourceReleaseResponse (unparseable)");
        return;
    };
    for psi in &released {
        if ues.get(&amf_ue_id).map(|c| c.releasing.contains(psi)) != Some(true) {
            warn!("UE {amf_ue_id}: release response for psi {psi} not awaiting release");
        }
    }
    info!(
        "UE {amf_ue_id}: gNB freed RAN resources for PDU session(s) {released:?} — \
         awaiting the UE's Release Complete"
    );
}

/// Finalise a network-initiated release once the UE's N1 PDU Session Release
/// Complete arrives (or the guard timer fires): release the SM context at the SMF
/// (N4 delete / IP release) and drop the session from the UE context. Idempotent —
/// a no-op if the session isn't releasing (already finalised).
async fn finalize_release(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    amf_ue_id: u64,
    psi: u8,
) {
    // Only finalise a session an active release is awaiting — guards against a
    // stray complete and against the guard firing after the complete already ran.
    if ues.get(&amf_ue_id).map(|c| c.releasing.contains(&psi)) != Some(true) {
        return;
    }
    if let Some((sm_ref, smf_base)) =
        ues.get(&amf_ue_id).and_then(|c| c.sm_refs.get(&psi).cloned())
    {
        match amf_smf.release_sm_context(&smf_base, &sm_ref).await {
            Ok(()) => info!("UE {amf_ue_id}: PDU session {psi} released at the SMF"),
            Err(e) => warn!("UE {amf_ue_id}: SMF release for session {psi} failed: {e}"),
        }
    }
    if let Some(c) = ues.get_mut(&amf_ue_id) {
        c.sm_refs.remove(&psi);
        c.releasing.remove(&psi);
    }
}

/// Extract the AMF-UE-NGAP-ID from a `PDUSessionResourceSetupResponse`.
fn setup_response_amf_ue_id(pdu: &NGAP_PDU) -> Option<u64> {
    let NGAP_PDU::SuccessfulOutcome(so) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_PDUSessionResourceSetup(resp) = &so.value else {
        return None;
    };
    resp.protocol_i_es.0.iter().find_map(|e| match &e.value {
        PDUSessionResourceSetupResponseProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => Some(id.0),
        _ => None,
    })
}

/// Identify the UE and create its context. Returns what to do next.
fn on_initial_ue(
    ues: &mut HashMap<u64, UeContext>,
    msg: &InitialUEMessage,
    amf_ue_id: u64,
    dereg_tx: &UnboundedSender<UeCmd>,
) -> Option<InitialUeOutcome> {
    let ran_ue_id = initial_ue_ran_id(msg)?;
    let identity = initial_ue_nas_pdu(msg)
        .and_then(|b| nas::decode_nas_5gs_message(b).ok())
        .and_then(registration_identity);

    // Resolve the identity to a SUPI: directly from a SUCI, or via the GUTI
    // directory for a returning UE (which is then re-authenticated like any
    // other — fresh 5G-AKA + NAS security). An unknown GUTI (e.g. an AMF
    // restart lost the mapping) falls back to an Identity Request for the SUCI.
    let (resolved, ue_sec_cap, requested_nssai) = match identity {
        Some((RegIdentity::Supi(supi), cap, nssai)) => (Some(supi), cap, nssai),
        Some((RegIdentity::GutiTmsi(tmsi), cap, nssai)) => {
            let hit = GUTI_DIRECTORY.lock().unwrap().get(&tmsi).cloned();
            match &hit {
                Some(supi) => info!(
                    "UE {amf_ue_id}: 5G-GUTI re-registration (tmsi {tmsi:#010x}) resolved to \
                     {supi}; re-authenticating"
                ),
                None => info!(
                    "UE {amf_ue_id}: unknown 5G-GUTI (tmsi {tmsi:#010x}) — asking for the SUCI"
                ),
            }
            (hit, cap, nssai)
        }
        Some((RegIdentity::Unknown, cap, nssai)) => (None, cap, nssai),
        None => (None, None, Vec::new()),
    };

    match resolved {
        Some(supi) => {
            let mut ctx = UeContext::new(ran_ue_id, RegState::Identified, Some(supi.clone()));
            ctx.replayed_ue_sec_cap = ue_sec_cap;
            ctx.requested_nssai = requested_nssai;
            // The UE's tracking area (from the gNB's ULI) + its assigned
            // registration area: the serving gNB's Supported TA List ∪ the UE's
            // TAI (the UE roams those areas without re-registering; paging is
            // scoped to them).
            ctx.tac = ngap::tac_from_initial_ue(msg);
            ctx.registration_area = registration_area_for(ctx.tac, dereg_tx);
            if let Some(tac) = ctx.tac {
                info!(
                    "UE {amf_ue_id}: registering from TAC {tac:02x?}; registration area {:02x?}",
                    ctx.registration_area
                );
            }
            ues.insert(amf_ue_id, ctx);
            // Make the UE reachable from the SBI callback surface (withdrawals).
            UE_DIRECTORY.lock().unwrap().insert(supi.clone(), (amf_ue_id, dereg_tx.clone()));
            Some(InitialUeOutcome::Identified { ran_ue_id, supi })
        }
        None => {
            // Keep whatever the request carried: when the Identity Response
            // resolves the SUPI, the security caps + requested NSSAI still apply.
            let mut ctx = UeContext::new(ran_ue_id, RegState::IdentityRequested, None);
            ctx.replayed_ue_sec_cap = ue_sec_cap;
            ctx.requested_nssai = requested_nssai;
            ctx.tac = ngap::tac_from_initial_ue(msg);
            ues.insert(amf_ue_id, ctx);
            let dl = ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, nas::identity_request_suci());
            Some(InitialUeOutcome::NeedIdentity(dl))
        }
    }
}

impl UeContext {
    fn new(ran_ue_id: u32, state: RegState, suci: Option<String>) -> Self {
        Self {
            ran_ue_id,
            state,
            suci,
            auth: None,
            sec: None,
            kamf: None,
            nh_chain: None,
            replayed_ue_sec_cap: None,
            sm_refs: HashMap::new(),
            session_snssai: HashMap::new(),
            subscribed_ue_ambr: None,
            pcf_ue_ambr: None,
            ue_ambr: None,
            rfsp: None,
            area_restriction: None,
            allowed_nssai: None,
            requested_nssai: Vec::new(),
            dereg_attempts: None,
            resync_attempted: false,
            cm_state: CmState::Connected,
            guti_tmsi: None,
            tac: None,
            registration_area: Vec::new(),
            retained_at: None,
            am_policy: None,
            pending_am_policy: None,
            releasing: std::collections::HashSet::new(),
            pending_config_update: None,
        }
    }

    /// Recompute the effective UE-AMBR from its sources: a PCF AM-policy override
    /// takes precedence over the subscribed (am-data) value.
    fn recompute_ue_ambr(&mut self) {
        self.ue_ambr = self.pcf_ue_ambr.or(self.subscribed_ue_ambr);
    }
}

/// Discover the AUSF, fetch a challenge, and send the NAS Authentication Request.
async fn start_authentication(
    conn: &ConnectedSocket,
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_ue_id: u64,
    ran_ue_id: u32,
    supi: &str,
) {
    info!("UE {amf_ue_id} identified ({supi}); starting authentication");
    match amf_auth.begin(supi).await {
        Ok((pending, nas_req)) => {
            if let Some(ctx) = ues.get_mut(&amf_ue_id) {
                ctx.auth = Some(pending);
                ctx.state = RegState::Authenticating;
            }
            let dl = ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, nas_req);
            send_or_log(conn, &dl, "DownlinkNASTransport (AuthenticationRequest)").await;
        }
        Err(e) => warn!("UE {amf_ue_id}: authentication start failed: {e}"),
    }
}

/// Correlate an uplink NAS message to its UE, verify/decipher it if a security
/// context exists, and dispatch by 5GMM message type. Returns a downlink to send.
async fn on_uplink_nas(
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_smf: &pdu_session::AmfSmf,
    msg: &UplinkNASTransport,
    dereg_tx: &UnboundedSender<UeCmd>,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(amf_ue_id) = uplink_amf_ue_id(msg) else {
        warn!("UplinkNASTransport without AMF-UE-NGAP-ID");
        return Vec::new();
    };
    if !ues.contains_key(&amf_ue_id) {
        warn!("uplink NAS for unknown UE {amf_ue_id}");
        return Vec::new();
    }
    let Some(raw) = uplink_nas_pdu(msg) else {
        warn!("UE {amf_ue_id}: UplinkNASTransport without NAS-PDU");
        return Vec::new();
    };

    // After the Security Mode Command, uplink NAS is integrity-protected/ciphered.
    let has_sec = ues.get(&amf_ue_id).is_some_and(|c| c.sec.is_some());
    let nas_msg = if has_sec {
        ues.get_mut(&amf_ue_id)
            .and_then(|c| c.sec.as_mut())
            .and_then(|s| s.unprotect(raw, 0))
    } else {
        nas::decode_nas_5gs_message(raw).ok()
    };
    let Some(nas_msg) = nas_msg else {
        warn!("UE {amf_ue_id}: could not verify/decode uplink NAS");
        return Vec::new();
    };

    // These procedures answer with more than one downlink (or need the multi-PDU
    // shape): Authentication Response (a rejected RES* → Authentication Reject + UE
    // Context Release), Security Mode Complete (a Registration Reject may be followed
    // by the release), and Deregistration (Accept + Release Command).
    match nas::gmm_message_type(&nas_msg) {
        Some(Nas5gmmMessageType::AuthenticationResponse) => {
            return complete_authentication(ues, amf_auth, amf_ue_id, &nas_msg).await;
        }
        Some(Nas5gmmMessageType::SecurityModeComplete) => {
            return on_security_mode_complete(ues, amf_ue_id, &NRF_BASE).await;
        }
        Some(Nas5gmmMessageType::DeregistrationRequestFromUe) => {
            return on_deregistration(ues, amf_smf, amf_ue_id, &nas_msg).await;
        }
        _ => {}
    }
    dispatch_uplink_nas(ues, amf_auth, amf_smf, amf_ue_id, nas_msg, dereg_tx)
        .await
        .into_iter()
        .collect()
}

/// UE-initiated deregistration (TS 24.501 §5.5.2.2): release the PDU session at
/// the SMF (N4 teardown), answer with a Deregistration Accept — unless the UE is
/// switching off, which expects silence — then release the RAN-side UE context
/// (UEContextReleaseCommand) and drop the AMF context.
async fn on_deregistration(
    ues: &mut HashMap<u64, UeContext>,
    amf_smf: &pdu_session::AmfSmf,
    amf_ue_id: u64,
    nas_msg: &Nas5gsMessage,
) -> Vec<(NGAP_PDU, &'static str)> {
    let switch_off = nas::deregistration_is_switch_off(nas_msg).unwrap_or(false);
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return Vec::new();
    };
    let ran_ue_id = ctx.ran_ue_id;

    // Tear down an in-progress/active PDU session first — best effort: the UE is
    // leaving either way, so a release failure is logged, not fatal.
    for (psi, (sm_ref, smf_base)) in std::mem::take(&mut ctx.sm_refs) {
        match amf_smf.release_sm_context(&smf_base, &sm_ref).await {
            Ok(()) => info!("UE {amf_ue_id}: released SM context {sm_ref} (psi {psi}) on deregistration"),
            Err(e) => warn!("UE {amf_ue_id}: SM context {sm_ref} (psi {psi}) release failed: {e}"),
        }
    }

    let mut downlinks = Vec::new();
    if switch_off {
        info!("UE {amf_ue_id}: deregistration (switch-off) — no accept expected");
    } else if let Some(sec) = ctx.sec.as_mut() {
        let bytes = sec.protect(&nas::deregistration_accept(), nas::sht::INTEGRITY_CIPHERED, 1);
        downlinks.push((
            ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, bytes),
            "DownlinkNASTransport (DeregistrationAccept)",
        ));
        info!("UE {amf_ue_id}: deregistered — sending Deregistration Accept");
    } else {
        warn!("UE {amf_ue_id}: deregistration before NAS security; no accept sent");
    }
    downlinks.push((
        ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::DEREGISTER),
        "UEContextReleaseCommand",
    ));
    if let Some(supi) = ues.get(&amf_ue_id).and_then(|c| c.suci.clone()) {
        UE_DIRECTORY.lock().unwrap().remove(&supi);
        spawn_sdm_unsubscribe(supi.clone());
        spawn_uecm_purge(supi);
    }
    spawn_am_policy_delete(ues.get_mut(&amf_ue_id).and_then(|c| c.am_policy.take()));
    ues.remove(&amf_ue_id);
    downlinks
}

/// Handle one verified uplink NAS message that answers with at most one downlink.
async fn dispatch_uplink_nas(
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_smf: &pdu_session::AmfSmf,
    amf_ue_id: u64,
    nas_msg: Nas5gsMessage,
    dereg_tx: &UnboundedSender<UeCmd>,
) -> Option<(NGAP_PDU, &'static str)> {
    match nas::gmm_message_type(&nas_msg) {
        Some(Nas5gmmMessageType::AuthenticationFailure) => {
            on_authentication_failure(ues, amf_auth, amf_ue_id, &nas_msg).await
        }
        Some(Nas5gmmMessageType::IdentityResponse) => {
            // The UE answers the Identity Request we sent from `on_initial_ue`
            // (unresolvable mobile identity, e.g. an unknown GUTI): resolve the
            // SUPI and resume the paused registration at authentication.
            let (state, ran_ue_id) = {
                let ctx = ues.get(&amf_ue_id)?;
                (ctx.state, ctx.ran_ue_id)
            };
            if state != RegState::IdentityRequested {
                warn!("UE {amf_ue_id}: unexpected Identity Response in state {state:?}");
                return None;
            }
            let Some(supi) = nas::supi_from_identity_response(&nas_msg) else {
                warn!("UE {amf_ue_id}: Identity Response without a usable SUCI");
                return None;
            };
            info!("UE {amf_ue_id} identified via Identity Response ({supi}); starting authentication");
            match amf_auth.begin(&supi).await {
                Ok((pending, nas_req)) => {
                    // Assign the registration area now that the SUPI is known — the
                    // Identity-Request path skips `on_initial_ue`'s identified branch,
                    // so without this the accept would carry no 5GS TAI list (paging
                    // would have nothing to scope to).
                    let registration_area = registration_area_for(
                        ues.get(&amf_ue_id).and_then(|c| c.tac),
                        dereg_tx,
                    );
                    let ctx = ues.get_mut(&amf_ue_id)?;
                    ctx.suci = Some(supi.clone());
                    ctx.auth = Some(pending);
                    ctx.state = RegState::Authenticating;
                    ctx.registration_area = registration_area;
                    // Reachable from the SBI callback surface from now on.
                    UE_DIRECTORY.lock().unwrap().insert(supi, (amf_ue_id, dereg_tx.clone()));
                    Some((
                        ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, nas_req),
                        "DownlinkNASTransport (AuthenticationRequest)",
                    ))
                }
                Err(e) => {
                    warn!("UE {amf_ue_id}: authentication start failed: {e}");
                    None
                }
            }
        }
        Some(Nas5gmmMessageType::DeregistrationAcceptToUe) => {
            let ctx = ues.get(&amf_ue_id)?;
            if ctx.dereg_attempts.is_none() {
                warn!("UE {amf_ue_id}: unexpected Deregistration Accept (no procedure running)");
                return None;
            }
            let ran_ue_id = ctx.ran_ue_id;
            info!("UE {amf_ue_id}: Deregistration Accept — network-initiated deregistration complete");
            spawn_am_policy_delete(ctx.am_policy.clone());
            if let Some(supi) = ctx.suci.clone() {
                UE_DIRECTORY.lock().unwrap().remove(&supi);
                // The subscription is gone — its GUTI must not resolve again.
                GUTI_DIRECTORY.lock().unwrap().retain(|_, s| s != &supi);
                spawn_sdm_unsubscribe(supi.clone());
                spawn_uecm_purge(supi);
            }
            ues.remove(&amf_ue_id);
            Some((
                ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::DEREGISTER),
                "UEContextReleaseCommand",
            ))
        }
        Some(Nas5gmmMessageType::RegistrationComplete) => {
            let ctx = ues.get_mut(&amf_ue_id)?;
            ctx.state = RegState::Registered;
            // Record this AMF as the serving AMF (UECM) — the UDR delivers
            // subscription withdrawals to our callback from now on — and subscribe to
            // Nudm_SDM subscriber-data changes so a mid-registration change refreshes
            // our cached view.
            if let Some(supi) = ctx.suci.clone() {
                spawn_uecm_register(supi.clone());
                spawn_sdm_subscribe(supi);
            }
            info!(
                "UE {amf_ue_id} REGISTERED (suci={:?}, ran_ue_id={}, state={:?})",
                ctx.suci, ctx.ran_ue_id, ctx.state
            );
            // Follow registration with a Configuration Update Command — a compliant UE
            // waits for it before initiating a PDU session (matches free5GC AMF behaviour).
            let ran_ue_id = ctx.ran_ue_id;
            let sec = ctx.sec.as_mut()?;
            let cuc = sec.protect(&nas::configuration_update_command(), nas::sht::INTEGRITY_CIPHERED, 1);
            Some((
                ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, cuc),
                "DownlinkNASTransport (ConfigurationUpdateCommand)",
            ))
        }
        Some(Nas5gmmMessageType::ConfigurationUpdateComplete) => {
            // The UE acknowledged a Configuration Update Command (TS 24.501 §8.2.20):
            // clear the outstanding command so T3555 stops retransmitting (a pending
            // expiry then no-ops). A re-registration it was asked for arrives as its
            // own Registration Request.
            let stopped =
                ues.get_mut(&amf_ue_id).is_some_and(|c| c.pending_config_update.take().is_some());
            if stopped {
                info!("UE {amf_ue_id}: Configuration Update Complete — T3555 stopped");
            } else {
                info!("UE {amf_ue_id}: Configuration Update Complete");
            }
            None
        }
        Some(Nas5gmmMessageType::UlNasTransport) => {
            // A UE PDU session request: CreateSMContext at the SMF (N4 establishment),
            // then send the N2 PDU Session Resource Setup to the gNB with the UPF's N3
            // F-TEID. The N1 SM container is opaque to the AMF (TS 29.502 multipart later).
            let Some((psi, container)) = nas::sm_container_from_ul_nas_transport(&nas_msg) else {
                warn!("UE {amf_ue_id}: UL NAS Transport without an SM container");
                return None;
            };
            // A PDU Session Release Complete (0xD4) is the UE's final ack to a
            // network-initiated release: finalise the session at the SMF now (strict
            // TS 23.502 §4.3.4 ordering — N4 delete follows the complete). It must
            // not fall through to the establishment (CreateSMContext) path.
            if nas::is_pdu_session_release_complete(&container) {
                info!("UE {amf_ue_id}: PDU Session Release Complete for psi {psi}");
                finalize_release(ues, amf_smf, amf_ue_id, psi).await;
                return None;
            }
            let Some((supi, ran_ue_id)) =
                ues.get(&amf_ue_id).and_then(|c| Some((c.suci.clone()?, c.ran_ue_id)))
            else {
                warn!("UE {amf_ue_id}: UL NAS Transport before SUPI is known");
                return None;
            };
            // The UE's requested DNN (0x25 IE) and S-NSSAI (0x22 IE) ride in the
            // transport; omitted → network default DNN / subscribed default slice.
            // The SMF authorizes the (slice, DNN) pair against the subscription
            // (design/27, design/31) — a denied pair fails CreateSMContext.
            let dnn = nas::requested_dnn_from_ul_nas_transport(&nas_msg)
                .unwrap_or_else(|| DEFAULT_DNN.to_string());
            let snssai = nas::requested_snssai_from_ul_nas_transport(&nas_msg);
            let pti = container.get(2).copied().unwrap_or(1);

            // Slice admission (TS 23.501): a requested slice outside the allowed NSSAI
            // granted at registration is rejected locally — no SMF round trip. An
            // unknown allowed NSSAI (am-data fetch failed) falls through to the SMF's
            // subscription check (fail-open).
            let outside_allowed = match (
                snssai,
                ues.get(&amf_ue_id).and_then(|c| c.allowed_nssai.as_deref()),
            ) {
                (Some(requested), Some(allowed)) => !allowed.contains(&requested),
                _ => false,
            };
            if outside_allowed {
                warn!(
                    "UE {amf_ue_id}: PDU session {psi} requested slice {snssai:?} outside the \
                     allowed NSSAI; sending Establishment Reject (5GSM cause #70)"
                );
                let reject = nas::pdu_session_establishment_reject(
                    psi,
                    pti,
                    nas::sm_cause::MISSING_OR_UNKNOWN_DNN_IN_SLICE,
                    Some(nas::GprsTimer3::from_secs(REJECT_BACKOFF_SECS)),
                );
                let dl = nas::dl_nas_transport_sm(psi, reject);
                let Some(sec) = ues.get_mut(&amf_ue_id).and_then(|c| c.sec.as_mut()) else {
                    warn!("UE {amf_ue_id}: cannot NAS-protect the reject (no security context)");
                    return None;
                };
                let protected = sec.protect(&dl, nas::sht::INTEGRITY_CIPHERED, 1);
                return Some((
                    ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, protected),
                    "DownlinkNASTransport (PDUSessionEstablishmentReject)",
                ));
            }

            let smf_base = match amf_smf.select_smf(snssai, &dnn).await {
                Ok(base) => base,
                Err(e) => {
                    // No SMF serves this (slice, DNN): reject the session (#27, or
                    // #70 when the UE named a slice) with a back-off, like the SMF's
                    // own refusal.
                    let cause = if snssai.is_some() {
                        nas::sm_cause::MISSING_OR_UNKNOWN_DNN_IN_SLICE
                    } else {
                        nas::sm_cause::MISSING_OR_UNKNOWN_DNN
                    };
                    warn!(
                        "UE {amf_ue_id}: PDU session {psi} SMF selection failed ({e}); \
                         sending Establishment Reject (5GSM cause #{cause})"
                    );
                    let reject = nas::pdu_session_establishment_reject(
                        psi,
                        pti,
                        cause,
                        Some(nas::GprsTimer3::from_secs(REJECT_BACKOFF_SECS)),
                    );
                    let dl = nas::dl_nas_transport_sm(psi, reject);
                    let sec = ues.get_mut(&amf_ue_id).and_then(|c| c.sec.as_mut())?;
                    let protected = sec.protect(&dl, nas::sht::INTEGRITY_CIPHERED, 1);
                    return Some((
                        ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, protected),
                        "DownlinkNASTransport (PDUSessionEstablishmentReject)",
                    ));
                }
            };
            match amf_smf.create_sm_context(&smf_base, &supi, psi, &dnn, snssai).await {
                Ok(created) => {
                    // Build the N1 PDU Session Establishment Accept (UE IP from the SMF,
                    // echoing the request's PTI) and NAS-protect a DL NAS Transport carrying
                    // it — the gNB relays that to the UE. The N2 SM info carries the UPF F-TEID.
                    // S-NSSAI and session AMBR come from the subscriber's UDR sm-data
                    // (looked up by the SMF during CreateSMContext); the DNN echoes
                    // the UE's authorized request.
                    // Per-flow QoS (5QI/ARP/GBR) from the SMF: the N1 accept lists
                    // the flows' descriptions; the N2 transfer carries the flows.
                    // Fall back to the single default non-GBR flow if the SMF
                    // supplied none (older SMF / no QoS profile).
                    let ngap_flows: Vec<ngap::QosFlow> = if created.ngap_flows.is_empty() {
                        vec![ngap::QosFlow::default_non_gbr()]
                    } else {
                        created.ngap_flows.clone()
                    };
                    let accept = nas::pdu_session_establishment_accept(
                        psi,
                        pti,
                        created.ue_ip,
                        &dnn,
                        created.snssai_sst,
                        created.snssai_sd,
                        created.ambr,
                        &created.nas_flows,
                    );
                    let dl = nas::dl_nas_transport_sm(psi, accept);
                    let Some(ctx) = ues.get_mut(&amf_ue_id) else { return None };
                    ctx.sm_refs.insert(psi, (created.sm_ref, smf_base));
                    ctx.session_snssai.insert(psi, (created.snssai_sst, created.snssai_sd));
                    let (ambr_dl, ambr_ul) = ctx.ue_ambr.unwrap_or(DEFAULT_UE_AMBR_BPS);
                    let Some(sec) = ctx.sec.as_mut() else {
                        warn!("UE {amf_ue_id}: PDU session before NAS security is established");
                        return None;
                    };
                    let nas_accept = sec.protect(&dl, nas::sht::INTEGRITY_CIPHERED, 1);
                    let setup = ngap::pdu_session_resource_setup_request(
                        amf_ue_id,
                        ran_ue_id,
                        psi,
                        &ngap_flows,
                        created.up_n3_teid,
                        created.up_n3_addr,
                        ambr_dl,
                        ambr_ul,
                        nas_accept,
                    );
                    info!(
                        "UE {amf_ue_id}: PDU session {psi} SM context created (UE IP {}); sending N2 setup",
                        created.ue_ip
                    );
                    Some((setup, "PDUSessionResourceSetupRequest"))
                }
                Err(e) => {
                    // Answer the UE with a 5GSM PDU Session Establishment Reject instead
                    // of silence: subscription refusal → cause #27 (missing or unknown
                    // DNN), or #70 (missing or unknown DNN in a slice) when the UE
                    // requested a specific S-NSSAI — both with a T3396 back-off
                    // (retrying can't help until provisioning changes); anything else
                    // → #31 (request rejected, unspecified), no back-off — a transient
                    // failure may clear. Plain DL NAS Transport — no N2 setup, since
                    // no session exists.
                    let (cause, backoff) = match &e {
                        pdu_session::CreateSmError::Forbidden => (
                            if snssai.is_some() {
                                nas::sm_cause::MISSING_OR_UNKNOWN_DNN_IN_SLICE
                            } else {
                                nas::sm_cause::MISSING_OR_UNKNOWN_DNN
                            },
                            Some(nas::GprsTimer3::from_secs(REJECT_BACKOFF_SECS)),
                        ),
                        // GFBR admission control refused it — #26 insufficient
                        // resources, no back-off (capacity may free up).
                        pdu_session::CreateSmError::InsufficientResources => {
                            (nas::sm_cause::INSUFFICIENT_RESOURCES, None)
                        }
                        pdu_session::CreateSmError::Other(_) => {
                            (nas::sm_cause::REQUEST_REJECTED_UNSPECIFIED, None)
                        }
                    };
                    warn!(
                        "UE {amf_ue_id}: PDU session {psi} (dnn={dnn}) CreateSMContext failed: {e}; \
                         sending Establishment Reject (5GSM cause #{cause}, backoff={backoff:?})"
                    );
                    let reject = nas::pdu_session_establishment_reject(psi, pti, cause, backoff);
                    let dl = nas::dl_nas_transport_sm(psi, reject);
                    let Some(sec) = ues.get_mut(&amf_ue_id).and_then(|c| c.sec.as_mut()) else {
                        warn!("UE {amf_ue_id}: cannot NAS-protect the reject (no security context)");
                        return None;
                    };
                    let protected = sec.protect(&dl, nas::sht::INTEGRITY_CIPHERED, 1);
                    Some((
                        ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, protected),
                        "DownlinkNASTransport (PDUSessionEstablishmentReject)",
                    ))
                }
            }
        }
        _ => {
            info!("UE {amf_ue_id}: uplink NAS {nas_msg}");
            None
        }
    }
}

/// Confirm the UE's RES* with the AUSF, derive the NAS security context, and return
/// the protected Security Mode Command downlink.
/// Handle a UE **Authentication Failure** (TS 24.501 §5.4.1.3.7). On a *synch
/// failure* (#21) the AMF resynchronises the SQN once — re-running
/// Nausf_UEAuthentication with the UE's AUTS (which flows AUSF→UDM→UDR/ARPF) and
/// sending the UE the fresh challenge. A second synch failure, or any other
/// cause, aborts the procedure (the UE context is dropped; the gNB releases it).
async fn on_authentication_failure(
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_ue_id: u64,
    nas_msg: &Nas5gsMessage,
) -> Option<(NGAP_PDU, &'static str)> {
    let Some((cause, auts)) = nas::authentication_failure_info(nas_msg) else {
        return None;
    };
    let ran_ue_id = ues.get(&amf_ue_id)?.ran_ue_id;

    // Only a synch failure with an AUTS is recoverable, and only once.
    let recoverable = cause == nas::GMM_CAUSE_SYNCH_FAILURE
        && auts.is_some()
        && !ues.get(&amf_ue_id)?.resync_attempted;
    if !recoverable {
        warn!("UE {amf_ue_id}: Authentication Failure (5GMM cause {cause:#x}) — aborting registration");
        ues.remove(&amf_ue_id);
        return Some((
            ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::NORMAL_RELEASE),
            "UEContextReleaseCommand",
        ));
    }

    // Re-authenticate with the AUTS: the AUSF/UDM adopt the UE's SQN and mint a
    // fresh challenge on the same AUSF the first attempt used.
    let pending_supi = {
        let ctx = ues.get(&amf_ue_id)?;
        ctx.auth.clone().zip(ctx.suci.clone())
    };
    let Some((pending, supi)) = pending_supi else {
        warn!("UE {amf_ue_id}: synch failure with no pending authentication — aborting");
        ues.remove(&amf_ue_id);
        return Some((
            ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::NORMAL_RELEASE),
            "UEContextReleaseCommand",
        ));
    };
    info!("UE {amf_ue_id}: synch failure — resynchronising SQN and re-challenging");
    match amf_auth.resync(&pending, &supi, &auts.unwrap()).await {
        Ok((fresh, nas_req)) => {
            let ctx = ues.get_mut(&amf_ue_id)?;
            ctx.auth = Some(fresh);
            ctx.resync_attempted = true;
            Some((
                ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, nas_req),
                "DownlinkNASTransport (AuthenticationRequest, resync)",
            ))
        }
        Err(e) => {
            warn!("UE {amf_ue_id}: resynchronisation failed: {e} — aborting registration");
            ues.remove(&amf_ue_id);
            Some((
                ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::NORMAL_RELEASE),
                "UEContextReleaseCommand",
            ))
        }
    }
}

/// On an **Authentication Response**: confirm RES* at the AUSF and either continue
/// to the Security Mode Command (success) or, when authentication is **not accepted**
/// (RES* mismatch), send an **Authentication Reject** and release the UE context
/// (TS 24.501 §5.4.1.3.7) — dropping the UE from the AMF. An internal error after a
/// successful confirm (missing K_SEAF/SUPI, no common integrity algorithm) is not an
/// "authentication not accepted", so it is a silent drop rather than a reject.
async fn complete_authentication(
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_ue_id: u64,
    nas_msg: &Nas5gsMessage,
) -> Vec<(NGAP_PDU, &'static str)> {
    let Some(pending) = ues.get_mut(&amf_ue_id).and_then(|c| c.auth.take()) else {
        warn!("UE {amf_ue_id}: Authentication Response with no pending authentication");
        return Vec::new();
    };
    // A confirm error or an explicit failure (or a response missing RES*) means
    // authentication was not accepted → Authentication Reject + release.
    let outcome = match nas::res_star_from_authentication_response(nas_msg) {
        Some(res_star) => amf_auth.finish(&pending, res_star).await.ok(),
        None => {
            warn!("UE {amf_ue_id}: Authentication Response without RES*");
            None
        }
    };
    let accepted = outcome.as_ref().is_some_and(|o| o.success);
    if !accepted {
        warn!("UE {amf_ue_id}: authentication not accepted (RES* rejected) — Authentication Reject + release");
        let ran_ue_id = ues.get(&amf_ue_id).map(|c| c.ran_ue_id).unwrap_or_default();
        if let Some(supi) = ues.get(&amf_ue_id).and_then(|c| c.suci.clone()) {
            UE_DIRECTORY.lock().unwrap().remove(&supi);
        }
        ues.remove(&amf_ue_id);
        return vec![
            (
                ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, nas::authentication_reject()),
                "DownlinkNASTransport (AuthenticationReject)",
            ),
            (
                ngap::ue_context_release_command(amf_ue_id, ran_ue_id, ngap::CauseNas::NORMAL_RELEASE),
                "UEContextReleaseCommand",
            ),
        ];
    }
    let (Some(kseaf), Some(supi)) = outcome.map(|o| (o.kseaf, o.supi)).unwrap_or((None, None)) else {
        warn!("UE {amf_ue_id}: authenticated but AUSF returned no K_SEAF/SUPI");
        return Vec::new();
    };

    info!("UE {amf_ue_id} authenticated ({supi}); establishing NAS security");
    // Negotiate NAS algorithms from the UE's advertised capabilities (falling back
    // to the AMF default if the UE didn't send them). The capabilities are also
    // replayed in the Security Mode Command so the UE can detect a bidding-down.
    let ue_sec_cap = ues
        .get(&amf_ue_id)
        .and_then(|c| c.replayed_ue_sec_cap)
        .unwrap_or(UE_SEC_CAP);
    let Some((sec, smc_bytes, _nea, _nia, kamf)) = establish_security(&kseaf, &supi, ue_sec_cap)
    else {
        warn!("UE {amf_ue_id}: cannot establish NAS security (no common integrity algorithm?)");
        return Vec::new();
    };
    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return Vec::new();
    };
    ctx.sec = Some(sec);
    // K_AMF is retained to derive K_gNB for the Initial Context Setup's Security
    // Key IE (TS 33.501 Annex A.9).
    ctx.kamf = Some(kamf);
    ctx.state = RegState::SecurityMode;
    let ran_ue_id = ctx.ran_ue_id;
    vec![(
        ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, smc_bytes),
        "DownlinkNASTransport (SecurityModeCommand)",
    )]
}

/// Negotiate NAS algorithms from `ue_sec_cap`, derive K_AMF + the NAS keys for the
/// selected algorithms, and build the protected Security Mode Command (which
/// announces the selection and replays the UE's capabilities for its bidding-down
/// check). `None` when the UE supports no acceptable **integrity** algorithm
/// (encryption falls back to NEA0/null). The NAS keys are algorithm-bound
/// (TS 33.501 Annex A.8), so the UE derives matching keys from the announced
/// algorithms.
fn establish_security(
    kseaf_hex: &str,
    supi: &str,
    ue_sec_cap: [u8; 2],
) -> Option<(nas::NasSecurityContext, Vec<u8>, u8, u8, [u8; 32])> {
    let nea = select_algo(ue_sec_cap[0], &NEA_PRIORITY)?;
    let nia = select_algo(ue_sec_cap[1], &NIA_PRIORITY)?;
    let kseaf: [u8; 32] = hex::decode(kseaf_hex).ok()?.try_into().ok()?;
    let kamf = aka::kamf(&kseaf, supi, &ABBA);
    let keys = aka::nas_keys(&kamf, nea, nia);
    let mut sec = nas::NasSecurityContext::new(keys.knas_int, keys.knas_enc, nia, nea);
    let smc = nas::security_mode_command(nea, nia, NGKSI, &ue_sec_cap);
    let bytes = sec.protect(&smc, nas::sht::INTEGRITY_NEW_CONTEXT, 1);
    info!(supi = %supi, "NAS security: selected NEA{nea} / NIA{nia}");
    Some((sec, bytes, nea, nia, kamf))
}

/// On Security Mode Complete, fetch the subscriber's am-data, intersect it with
/// the UE's requested NSSAI, and answer: a **Registration Accept** (5G-GUTI,
/// allowed + rejected NSSAIs) — or, when the intersection is empty, a
/// **Registration Reject** with 5GMM cause #62 *no network slices available*
/// (TS 24.501 §5.5.1.2.8), releasing the UE context.
async fn on_security_mode_complete(
    ues: &mut HashMap<u64, UeContext>,
    amf_ue_id: u64,
    nrf_base: &str,
) -> Vec<(NGAP_PDU, &'static str)> {
    // Fetch before taking the mutable borrow (the fetch awaits).
    let Some(supi) = ues.get(&amf_ue_id).map(|c| c.suci.clone()) else {
        return Vec::new();
    };
    let (subscribed, ue_ambr) = match &supi {
        Some(supi) => fetch_am_data(nrf_base, supi).await,
        None => (None, None),
    };
    // Create the AM policy association at the PCF (Npcf_AMPolicyControl); its
    // UE-AMBR (when present) overrides the subscribed one at the gNB. Best-effort:
    // no PCF ⇒ subscribed policy stands.
    let am = match &supi {
        Some(supi) => create_am_policy(nrf_base, supi, PLMN_MCC, PLMN_MNC).await,
        None => None,
    };

    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return Vec::new();
    };
    // AM policy: record the PCF UE-AMBR override (it takes precedence over the
    // subscribed value) and store the association for deletion at deregistration.
    // Fail-open on the subscribed source: an unreachable am-data fetch (`None`) keeps
    // a previously-known subscribed value rather than clobbering it.
    ctx.subscribed_ue_ambr = ue_ambr.or(ctx.subscribed_ue_ambr);
    if let Some((pcf_base, assoc_id, policy)) = am {
        if let Some(pcf_ambr) = &policy.ue_ambr {
            if let (Some(dl), Some(ul)) =
                (bitrate_to_bps(&pcf_ambr.downlink), bitrate_to_bps(&pcf_ambr.uplink))
            {
                ctx.pcf_ue_ambr = Some((dl, ul));
                info!(
                    "UE {amf_ue_id}: AM policy applied — UE-AMBR {}/{} (dl/ul), RFSP {:?}",
                    pcf_ambr.downlink, pcf_ambr.uplink, policy.rfsp
                );
            }
        }
        ctx.rfsp = policy.rfsp;
        ctx.area_restriction = policy.serv_area_res.as_ref().and_then(area_restriction_tacs);
        if let Some((allowed, not_allowed)) = &ctx.area_restriction {
            info!(
                "UE {amf_ue_id}: AM policy service area restriction — allowed TACs {allowed:?}, non-allowed {not_allowed:?}"
            );
        }
        ctx.am_policy = Some((pcf_base, assoc_id));
    }
    // Effective UE-AMBR = PCF override, else subscribed (fail-open: both `None` when
    // subscription/PCF are unreachable → a default is used at signalling).
    ctx.recompute_ue_ambr();
    let ran_ue_id = ctx.ran_ue_id;
    let tmsi = amf_ue_id as u32;
    // Remember the assigned 5G-TMSI as this UE's persistent identity (a Service
    // Request presents it; the retained-context store is keyed by it).
    ctx.guti_tmsi = Some(tmsi);
    // Fail-open when the subscription is unreachable: no NSSAI IEs, and slice
    // admission falls back to the SMF's check.
    let (allowed, rejected) = match &subscribed {
        Some(subscribed) => compute_nssai(&ctx.requested_nssai, subscribed),
        None => (Vec::new(), Vec::new()),
    };

    // Nothing the UE requested is subscribed → the registration cannot serve any
    // slice: Registration Reject #62, then a UE Context Release Command so the
    // gNB drops its side too; the AMF context is released here.
    if subscribed.is_some() && allowed.is_empty() {
        let Some(sec) = ctx.sec.as_mut() else {
            return Vec::new();
        };
        let reject = nas::registration_reject(
            nas::mm_cause::NO_NETWORK_SLICES_AVAILABLE,
            &rejected,
            Some(nas::GprsTimer2::from_secs(REG_REJECT_BACKOFF_SECS)),
        );
        let bytes = sec.protect(&reject, nas::sht::INTEGRITY_CIPHERED, 1);
        warn!(
            "UE {amf_ue_id}: no requested slice is subscribed ({rejected:?}); sending \
             Registration Reject (5GMM cause #62) + UE Context Release Command"
        );
        if let Some(supi) = supi {
            UE_DIRECTORY.lock().unwrap().remove(&supi);
        }
        ues.remove(&amf_ue_id);
        return vec![
            (
                ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, bytes),
                "DownlinkNASTransport (RegistrationReject)",
            ),
            (
                ngap::ue_context_release_command(
                    amf_ue_id,
                    ran_ue_id,
                    ngap::CauseNas::NORMAL_RELEASE,
                ),
                "UEContextReleaseCommand",
            ),
        ];
    }

    ctx.allowed_nssai = subscribed.is_some().then(|| allowed.clone());
    let registration_area = ctx.registration_area.clone();
    // Everything the Initial Context Setup carries alongside the accept — copied
    // before the mutable `sec` borrow.
    let kamf = ctx.kamf;
    let ue_sec_cap = ctx.replayed_ue_sec_cap.unwrap_or(UE_SEC_CAP);
    let (rfsp, ue_ambr) = (ctx.rfsp, ctx.ue_ambr);
    let area_restriction = ctx.area_restriction.clone();
    let Some(sec) = ctx.sec.as_mut() else {
        return Vec::new();
    };
    // Record the assigned 5G-GUTI so a returning UE can re-register with it; a
    // fresh GUTI supersedes any earlier one held by the same SUPI.
    if let Some(supi) = &supi {
        let mut gutis = GUTI_DIRECTORY.lock().unwrap();
        gutis.retain(|_, s| s != supi);
        gutis.insert(tmsi, supi.clone());
    }
    // The Registration Accept assigns the GUTI, the granted slices, T3512, and the
    // registration area (5GS TAI list) paging is scoped to.
    let accept = nas::registration_accept(
        PLMN_MCC,
        PLMN_MNC,
        tmsi,
        &allowed,
        &rejected,
        T3512_SECS,
        &registration_area,
        None, // initial registration — no PDU sessions to reconcile yet
    );
    // K_gNB from K_AMF and the Security Mode Complete's uplink NAS COUNT
    // (TS 33.501 Annex A.9) — `unprotect` has already advanced ul_count past it.
    let kgnb = kamf.map(|k| aka::kgnb(&k, sec.ul_count.wrapping_sub(1)));
    let bytes = sec.protect(&accept, nas::sht::INTEGRITY_CIPHERED, 1);

    // Establish the UE context at the gNB with an **Initial Context Setup Request**
    // (TS 38.413 §8.3.1): GUAMI, allowed NSSAI, the UE's security capabilities,
    // K_gNB, the AM policy outputs (UE-AMBR / RFSP / mobility restriction), and the
    // Registration Accept as its NAS-PDU — one procedure instead of a plain
    // DownlinkNASTransport plus a trailing UE Context Modification.
    let Some(security_key) = kgnb else {
        // No K_AMF retained (unreachable in practice: it is stored with `sec`) —
        // degrade to the plain NAS transport rather than hand the RAN a bogus key.
        warn!("UE {amf_ue_id}: no K_AMF to derive K_gNB — sending the accept without a context setup");
        return vec![(
            ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, bytes),
            "DownlinkNASTransport (RegistrationAccept)",
        )];
    };
    info!(
        "UE {amf_ue_id}: SecurityModeComplete — Initial Context Setup with the Registration Accept \
         (allowed NSSAI: {allowed:?}, rejected: {rejected:?}, RFSP {rfsp:?}, UE-AMBR {ue_ambr:?})"
    );
    // Seed the NH chain: the delivered K_gNB is the sync input for the first NH
    // (NCC 0 → the first path switch hands out {NH₁, NCC 1}).
    ctx.nh_chain = Some((security_key, 0));
    let (allowed_tacs, not_allowed_tacs) = area_restriction.unwrap_or_default();
    let ic = ngap::InitialContext {
        allowed_nssai: allowed.clone(),
        ue_sec_cap,
        security_key,
        ue_ambr,
        rfsp,
        area_restriction: (!allowed_tacs.is_empty() || !not_allowed_tacs.is_empty())
            .then_some((allowed_tacs, not_allowed_tacs)),
        pdu_sessions: Vec::new(), // no PDU sessions exist yet at initial registration
        nas: bytes,
    };
    vec![(
        ngap::initial_context_setup_request(amf_ue_id, ran_ue_id, PLMN_MCC, PLMN_MNC, &ic),
        "InitialContextSetupRequest (RegistrationAccept)",
    )]
}

/// Intersect the UE's requested NSSAI with the subscribed one (TS 23.501 slice
/// admission, simplified): allowed = requested ∩ subscribed, rejected =
/// requested \ subscribed. A UE that requested nothing is granted the
/// subscribed defaults and nothing is rejected.
fn compute_nssai(
    requested: &[(u8, Option<[u8; 3]>)],
    subscribed: &[(u8, Option<[u8; 3]>)],
) -> (Vec<(u8, Option<[u8; 3]>)>, Vec<(u8, Option<[u8; 3]>)>) {
    if requested.is_empty() {
        return (subscribed.to_vec(), Vec::new());
    }
    requested.iter().partition(|slice| subscribed.contains(slice))
}

/// A 6-hex-digit tracking area code ("000001") to its 3 octets. `None` if malformed.
fn parse_tac(s: &str) -> Option<[u8; 3]> {
    if s.len() != 6 {
        return None;
    }
    let v = u32::from_str_radix(s, 16).ok()?;
    Some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

/// Split a PCF service area restriction into `(allowed_tacs, non_allowed_tacs)` for
/// the NGAP Mobility Restriction List. `ALLOWED_AREAS` fills the allowed list,
/// anything else (e.g. `NOT_ALLOWED_AREAS`) the non-allowed list. Malformed TACs are
/// dropped; the result is `None` only when nothing usable remains.
fn area_restriction_tacs(
    sar: &sbi_core::npcf_am::ServiceAreaRestriction,
) -> Option<(Vec<[u8; 3]>, Vec<[u8; 3]>)> {
    let tacs: Vec<[u8; 3]> = sar.tacs.iter().filter_map(|t| parse_tac(t)).collect();
    if tacs.is_empty() {
        return None;
    }
    if sar.restriction_type == "ALLOWED_AREAS" {
        Some((tacs, Vec::new()))
    } else {
        Some((Vec::new(), tacs))
    }
}

/// Convert a TS 29.571 `BitRate` string ("2 Gbps") to bits/sec (integer values).
fn bitrate_to_bps(s: &str) -> Option<u64> {
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

/// Create an AM policy association at the NRF-discovered PCF
/// (Npcf_AMPolicyControl, TS 29.507). Returns `(pcf_base, assoc_id, policy)` — the
/// PCF's AM policy (RFSP + UE-AMBR). `None` (best-effort) when no PCF is reachable
/// or the call fails, so registration proceeds with the subscribed policy.
async fn create_am_policy(
    nrf_base: &str,
    supi: &str,
    mcc: &str,
    mnc: &str,
) -> Option<(String, String, sbi_core::npcf_am::PolicyAssociation)> {
    let pcf = discover_nf(nrf_base, "PCF").await.ok()?;
    let req = sbi_core::npcf_am::PolicyAssociationRequest {
        supi: supi.to_string(),
        serving_plmn: Some(format!("{mcc}{mnc}")),
        // Where the PCF pushes Npcf_AMPolicyControl_UpdateNotify (the AMF's callback).
        notification_uri: Some(format!(
            "{}://{}:{SBI_PORT}/npcf-callback/v1/am-policy-notify/{supi}",
            sbi_core::sbi_scheme(),
            &*ADVERTISE_ADDR
        )),
    };
    match sbi_core::npcf_am::AmPolicyClient::new(pcf.clone()).create(&req).await {
        Ok(created) => Some((pcf, created.assoc_id, created.policy)),
        Err(e) => {
            debug!("AM policy association not created ({e}); using subscribed policy");
            None
        }
    }
}

/// Delete an AM policy association at the PCF (best-effort, off the path), called
/// when a UE's context is torn down at deregistration.
fn spawn_am_policy_delete(am_policy: Option<(String, String)>) {
    let Some((pcf_base, assoc_id)) = am_policy else {
        return;
    };
    tokio::spawn(async move {
        match sbi_core::npcf_am::AmPolicyClient::new(pcf_base).delete(&assoc_id).await {
            Ok(()) => info!("deleted AM policy association {assoc_id}"),
            Err(e) => warn!("AM policy association delete failed: {e}"),
        }
    });
}

/// Fetch the subscriber's am-data via the NRF-discovered UDM (Nudm_SDM) and
/// extract what the AMF needs at registration: the subscribed default S-NSSAIs
/// (`nssai.defaultSingleNssais`) and the UE-AMBR (`subscribedUeAmbr`). The NSSAI
/// half keeps the fail-open contract — `None` (the first element) means "no
/// am-data / no default NSSAI", so slice admission falls back to the SMF check;
/// the UE-AMBR is independent (`None` → the AMF sends [`DEFAULT_UE_AMBR_BPS`]).
async fn fetch_am_data(
    nrf_base: &str,
    supi: &str,
) -> (Option<Vec<(u8, Option<[u8; 3]>)>>, Option<(u64, u64)>) {
    let Ok(udm) = discover_nf(nrf_base, "UDM").await.map_err(|e| warn!("UDM discovery failed: {e}"))
    else {
        return (None, None);
    };
    let am = match sbi_core::nudm::NudmClient::new(udm).get_am_data(supi, &format!("{PLMN_MCC}{PLMN_MNC}")).await {
        Ok(Some(am)) => am,
        Ok(None) => return (None, None),
        Err(e) => {
            warn!("Nudm_SDM am-data fetch failed: {e}");
            return (None, None);
        }
    };
    let slices: Vec<(u8, Option<[u8; 3]>)> = am
        .pointer("/nssai/defaultSingleNssais")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let sst = u8::try_from(s.get("sst")?.as_u64()?).ok()?;
                    let sd = s
                        .get("sd")
                        .and_then(|v| v.as_str())
                        .and_then(|sd| hex::decode(sd).ok())
                        .and_then(|b| <[u8; 3]>::try_from(b).ok());
                    Some((sst, sd))
                })
                .collect()
        })
        .unwrap_or_default();
    let nssai = (!slices.is_empty()).then_some(slices);
    let ue_ambr = am.pointer("/subscribedUeAmbr").and_then(|a| {
        let dl = bitrate_to_bps(a.get("downlink")?.as_str()?)?;
        let ul = bitrate_to_bps(a.get("uplink")?.as_str()?)?;
        Some((dl, ul))
    });
    (nssai, ue_ambr)
}

/// Discover an NF's first service endpoint via the NRF.
async fn discover_nf(nrf_base: &str, nf_type: &str) -> Result<String, String> {
    let profile = sbi_core::nnrf::NrfClient::new(nrf_base.to_string())
        .discover(nf_type, "AMF")
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no {nf_type} registered with the NRF"))?;
    let endpoint = profile
        .nf_services
        .and_then(|s| s.into_iter().next())
        .and_then(|svc| svc.ip_end_points.into_iter().next())
        .ok_or("profile has no service endpoint")?;
    let ip = endpoint.ipv4_address.ok_or("endpoint missing IP")?;
    let port = endpoint.port.ok_or("endpoint missing port")?;
    Ok(format!("http://{ip}:{port}"))
}

/// How a Registration Request's mobile identity identifies the UE.
enum RegIdentity {
    /// A SUCI, deconcealed to the SUPI (null scheme, TS 33.501).
    Supi(String),
    /// A 5G-GUTI — the 5G-TMSI to resolve against [`GUTI_DIRECTORY`].
    GutiTmsi(u32),
    /// Another/unusable identity type — ask for the SUCI.
    Unknown,
}

/// From a decoded NAS RegistrationRequest, extract the identity the AMF needs
/// (SUCI→SUPI, or the 5G-GUTI's TMSI) plus the UE's advertised 5GS security
/// capabilities `[EA, IA]` (to replay in the Security Mode Command) and its
/// requested NSSAI — the latter two are captured even when the identity still
/// needs resolving. `None` if the message is not a RegistrationRequest.
fn registration_identity(
    msg: Nas5gsMessage,
) -> Option<(RegIdentity, Option<[u8; 2]>, Vec<(u8, Option<[u8; 3]>)>)> {
    let requested_nssai = nas::requested_nssai_from_registration_request(&msg);
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = msg else {
        return None;
    };
    let identity = if let Some(suci) = reg.fgs_mobile_identity.as_suci() {
        RegIdentity::Supi(nas::suci_to_supi(&suci))
    } else if let Some(guti) = reg.fgs_mobile_identity.as_guti() {
        RegIdentity::GutiTmsi(guti.tmsi)
    } else {
        RegIdentity::Unknown
    };
    let ue_sec_cap = reg
        .ue_security_capability
        .as_ref()
        .map(|c| [c.ea_byte(), c.ia_byte()]);
    Some((identity, ue_sec_cap, requested_nssai))
}

fn initial_ue_nas_pdu(msg: &InitialUEMessage) -> Option<&[u8]> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        InitialUEMessageProtocolIEs_EntryValue::Id_NAS_PDU(nas) => Some(nas.0.as_slice()),
        _ => None,
    })
}

fn initial_ue_ran_id(msg: &InitialUEMessage) -> Option<u32> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        InitialUEMessageProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(id) => Some(id.0),
        _ => None,
    })
}

fn uplink_nas_pdu(msg: &UplinkNASTransport) -> Option<&[u8]> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        UplinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(nas) => Some(nas.0.as_slice()),
        _ => None,
    })
}

fn uplink_amf_ue_id(msg: &UplinkNASTransport) -> Option<u64> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        UplinkNASTransportProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => Some(id.0),
        _ => None,
    })
}

/// APER-encode and send an NGAP PDU, logging success/failure under `label`.
async fn send_or_log(conn: &ConnectedSocket, pdu: &NGAP_PDU, label: &str) {
    match send_ngap(conn, pdu).await {
        Ok(()) => info!("sent {label}"),
        Err(e) => error!("send {label} failed: {e:#}"),
    }
}

/// APER-encode an NGAP PDU and send it on the association with the NGAP PPID.
async fn send_ngap(conn: &ConnectedSocket, pdu: &NGAP_PDU) -> anyhow::Result<()> {
    let payload = pdu
        .encode()
        .map_err(|e| anyhow::anyhow!("NGAP encode failed: {e:?}"))?;
    conn.sctp_send(SendData {
        payload,
        snd_info: Some(SendInfo {
            ppid: NGAP_PPID,
            ..Default::default()
        }),
    })
    .await
    .context("sctp_send")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // The test UE supports/derives keys with 128-NEA2 / 128-NIA2 — what the AMF
    // negotiates from the default UE_SEC_CAP (EA2/IA2 are the top-priority bits set).
    const NAS_NEA: u8 = 2;
    const NAS_NIA: u8 = 2;

    const REG_REQUEST_HEX: &str = "7e004179000d0199f9070000000000000010022e08a020000000000000";

    fn registration_request() -> Vec<u8> {
        hex::decode(REG_REQUEST_HEX).unwrap()
    }

    #[test]
    fn bitrate_to_bps_parsing() {
        assert_eq!(bitrate_to_bps("2 Gbps"), Some(2_000_000_000));
        assert_eq!(bitrate_to_bps("500 Mbps"), Some(500_000_000));
        assert_eq!(bitrate_to_bps("1 Tbps"), Some(1_000_000_000_000));
        assert_eq!(bitrate_to_bps("100 bps"), Some(100));
        assert_eq!(bitrate_to_bps("fast"), None);
        assert_eq!(bitrate_to_bps("2Gbps"), None, "needs a space");
    }

    #[test]
    fn nssai_intersection() {
        let sub: Vec<(u8, Option<[u8; 3]>)> = vec![(1, Some([1, 2, 3])), (2, None)];
        // No request → the subscribed defaults, nothing rejected.
        assert_eq!(compute_nssai(&[], &sub), (sub.clone(), vec![]));
        // Partial overlap → intersection allowed, the rest rejected.
        let req = vec![(1, Some([1, 2, 3])), (7, None)];
        assert_eq!(compute_nssai(&req, &sub), (vec![(1, Some([1, 2, 3]))], vec![(7, None)]));
        // No overlap → everything rejected, nothing allowed.
        let req = vec![(9, None)];
        assert_eq!(compute_nssai(&req, &sub), (vec![], vec![(9, None)]));
    }

    /// Extract the NAS PDU from a built NGAP DownlinkNASTransport.
    fn downlink_nas_pdu(pdu: &NGAP_PDU) -> Option<Vec<u8>> {
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
            return None;
        };
        let InitiatingMessageValue::Id_DownlinkNASTransport(msg) = value else {
            return None;
        };
        msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
            ngap::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(nas) => Some(nas.0.clone()),
            _ => None,
        })
    }

    /// Deregistration releases the SM context at the SMF, answers with an Accept
    /// (unless switch-off), sends the UE Context Release Command, and drops the
    /// AMF context.
    #[tokio::test]
    async fn deregistration_releases_session_and_contexts() {
        use axum::http::StatusCode;
        use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, NrfClient};
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        // Mock SMF counting /release hits, registered with an ephemeral NRF.
        static RELEASES: AtomicUsize = AtomicUsize::new(0);
        async fn mock_release() -> StatusCode {
            RELEASES.fetch_add(1, AtomicOrdering::Relaxed);
            StatusCode::NO_CONTENT
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/release",
            axum::routing::post(mock_release),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });

        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let store = sbi_core::nnrf::NrfStore::default();
        tokio::spawn(async move { sbi_core::run_on(nrf_l, sbi_core::nnrf::router(store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");
        let mut profile = NfProfile::new("smf-mock", "SMF", smf_addr.ip().to_string());
        profile.nf_services = Some(vec![NfService {
            service_instance_id: "nsmf-pdusession-1".into(),
            service_name: "nsmf-pdusession".into(),
            scheme: "http".into(),
            ip_end_points: vec![IpEndPoint {
                ipv4_address: Some(smf_addr.ip().to_string()),
                port: Some(smf_addr.port()),
            }],
        }]);
        NrfClient::new(nrf_base.clone()).register(&profile).await.unwrap();
        let amf_smf = pdu_session::AmfSmf::new(nrf_base, "999", "70");

        // A registered, secured UE with TWO active PDU sessions (psi 5 and 6).
        let (ki, ke) = ([0x11u8; 16], [0x22u8; 16]);
        let mut ctx = UeContext::new(7, RegState::Registered, Some("imsi-999700000000001".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        let smf_base = format!("http://{smf_addr}");
        ctx.sm_refs.insert(5, ("ctx-5".into(), smf_base.clone()));
        ctx.sm_refs.insert(6, ("ctx-6".into(), smf_base));
        let mut ues = HashMap::new();
        ues.insert(1u64, ctx);

        // Normal deregistration → both SM contexts released + Accept + Release Command.
        let dereg = nas::deregistration_request_from_ue(0x01, "999", "70", 1);
        let downlinks = on_deregistration(&mut ues, &amf_smf, 1, &dereg).await;
        assert_eq!(
            downlinks.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["DownlinkNASTransport (DeregistrationAccept)", "UEContextReleaseCommand"]
        );
        assert_eq!(RELEASES.load(AtomicOrdering::Relaxed), 2, "both SM contexts released at the SMF");
        assert!(!ues.contains_key(&1), "AMF context dropped");
        assert_eq!(
            ngap::parse_ue_context_release_command(&downlinks[1].0),
            Some((1, 7, Some(ngap::CauseNas::DEREGISTER)))
        );
        // UE side: the accept verifies and decodes.
        let nas_bytes = downlink_nas_pdu(&downlinks[0].0).expect("NAS PDU");
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let msg = ue_sec.unprotect(&nas_bytes, 1).expect("UE verifies the accept");
        assert_eq!(
            nas::gmm_message_type(&msg),
            Some(nas::Nas5gmmMessageType::DeregistrationAcceptFromUe)
        );

        // Switch-off (bit 4 set) → no accept, just the release command.
        let mut ctx = UeContext::new(9, RegState::Registered, Some("imsi-999700000000001".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ues.insert(2u64, ctx);
        let dereg = nas::deregistration_request_from_ue(0x09, "999", "70", 1);
        let downlinks = on_deregistration(&mut ues, &amf_smf, 2, &dereg).await;
        assert_eq!(
            downlinks.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["UEContextReleaseCommand"],
            "switch-off expects silence, only the RAN release goes out"
        );
        assert!(!ues.contains_key(&2));
        assert_eq!(RELEASES.load(AtomicOrdering::Relaxed), 2, "no session, no extra release");
    }

    /// gNB-initiated AN release: the AMF deactivates each PDU session's user plane
    /// at the SMF (upCnxState DEACTIVATED), keeps the registered context in
    /// CM-IDLE, and answers with a UEContextReleaseCommand.
    #[tokio::test]
    async fn an_release_deactivates_up_and_goes_cm_idle() {
        use axum::http::StatusCode;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        // Mock SMF recording deactivation (upCnxState=DEACTIVATED) on /modify.
        static DEACTIVATIONS: AtomicUsize = AtomicUsize::new(0);
        async fn mock_modify(axum::Json(body): axum::Json<serde_json::Value>) -> StatusCode {
            if body.get("upCnxState").and_then(|v| v.as_str()) == Some("DEACTIVATED") {
                DEACTIVATIONS.fetch_add(1, AtomicOrdering::Relaxed);
            }
            StatusCode::OK
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            axum::routing::post(mock_modify),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70"); // NRF unused here

        // A registered UE (assigned 5G-TMSI 0x00000101) with two PDU sessions.
        let tmsi = 0x0000_0101u32;
        let smf_base = format!("http://{smf_addr}");
        let mut ctx = UeContext::new(7, RegState::Registered, Some("imsi-999700000000081".into()));
        ctx.guti_tmsi = Some(tmsi);
        ctx.sm_refs.insert(5, ("ctx-5".into(), smf_base.clone()));
        ctx.sm_refs.insert(6, ("ctx-6".into(), smf_base));
        let mut ues = HashMap::new();
        ues.insert(1u64, ctx);

        // gNB → UEContextReleaseRequest (cause radioNetwork user-inactivity).
        let req = ngap::ue_context_release_request(1, 7, 20);
        let dl = on_ue_context_release_request(&mut ues, &amf_smf, &req).await.expect("release cmd");
        assert_eq!(
            ngap::parse_ue_context_release_command(&dl),
            Some((1, 7, Some(ngap::CauseNas::NORMAL_RELEASE)))
        );
        assert_eq!(DEACTIVATIONS.load(AtomicOrdering::Relaxed), 2, "both sessions' UP deactivated");
        // The context left the association map and is retained by 5G-TMSI, CM-IDLE,
        // with its PDU sessions intact for a Service Request.
        assert!(!ues.contains_key(&1), "N2 context removed from the association");
        let retained = RETAINED.lock().unwrap().remove(&tmsi).expect("context retained by 5G-TMSI");
        assert_eq!(retained.cm_state, CmState::Idle);
        assert_eq!(retained.sm_refs.len(), 2, "PDU sessions kept for a later Service Request");

        // A release request for an unknown UE produces no command.
        assert!(on_ue_context_release_request(&mut ues, &amf_smf, &ngap::ue_context_release_request(99, 1, 20)).await.is_none());
    }

    /// Npcf_AMPolicyControl_UpdateNotify handling: the AMF's am-policy-notify
    /// callback resolves the SUPI, delivers the new RFSP + UE-AMBR to the
    /// association, and the handler signals the RAN (UE Context Modification) and
    /// the UE (Configuration Update Command).
    #[tokio::test]
    async fn am_policy_update_notify_applies_the_new_ue_ambr() {
        let (ki, ke) = ([0x77u8; 16], [0x88u8; 16]);
        let mut ctx = UeContext::new(9, RegState::Registered, Some("imsi-999700000000111".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.ue_ambr = Some((2_000_000_000, 1_000_000_000));
        ctx.rfsp = Some(3);
        let mut ues = HashMap::new();
        ues.insert(1u64, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        // The changed policy also moves the UE to a new service area (allow TAC 000002).
        let dls = on_am_policy_update(
            &mut ues,
            1,
            FieldUpdate::Set((600_000_000, 300_000_000)),
            FieldUpdate::Set(9),
            FieldUpdate::Set((vec![[0, 0, 2]], Vec::new())),
            &tx,
        );
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            [
                "UEContextModificationRequest (RFSP)",
                "DownlinkNASTransport (ConfigurationUpdateCommand)",
            ]
        );
        assert_eq!(ues.get(&1).unwrap().ue_ambr, Some((600_000_000, 300_000_000)), "UE-AMBR updated");
        assert_eq!(ues.get(&1).unwrap().rfsp, Some(9), "RFSP updated");
        assert_eq!(
            ues.get(&1).unwrap().area_restriction,
            Some((vec![[0, 0, 2]], Vec::new())),
            "service area updated"
        );
        // The RAN sees the new RFSP + UE-AMBR in the UE Context Modification.
        assert_eq!(
            ngap::ue_context_modification_params(&dls[0].0),
            Some((1, 9, Some(9), Some((600_000_000, 300_000_000))))
        );
        // The RAN sees the new service area (Mobility Restriction List) on the same
        // DownlinkNASTransport that carries the Configuration Update Command.
        assert_eq!(
            ngap::area_restriction_from_downlink_nas(&dls[1].0),
            Some((vec![[0, 0, 2]], Vec::new()))
        );
        // The UE decodes the Configuration Update Command under its context.
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let bytes = downlink_nas_pdu(&dls[1].0).expect("NAS PDU");
        let cuc = ue_sec.unprotect(&bytes, 1).expect("UE verifies the CUC");
        assert_eq!(
            nas::gmm_message_type(&cuc),
            Some(nas::Nas5gmmMessageType::ConfigurationUpdateCommand)
        );
        // The AM-policy command requests acknowledgement and is tracked for T3555
        // retransmission (with the service area, so a resend re-attaches the MRL).
        assert!(nas::configuration_update_acknowledgement_requested(&cuc), "AM-policy CUC requests ack");
        let pending = ues.get(&1).unwrap().pending_config_update.as_ref().expect("tracked");
        assert_eq!(pending.area_restriction, Some((vec![[0, 0, 2]], Vec::new())), "MRL retained for resend");

        // Clearing the service area falls back to the plain transport (no MRL).
        let dls = on_am_policy_update(&mut ues, 1, FieldUpdate::Set((1, 1)), FieldUpdate::Clear, FieldUpdate::Clear, &tx);
        assert_eq!(ngap::area_restriction_from_downlink_nas(&dls[1].0), None);
        assert_eq!(ues.get(&1).unwrap().area_restriction, None, "service area cleared");
        assert_eq!(
            ues.get(&1).unwrap().pending_config_update.as_ref().unwrap().area_restriction,
            None,
            "no MRL tracked after clearing"
        );
        // Unknown UE → no downlinks.
        assert!(
            on_am_policy_update(&mut ues, 999, FieldUpdate::Set((1, 1)), FieldUpdate::Keep, FieldUpdate::Keep, &tx)
                .is_empty()
        );
    }

    /// The PCF removing its UE-AMBR override (an UpdateNotify with no UE-AMBR) falls
    /// the effective UE-AMBR back to the subscribed value and re-signals the RAN.
    #[tokio::test]
    async fn pcf_removing_the_ambr_override_falls_back_to_subscribed() {
        let (ki, ke) = ([0xa1u8; 16], [0xa2u8; 16]);
        let amf_ue_id = 0x81u64;
        let mut ctx = UeContext::new(4, RegState::Registered, Some("imsi-999700000000081".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.subscribed_ue_ambr = Some((1_000_000, 500_000));
        ctx.pcf_ue_ambr = Some((5_000_000, 5_000_000));
        ctx.recompute_ue_ambr();
        ctx.rfsp = Some(7);
        assert_eq!(ctx.ue_ambr, Some((5_000_000, 5_000_000)), "override in effect");
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        // The PCF removes the UE-AMBR override (a partial delta that clears only the
        // UE-AMBR — RFSP and service area omitted, so they're kept) → effective falls
        // back to subscribed, signalled to the RAN in a UE Context Modification.
        let dls =
            on_am_policy_update(&mut ues, amf_ue_id, FieldUpdate::Clear, FieldUpdate::Keep, FieldUpdate::Keep, &tx);
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            [
                "UEContextModificationRequest (RFSP)",
                "DownlinkNASTransport (ConfigurationUpdateCommand)"
            ]
        );
        assert_eq!(ues[&amf_ue_id].pcf_ue_ambr, None, "override removed");
        assert_eq!(ues[&amf_ue_id].ue_ambr, Some((1_000_000, 500_000)), "effective = subscribed");
        assert_eq!(ues[&amf_ue_id].rfsp, Some(7), "RFSP kept (omitted from the delta)");
        let back = NGAP_PDU::decode(&dls[0].0.encode().unwrap()).unwrap();
        let (_a, _r, _rfsp, ambr) = ngap::ue_context_modification_params(&back).unwrap();
        assert_eq!(ambr, Some((1_000_000, 500_000)), "RAN gets the subscribed UE-AMBR");
    }

    /// A **partial** UpdateNotify that changes only the RFSP: the omitted UE-AMBR and
    /// service area are kept (not wiped), so the effective UE-AMBR and the Mobility
    /// Restriction List survive the delta.
    #[tokio::test]
    async fn partial_update_notify_keeps_omitted_fields() {
        let (ki, ke) = ([0xb1u8; 16], [0xb2u8; 16]);
        let amf_ue_id = 0x91u64;
        let mut ctx = UeContext::new(5, RegState::Registered, Some("imsi-999700000000091".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.subscribed_ue_ambr = Some((1_000_000, 500_000));
        ctx.pcf_ue_ambr = Some((5_000_000, 5_000_000));
        ctx.recompute_ue_ambr();
        ctx.rfsp = Some(3);
        ctx.area_restriction = Some((vec![[0, 0, 1]], Vec::new()));
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        // Only the RFSP changes (3 → 9); UE-AMBR and service area are omitted (`Keep`).
        let dls =
            on_am_policy_update(&mut ues, amf_ue_id, FieldUpdate::Keep, FieldUpdate::Set(9), FieldUpdate::Keep, &tx);
        let ctx = &ues[&amf_ue_id];
        assert_eq!(ctx.rfsp, Some(9), "RFSP set");
        assert_eq!(ctx.pcf_ue_ambr, Some((5_000_000, 5_000_000)), "UE-AMBR override kept");
        assert_eq!(ctx.ue_ambr, Some((5_000_000, 5_000_000)), "effective UE-AMBR kept");
        assert_eq!(ctx.area_restriction, Some((vec![[0, 0, 1]], Vec::new())), "service area kept");
        // The RAN still sees the kept UE-AMBR alongside the new RFSP; the kept service
        // area still rides the Configuration Update Command's transport (MRL).
        assert_eq!(
            ngap::ue_context_modification_params(&dls[0].0),
            Some((amf_ue_id, 5, Some(9), Some((5_000_000, 5_000_000))))
        );
        assert_eq!(
            ngap::area_restriction_from_downlink_nas(&dls[1].0),
            Some((vec![[0, 0, 1]], Vec::new())),
            "kept service area still signalled"
        );
    }

    /// Service area restriction: the PCF policy's `servAreaRes` is parsed into
    /// allowed / non-allowed TACs and rides the Registration Accept's
    /// DownlinkNASTransport to the RAN as a Mobility Restriction List.
    #[test]
    fn service_area_restriction_reaches_the_ran() {
        use sbi_core::npcf_am::ServiceAreaRestriction;
        let allowed = ServiceAreaRestriction {
            restriction_type: "ALLOWED_AREAS".into(),
            tacs: vec!["000001".into(), "00000a".into(), "bad".into()], // "bad" dropped
        };
        assert_eq!(
            area_restriction_tacs(&allowed),
            Some((vec![[0, 0, 1], [0, 0, 0x0a]], Vec::new())),
            "ALLOWED_AREAS → allowed TACs, malformed dropped"
        );
        let forbidden = ServiceAreaRestriction {
            restriction_type: "NOT_ALLOWED_AREAS".into(),
            tacs: vec!["000002".into()],
        };
        assert_eq!(area_restriction_tacs(&forbidden), Some((Vec::new(), vec![[0, 0, 2]])));
        // No usable TAC → nothing to signal.
        assert_eq!(
            area_restriction_tacs(&ServiceAreaRestriction {
                restriction_type: "ALLOWED_AREAS".into(),
                tacs: vec!["zz".into()],
            }),
            None
        );

        // The AMF builds the Registration Accept DL NAS with the restriction, and the
        // RAN reads it back out of the Mobility Restriction List.
        let (a, na) = area_restriction_tacs(&allowed).unwrap();
        let dl = ngap::downlink_nas_transport_with_area_restriction(1, 2, vec![9, 9], "999", "70", &a, &na);
        assert_eq!(
            ngap::area_restriction_from_downlink_nas(&dl),
            Some((vec![[0, 0, 1], [0, 0, 0x0a]], Vec::new()))
        );
    }

    /// AM policy: the AMF discovers the PCF and creates an AM policy association at
    /// registration; the PCF's UE-AMBR overrides the subscribed one (verified by the
    /// `on_security_mode_complete` override math in production).
    #[tokio::test]
    async fn am_policy_association_created_at_registration() {
        use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, NrfClient, NrfStore};

        // NRF + a real AM-policy PCF (demo config) registered as nf-type PCF.
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(nrf_l, sbi_core::nnrf::router(NrfStore::default())).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");

        let am = sbi_core::npcf_am::AmPcfState::new(sbi_core::npcf_am::AmPolicyConfig::demo());
        let pcf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pcf_addr = pcf_l.local_addr().unwrap();
        let am_served = am.clone();
        tokio::spawn(async move { sbi_core::run_on(pcf_l, sbi_core::npcf_am::router(am_served)).await.unwrap() });
        let mut profile = NfProfile::new("pcf-am", "PCF", pcf_addr.ip().to_string());
        profile.nf_services = Some(vec![NfService {
            service_instance_id: "npcf-am-policy-control-1".into(),
            service_name: "npcf-am-policy-control".into(),
            scheme: "http".into(),
            ip_end_points: vec![IpEndPoint {
                ipv4_address: Some(pcf_addr.ip().to_string()),
                port: Some(pcf_addr.port()),
            }],
        }]);
        NrfClient::new(nrf_base.clone()).register(&profile).await.unwrap();

        // create_am_policy discovers the PCF and opens the association.
        let (pcf_base, assoc_id, policy) =
            create_am_policy(&nrf_base, "imsi-999700000000001", "999", "70").await.expect("AM policy");
        assert_eq!(am.association_count(), 1, "association opened at the PCF");
        assert_eq!(policy.rfsp, Some(3));
        let ambr = policy.ue_ambr.as_ref().expect("policy UE-AMBR");
        // The override the AMF applies: (dl, ul) bps from the policy bitrate strings.
        assert_eq!(
            (bitrate_to_bps(&ambr.downlink), bitrate_to_bps(&ambr.uplink)),
            (Some(1_000_000_000), Some(500_000_000)),
            "policy UE-AMBR overrides the subscribed one"
        );
        // The PCF policy carries a service area restriction the AMF signals to the RAN.
        let sar = policy.serv_area_res.as_ref().expect("policy servAreaRes");
        assert_eq!(area_restriction_tacs(sar), Some((vec![[0, 0, 1]], Vec::new())));

        // Deletion (deregistration) closes it.
        spawn_am_policy_delete(Some((pcf_base, assoc_id)));
        for _ in 0..50 {
            if am.association_count() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(am.association_count(), 0, "association deleted at deregistration");
    }

    /// Implicit deregistration: a retained CM-IDLE context idle past the deadline is
    /// evicted — its PDU sessions released at the SMF — while a fresh one survives.
    #[tokio::test]
    async fn stale_retained_context_is_implicitly_deregistered() {
        use axum::http::StatusCode;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::time::{Duration, Instant};

        static RELEASES: AtomicUsize = AtomicUsize::new(0);
        async fn mock_release() -> StatusCode {
            RELEASES.fetch_add(1, AtomicOrdering::Relaxed);
            StatusCode::NO_CONTENT
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/release",
            axum::routing::post(mock_release),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");
        let smf_base = format!("http://{smf_addr}");

        // A stale idle context (retained long ago) with one PDU session…
        let stale_tmsi = 0x0000_1201u32;
        let mut stale = UeContext::new(0, RegState::Registered, Some("imsi-999700000001201".into()));
        stale.guti_tmsi = Some(stale_tmsi);
        stale.retained_at = Some(Instant::now() - Duration::from_secs(3600));
        stale.sm_refs.insert(5, ("ctx-5".into(), smf_base));
        RETAINED.lock().unwrap().insert(stale_tmsi, stale);

        // …and a freshly idle one that must survive.
        let fresh_tmsi = 0x0000_1202u32;
        let mut fresh = UeContext::new(0, RegState::Registered, Some("imsi-999700000001202".into()));
        fresh.guti_tmsi = Some(fresh_tmsi);
        fresh.retained_at = Some(Instant::now());
        RETAINED.lock().unwrap().insert(fresh_tmsi, fresh);

        // Sweep with a 5-minute deadline: only the stale one is evicted.
        evict_stale_retained(&amf_smf, Duration::from_secs(300)).await;
        assert!(RETAINED.lock().unwrap().get(&stale_tmsi).is_none(), "stale context evicted");
        assert!(RETAINED.lock().unwrap().get(&fresh_tmsi).is_some(), "fresh context kept");
        assert_eq!(RELEASES.load(AtomicOrdering::Relaxed), 1, "the stale UE's PDU session released");

        RETAINED.lock().unwrap().remove(&fresh_tmsi);
    }

    /// Network-initiated paging: the SMF's N1N2 message transfer (downlink data)
    /// resolves the SUPI to its retained CM-IDLE 5G-TMSI and broadcasts a Page
    /// command to the gNB associations, which each build an NGAP Paging.
    #[tokio::test]
    async fn downlink_data_pages_a_cm_idle_ue() {
        let supi = "imsi-999700000000101";
        let tmsi = 0x0000_0101u32;

        // A retained CM-IDLE context for the UE.
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.guti_tmsi = Some(tmsi);
        RETAINED.lock().unwrap().insert(tmsi, ctx);

        // A mock gNB association link registered in GNB_LINKS (serving the AMF TAC).
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        GNB_LINKS.lock().unwrap().push(GnbLink { tacs: vec![AMF_TAC], gnb_id: None, tx });

        // The SMF calls the AMF's N1N2 paging surface.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(listener, namf_callback_router()).await.unwrap() });
        let client = sbi_core::h2c_client();
        let status = client
            .post(format!("http://{addr}/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 202, "paging accepted");
        // The gNB link received a Page for this TMSI (tolerating broadcasts from
        // parallel tests sharing the global registry).
        let mut paged = false;
        for _ in 0..10 {
            match rx.recv().await {
                Some(UeCmd::Page { tmsi: t, .. }) if t == tmsi => {
                    paged = true;
                    break;
                }
                Some(_) => continue,
                None => break,
            }
        }
        assert!(paged, "gNB paged for the downlink data");

        // Paging an unknown (not CM-IDLE) UE → 404.
        let status = client
            .post(format!("http://{addr}/namf-comm/v1/ue-contexts/imsi-000/n1-n2-messages"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404);

        RETAINED.lock().unwrap().remove(&tmsi);
    }

    /// Registration-area paging: only the gNB associations whose Supported TA List
    /// intersects the UE's registration area are paged (each with the full area in
    /// its TAI list); a gNB with no NG Setup yet (empty TA list) is included
    /// fail-open, and an empty area pages everyone in the default TAC.
    #[tokio::test]
    async fn paging_is_scoped_to_the_ue_registration_area() {
        let tmsi = 0x0000_0131u32;
        // A two-TA registration area, unique to this test.
        let area = vec![[0u8, 0, 0x77], [0u8, 0, 0x7a]];

        // gNB A serves one of the area's TAs; gNB B serves a different one; gNB C
        // has no NG Setup yet (empty list → fail-open).
        let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();
        let (tx_c, mut rx_c) = tokio::sync::mpsc::unbounded_channel();
        {
            let mut links = GNB_LINKS.lock().unwrap();
            links.push(GnbLink { tacs: vec![[0, 0, 0x7a]], gnb_id: None, tx: tx_a });
            links.push(GnbLink { tacs: vec![[0, 0, 0x78]], gnb_id: None, tx: tx_b });
            links.push(GnbLink { tacs: Vec::new(), gnb_id: None, tx: tx_c });
        }

        // Page the area: A and C see it (carrying the FULL area), B does not.
        page_gnbs(tmsi, &area);
        let mine = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<UeCmd>| {
            let mut hits = 0;
            while let Ok(cmd) = rx.try_recv() {
                if matches!(&cmd, UeCmd::Page { tmsi: t, tacs } if *t == tmsi && *tacs == area) {
                    hits += 1;
                }
            }
            hits
        };
        assert_eq!(mine(&mut rx_a), 1, "a gNB serving part of the area is paged");
        assert_eq!(mine(&mut rx_b), 0, "a gNB outside the registration area is not");
        assert_eq!(mine(&mut rx_c), 1, "a gNB with no TA list yet is paged fail-open");

        // An empty area falls back to paging everyone (in the default TAC).
        page_gnbs(tmsi, &[]);
        let broadcast = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<UeCmd>| {
            let mut hits = 0;
            while let Ok(cmd) = rx.try_recv() {
                if matches!(&cmd, UeCmd::Page { tmsi: t, tacs } if *t == tmsi && *tacs == [AMF_TAC]) {
                    hits += 1;
                }
            }
            hits
        };
        assert_eq!(broadcast(&mut rx_a), 1);
        assert_eq!(broadcast(&mut rx_b), 1);
        assert_eq!(broadcast(&mut rx_c), 1);
    }

    /// Mobility registration update (TS 24.501 §5.5.1.3): a CM-IDLE UE that moved
    /// outside its registration area comes back with a protected Registration
    /// Periodic registration updating (TS 24.501 §5.5.1.3.2): a CM-IDLE UE checks
    /// in when T3512 expires. The AMF verifies it under the retained security
    /// context, keeps the registration area unchanged (the UE hasn't moved),
    /// answers with a Registration Accept, and does not reactivate the user plane
    /// — the point is to refresh the context so the implicit-dereg sweep won't
    /// evict a UE that is still reachable.
    #[tokio::test]
    async fn periodic_registration_update_refreshes_without_reauth() {
        let (ki, ke) = ([0x31u8; 16], [0x32u8; 16]);
        let kamf = [0x33u8; 32];
        let supi = "imsi-999700000000211";
        let tmsi = 0x0000_0211u32;
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.guti_tmsi = Some(tmsi);
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.kamf = Some(kamf);
        ctx.tac = Some([0, 0, 1]);
        ctx.registration_area = vec![[0, 0, 1], [0, 0, 2]];
        ctx.allowed_nssai = Some(vec![(1, Some([1, 2, 3]))]);
        ctx.retained_at = Some(std::time::Instant::now()); // was ticking toward eviction
        ctx.sm_refs.insert(5, ("ctx-per".into(), "http://127.0.0.1:1".into()));
        RETAINED.lock().unwrap().insert(tmsi, ctx);
        GUTI_DIRECTORY.lock().unwrap().insert(tmsi, supi.into()); // the old GUTI



        // The UE checks in from the same gNB (TAC 000001) with a protected periodic
        // Registration Request — a mock SMF that would fail any activation call.
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let rr = ue_sec.protect(
            &nas::registration_request_periodic("999", "70", tmsi),
            nas::sht::INTEGRITY_CIPHERED,
            0,
        );
        let pdu = ngap::initial_ue_message_with_stmsi_at(7, tmsi, rr, "999", "70", &[0, 0, 1]);
        let init = as_initial_ue(&pdu);
        let (gnb_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut ues = HashMap::new();
        let dls = on_service_request(&mut ues, &amf_smf, init, tmsi, &gnb_tx).await;

        // One downlink: the ICS carrying the periodic Registration Accept. No PDU
        // session reactivation.
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["InitialContextSetupRequest (RegistrationAccept — periodic)"]
        );
        let (new_amf_id, _r, ic) = ngap::initial_context_setup_params(&dls[0].0).expect("ICS parses");
        // The context is restored CM-CONNECTED, the retained timer stopped, the
        // area unchanged (the UE didn't move), the session intact.
        let restored = ues.get(&new_amf_id).expect("context restored");
        assert_eq!(restored.cm_state, CmState::Connected);
        assert_eq!(restored.retained_at, None, "mobile-reachable timer stopped");
        assert_eq!(restored.registration_area, vec![[0, 0, 1], [0, 0, 2]], "area unchanged");
        assert_eq!(restored.sm_refs.len(), 1, "PDU session kept");
        assert!(RETAINED.lock().unwrap().get(&tmsi).is_none(), "no longer awaiting eviction");
        // GUTI reallocation: a fresh 5G-TMSI (the new AMF-UE-NGAP-ID); GUTI_DIRECTORY
        // re-keyed (old TMSI gone, new → SUPI); the context holds the new TMSI.
        let new_tmsi = new_amf_id as u32;
        assert_ne!(new_tmsi, tmsi, "GUTI reallocated");
        assert_eq!(restored.guti_tmsi, Some(new_tmsi));
        assert_eq!(GUTI_DIRECTORY.lock().unwrap().get(&tmsi), None, "old GUTI removed");
        assert_eq!(GUTI_DIRECTORY.lock().unwrap().get(&new_tmsi).map(String::as_str), Some(supi));
        // The UE decodes the accept: the new GUTI, same area, kept NSSAI.
        let accept = ue_sec.unprotect(&ic.nas, 1).expect("UE verifies the accept");
        assert_eq!(nas::gmm_message_type(&accept), Some(nas::Nas5gmmMessageType::RegistrationAccept));
        assert_eq!(nas::guti_tmsi_from_registration_accept(&accept), Some(new_tmsi), "new GUTI to the UE");
        assert_eq!(
            nas::registration_area_from_registration_accept(&accept),
            Some(vec![[0, 0, 1], [0, 0, 2]])
        );
        GUTI_DIRECTORY.lock().unwrap().retain(|_, s| s != supi);
        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// Uplink Data Status (TS 24.501 §9.11.3.57): a registration update whose
    /// Uplink Data Status IE lists a PDU session reactivates **that** session's
    /// user plane (unlike a plain registration update), while leaving an unlisted
    /// session deactivated.
    #[tokio::test]
    async fn registration_update_reactivates_uplink_data_status_sessions() {
        use std::sync::atomic::{AtomicUsize, Ordering as O};

        // Mock SMF: ACTIVATING returns the retained N3 info + counts activations.
        static ACTS: AtomicUsize = AtomicUsize::new(0);
        async fn mock_modify(axum::Json(body): axum::Json<serde_json::Value>) -> axum::response::Response {
            use axum::response::IntoResponse;
            if body.get("upCnxState").and_then(|v| v.as_str()) == Some("ACTIVATING") {
                ACTS.fetch_add(1, O::Relaxed);
                return (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "upN3Teid": "00000001", "upN3Addr": "127.0.0.1", "ueIpv4Addr": "10.45.0.2"
                    })),
                )
                    .into_response();
            }
            axum::http::StatusCode::OK.into_response()
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            axum::routing::post(mock_modify),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        let (ki, ke) = ([0x41u8; 16], [0x42u8; 16]);
        let supi = "imsi-999700000000221";
        let tmsi = 0x0000_0221u32;
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.guti_tmsi = Some(tmsi);
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.kamf = Some([0x43u8; 32]);
        ctx.tac = Some([0, 0, 1]);
        ctx.registration_area = vec![[0, 0, 1]];
        ctx.allowed_nssai = Some(vec![(1, Some([1, 2, 3]))]);
        // Two retained PDU sessions; only #5 has pending uplink data.
        ctx.sm_refs.insert(5, ("ctx-5".into(), format!("http://{smf_addr}")));
        ctx.sm_refs.insert(6, ("ctx-6".into(), format!("http://{smf_addr}")));
        RETAINED.lock().unwrap().insert(tmsi, ctx);

        // A mobility registration update with an Uplink Data Status listing PSI 5.
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let rr = ue_sec.protect(
            &nas::registration_request_with_uplink_data(
                nas::RegistrationType::MobilityRegistrationUpdate,
                "999",
                "70",
                tmsi,
                &[5],
            ),
            nas::sht::INTEGRITY_CIPHERED,
            0,
        );
        let pdu = ngap::initial_ue_message_with_stmsi_at(6, tmsi, rr, "999", "70", &[0, 0, 1]);
        let init = as_initial_ue(&pdu);
        let (gnb_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut ues = HashMap::new();
        let dls = on_service_request(&mut ues, &amf_smf, init, tmsi, &gnb_tx).await;

        // One Initial Context Setup carrying the accept and PSI 5 set up inline.
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["InitialContextSetupRequest (RegistrationAccept — mobility update)"]
        );
        assert_eq!(ACTS.load(O::Relaxed), 1, "only the flagged session reactivated");
        // Only PSI 5 rides the ICS — PSI 6 stays deactivated.
        assert_eq!(
            ngap::initial_context_setup_request_session_ids(&dls[0].0)
                .iter()
                .map(|(psi, _, _)| *psi)
                .collect::<Vec<_>>(),
            vec![5]
        );
        UE_DIRECTORY.lock().unwrap().remove(supi);
        GUTI_DIRECTORY.lock().unwrap().retain(|_, s| s != supi);
    }

    /// Request (type = mobility registration updating, GUTI identity). The AMF
    /// verifies it under the retained security context, **re-assigns** the
    /// registration area around the new serving gNB, and answers with a
    /// Registration Accept carrying the new 5GS TAI list — no user-plane
    /// reactivation unless the Uplink Data Status IE requests it.
    #[tokio::test]
    async fn mobility_registration_update_reassigns_the_area() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        // Mock SMF counting UP activation attempts (a mobility update must not).
        static MOBILITY_ACTIVATIONS: AtomicUsize = AtomicUsize::new(0);
        async fn mock_modify(axum::Json(body): axum::Json<serde_json::Value>) -> axum::http::StatusCode {
            if body.get("upCnxState").and_then(|v| v.as_str()) == Some("ACTIVATING") {
                MOBILITY_ACTIVATIONS.fetch_add(1, AtomicOrdering::Relaxed);
            }
            axum::http::StatusCode::OK
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            axum::routing::post(mock_modify),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        // A retained CM-IDLE UE registered in TAC 000001 with a one-TA area + a
        // PDU session, holding a NAS security context.
        let (ki, ke) = ([0xbbu8; 16], [0xccu8; 16]);
        let supi = "imsi-999700000000151";
        let tmsi = 0x0000_0151u32;
        let kamf = [0x51u8; 32];
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.guti_tmsi = Some(tmsi);
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.kamf = Some(kamf);
        ctx.tac = Some([0, 0, 1]);
        ctx.registration_area = vec![[0, 0, 1]];
        ctx.allowed_nssai = Some(vec![(1, Some([1, 2, 3]))]);
        ctx.sm_refs.insert(5, ("ctx-m5".into(), format!("http://{smf_addr}")));
        RETAINED.lock().unwrap().insert(tmsi, ctx);

        // The new serving gNB's association serves TACs 000009 + 00000b.
        let (gnb_tx, _gnb_rx) = tokio::sync::mpsc::unbounded_channel();
        GNB_LINKS
            .lock()
            .unwrap()
            .push(GnbLink { tacs: vec![[0, 0, 9], [0, 0, 0x0b]], gnb_id: None, tx: gnb_tx.clone() });

        // The UE moved to TAC 000009 (outside its area) → protected mobility
        // Registration Request, GUTI identity, via that gNB.
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let rr = ue_sec.protect(
            &nas::registration_request_mobility("999", "70", tmsi),
            nas::sht::INTEGRITY_CIPHERED,
            0,
        );
        let pdu = ngap::initial_ue_message_with_stmsi_at(6, tmsi, rr, "999", "70", &[0, 0, 9]);
        let init = as_initial_ue(&pdu);
        let mut ues = HashMap::new();
        let dls = on_service_request(&mut ues, &amf_smf, init, tmsi, &gnb_tx).await;

        // One downlink: the Initial Context Setup carrying the mobility
        // Registration Accept (a fresh AS context at the new gNB). No user-plane
        // reactivation.
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["InitialContextSetupRequest (RegistrationAccept — mobility update)"]
        );
        assert_eq!(MOBILITY_ACTIVATIONS.load(AtomicOrdering::Relaxed), 0, "UP stays deactivated");
        // The context is restored CM-CONNECTED with the area RE-ASSIGNED around
        // the new serving gNB (not merely extended), sessions intact.
        let (_id, restored) = ues.iter().next().expect("context restored");
        assert_eq!(restored.cm_state, CmState::Connected);
        assert_eq!(restored.tac, Some([0, 0, 9]));
        assert_eq!(restored.registration_area, vec![[0, 0, 9], [0, 0, 0x0b]]);
        assert_eq!(restored.sm_refs.len(), 1, "PDU session survives the mobility update");
        assert!(UE_DIRECTORY.lock().unwrap().contains_key(supi), "reachable again over N2");
        assert!(RETAINED.lock().unwrap().get(&tmsi).is_none(), "retained context consumed");

        // A fresh K_gNB bound to the mobility Registration Request's UL NAS COUNT.
        let (_a, _r, ic) = ngap::initial_context_setup_params(&dls[0].0).expect("ICS parses");
        assert_eq!(ic.security_key, aka::kgnb(&kamf, 0));
        assert_eq!(ic.allowed_nssai, vec![(1, Some([1, 2, 3]))], "retained NSSAI at the RAN too");
        // The UE decodes the accept: same GUTI, the NEW 5GS TAI list, NSSAI kept.
        let accept = ue_sec.unprotect(&ic.nas, 1).expect("UE verifies the accept");
        assert_eq!(nas::gmm_message_type(&accept), Some(nas::Nas5gmmMessageType::RegistrationAccept));
        assert_eq!(
            nas::registration_area_from_registration_accept(&accept),
            Some(vec![[0, 0, 9], [0, 0, 0x0b]])
        );
        assert_eq!(
            nas::allowed_nssai_from_registration_accept(&accept),
            vec![(1, Some([1, 2, 3]))]
        );
        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// Xn handover path switch (TS 38.413 §8.4.4 + TS 33.501 §6.9.2.3.3): the
    /// target gNB's PathSwitchRequest re-points the UPF downlink to its new
    /// F-TEID, rotates the NH chain (fresh NH, NCC+1), and the acknowledge hands
    /// the target the {NCC, NH} pair; a second switch chains NH from the first.
    #[tokio::test]
    async fn xn_path_switch_rotates_nh_and_repoints_the_downlink() {
        use std::sync::Mutex as StdMutex;

        // Mock SMF capturing the downlink re-point bodies.
        static SWITCHES: StdMutex<Vec<(String, String)>> = StdMutex::new(Vec::new());
        async fn mock_modify(
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::http::StatusCode {
            if let (Some(teid), Some(addr)) = (
                body.get("gnbN3Teid").and_then(|v| v.as_str()),
                body.get("gnbN3Addr").and_then(|v| v.as_str()),
            ) {
                SWITCHES.lock().unwrap().push((teid.into(), addr.into()));
            }
            axum::http::StatusCode::OK
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            axum::routing::post(mock_modify),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        // A CM-CONNECTED UE whose NH chain was seeded by the Initial Context Setup.
        let kamf = [0x71u8; 32];
        let kgnb0 = aka::kgnb(&kamf, 0);
        let amf_ue_id = 0x171u64;
        let mut ctx = UeContext::new(3, RegState::Registered, Some("imsi-999700000000171".into()));
        ctx.kamf = Some(kamf);
        ctx.nh_chain = Some((kgnb0, 0));
        ctx.tac = Some([0, 0, 1]);
        ctx.sm_refs.insert(5, ("ctx-ps5".into(), format!("http://{smf_addr}")));
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);

        // This association's own channel (the context is local — no takeover).
        let (dereg_tx, _dereg_rx) = tokio::sync::mpsc::unbounded_channel();
        // The target gNB (RAN-UE 9, TAC 000002) asks to switch PDU session 5.
        let req = ngap::path_switch_request(
            amf_ue_id,
            9,
            "999",
            "70",
            &[0, 0, 2],
            &[0x20, 0x20],
            &[(5, 0x77, std::net::Ipv4Addr::new(10, 0, 9, 2))],
        );
        let (ack, label) =
            on_path_switch(&mut ues, &amf_smf, &req, &dereg_tx).await.expect("acknowledged");
        assert_eq!(label, "PathSwitchRequestAcknowledge");
        // The fresh {NCC, NH}: first hop = KDF(K_AMF, initial K_gNB), NCC 1.
        let nh1 = aka::nh(&kamf, &kgnb0);
        assert_eq!(ngap::path_switch_ack_security(&ack), Some((1, nh1, vec![5])));
        // The context followed the UE to the target gNB.
        let ctx = ues.get(&amf_ue_id).unwrap();
        assert_eq!(ctx.ran_ue_id, 9);
        assert_eq!(ctx.tac, Some([0, 0, 2]), "location refreshed from the ULI");
        assert_eq!(ctx.nh_chain, Some((nh1, 1)), "chain rotated");
        // The UPF downlink was re-pointed to the target's F-TEID.
        assert_eq!(
            SWITCHES.lock().unwrap().as_slice(),
            [("00000077".to_string(), "10.0.9.2".to_string())]
        );

        // A second switch chains the NH from the first (NCC 2).
        let req2 = ngap::path_switch_request(
            amf_ue_id,
            11,
            "999",
            "70",
            &[0, 0, 1],
            &[0x20, 0x20],
            &[(5, 0x88, std::net::Ipv4Addr::new(10, 0, 9, 3))],
        );
        let (ack2, _) = on_path_switch(&mut ues, &amf_smf, &req2, &dereg_tx).await.expect("acknowledged");
        let nh2 = aka::nh(&kamf, &nh1);
        assert_ne!(nh2, nh1);
        assert_eq!(ngap::path_switch_ack_security(&ack2), Some((2, nh2, vec![5])));
        assert_eq!(ues.get(&amf_ue_id).unwrap().nh_chain, Some((nh2, 2)));

        // Unknown UE / unseeded chain → a PathSwitchRequestFailure, not an ack.
        let bogus =
            ngap::path_switch_request(9999, 1, "999", "70", &[0, 0, 1], &[0x20, 0x20], &[(5, 1, std::net::Ipv4Addr::LOCALHOST)]);
        let (fail, label) =
            on_path_switch(&mut ues, &amf_smf, &bogus, &dereg_tx).await.expect("failure sent");
        assert_eq!(label, "PathSwitchRequestFailure");
        assert_eq!(ngap::path_switch_failure_params(&fail), Some((9999, 1, vec![5])));
        ues.get_mut(&amf_ue_id).unwrap().nh_chain = None;
        let (fail, label) =
            on_path_switch(&mut ues, &amf_smf, &req2, &dereg_tx).await.expect("failure sent");
        assert_eq!(label, "PathSwitchRequestFailure");
        assert_eq!(ngap::path_switch_failure_params(&fail), Some((amf_ue_id, 11, vec![5])));
    }

    /// Indirect data forwarding (TS 23.502 §4.9.1.3.3): when the source has no
    /// direct Xn-U path, the AMF sets up a UPF forwarding tunnel per session and
    /// the Handover Command carries the **UPF's** ingress F-TEID (not the target's
    /// forwarding F-TEID); the tunnels are released when the UE arrives.
    #[tokio::test]
    async fn n2_handover_sets_up_indirect_forwarding() {
        use std::sync::atomic::{AtomicUsize, Ordering as O};

        // Mock SMF: ACTIVATING → UL N3 info; indirect-forwarding setup → a UPF
        // ingress F-TEID (000000cc); release → 204. Setup/release counted.
        static SETUPS: AtomicUsize = AtomicUsize::new(0);
        static RELEASES: AtomicUsize = AtomicUsize::new(0);
        async fn mock_modify(axum::Json(_): axum::Json<serde_json::Value>) -> axum::response::Response {
            use axum::response::IntoResponse;
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "upN3Teid": "00000001", "upN3Addr": "127.0.0.1", "ueIpv4Addr": "10.45.0.2"
                })),
            )
                .into_response()
        }
        async fn mock_fwd(axum::Json(body): axum::Json<serde_json::Value>) -> axum::response::Response {
            use axum::response::IntoResponse;
            if body.get("release").and_then(|v| v.as_bool()) == Some(true) {
                RELEASES.fetch_add(1, O::Relaxed);
                return axum::http::StatusCode::NO_CONTENT.into_response();
            }
            SETUPS.fetch_add(1, O::Relaxed);
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({ "fwdN3Teid": "000000cc", "fwdN3Addr": "10.0.9.9" })),
            )
                .into_response()
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new()
            .route("/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify", axum::routing::post(mock_modify))
            .route(
                "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/indirect-forwarding",
                axum::routing::post(mock_fwd),
            );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        let kamf = [0xc1u8; 32];
        let amf_ue_id = 0x1c1u64;
        let supi = "imsi-999700000000201";
        let mut ctx = UeContext::new(4, RegState::Registered, Some(supi.into()));
        ctx.kamf = Some(kamf);
        ctx.nh_chain = Some((aka::kgnb(&kamf, 0), 0));
        ctx.sm_refs.insert(5, ("ctx-ind".into(), format!("http://{smf_addr}")));
        let mut src_ues = HashMap::new();
        src_ues.insert(amf_ue_id, ctx);

        let (src_tx, mut src_rx) = tokio::sync::mpsc::unbounded_channel();
        let (tgt_tx, mut tgt_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let mut links = GNB_LINKS.lock().unwrap();
            links.push(GnbLink { tacs: Vec::new(), gnb_id: None, tx: src_tx.clone() });
            links.push(GnbLink { tacs: Vec::new(), gnb_id: Some(0x99), tx: tgt_tx.clone() });
        }
        UE_DIRECTORY.lock().unwrap().insert(supi.into(), (amf_ue_id, src_tx.clone()));

        async fn next_forward(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<UeCmd>,
        ) -> (NGAP_PDU, &'static str) {
            loop {
                match rx.recv().await {
                    Some(UeCmd::Forward { pdu, label }) => return (*pdu, label),
                    Some(_) => continue,
                    None => panic!("link closed"),
                }
            }
        }

        // Handover Required with NO direct forwarding path.
        let required =
            ngap::handover_required(amf_ue_id, 4, 0x99, "999", "70", &[0, 0, 2], &[5], false, b"s2t".to_vec());
        assert!(on_handover_required(&mut src_ues, &amf_smf, &required, &src_tx).await.is_none());
        let _ = next_forward(&mut tgt_rx).await; // the HandoverRequest

        // The source association's select loop (simulated): owns the context and
        // services TakeUe + captures forwarded PDUs (the Handover Command).
        let src_cap: std::sync::Arc<std::sync::Mutex<Vec<(NGAP_PDU, &'static str)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let src_cap_w = src_cap.clone();
        tokio::spawn(async move {
            while let Some(cmd) = src_rx.recv().await {
                match cmd {
                    UeCmd::TakeUe { amf_ue_id, reply } => {
                        for dl in on_take_ue(&mut src_ues, amf_ue_id, reply) {
                            src_cap_w.lock().unwrap().push(dl);
                        }
                    }
                    UeCmd::Forward { pdu, label } => src_cap_w.lock().unwrap().push((*pdu, label)),
                    _ => {}
                }
            }
        });

        // The target admits the session offering a DL FORWARDING F-TEID (0xBB).
        let ack = ngap::handover_request_acknowledge(
            amf_ue_id,
            9,
            &[(5, 0xAA, std::net::Ipv4Addr::new(10, 0, 9, 5), Some((0xBB, std::net::Ipv4Addr::new(10, 0, 9, 6))))],
            b"t2s".to_vec(),
        );
        on_handover_request_ack(&amf_smf, &ack).await;

        // The AMF set up ONE indirect tunnel and the Handover Command carries the
        // UPF's ingress F-TEID (000000cc @ 10.0.9.9), not the target's 0xBB.
        assert_eq!(SETUPS.load(O::Relaxed), 1, "one indirect tunnel established");
        let mut command_ok = false;
        for _ in 0..50 {
            {
                let cap = src_cap.lock().unwrap();
                if let Some((pdu, _)) = cap.iter().find(|(_, l)| *l == "HandoverCommand") {
                    assert_eq!(
                        ngap::handover_command_params(pdu),
                        Some((amf_ue_id, 4, vec![(5, 0xCC, std::net::Ipv4Addr::new(10, 0, 9, 9))], b"t2s".to_vec())),
                        "the source forwards to the UPF ingress, not the target"
                    );
                    command_ok = true;
                }
            }
            if command_ok {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(command_ok, "Handover Command with the UPF ingress F-TEID reached the source");
        assert!(HANDOVERS.lock().unwrap().get(&amf_ue_id).unwrap().indirect_active);

        // The UE arrives → the forwarding tunnel is released.
        let notify = ngap::handover_notify(amf_ue_id, 9, "999", "70", &[0, 0, 2]);
        let mut tgt_ues = HashMap::new();
        on_handover_notify(&mut tgt_ues, &amf_smf, &notify, &tgt_tx).await;
        assert_eq!(RELEASES.load(O::Relaxed), 1, "indirect tunnel released on completion");
        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// The full N2 handover (TS 23.502 §4.9.1.3): Handover Required on the source
    /// association → Handover Request to the target (rotated {NH, NCC} + the UPF's
    /// UL F-TEID) → the target's acknowledge → Handover Command back to the source
    /// → Handover Notify → context takeover, downlink re-point to the target's DL
    /// F-TEID, source release, directory re-point.
    #[tokio::test]
    async fn n2_handover_orchestrates_source_to_target() {
        use std::sync::Mutex as StdMutex;

        // Mock SMF: ACTIVATING fetches return the UPF's UL N3 info; gnbN3Teid
        // bodies (the downlink re-point) are captured.
        static HO_SWITCHES: StdMutex<Vec<(String, String)>> = StdMutex::new(Vec::new());
        async fn mock_modify(
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::response::Response {
            use axum::response::IntoResponse;
            if body.get("upCnxState").and_then(|v| v.as_str()) == Some("ACTIVATING") {
                return (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "upN3Teid": "00000001", "upN3Addr": "127.0.0.1", "ueIpv4Addr": "10.45.0.2"
                    })),
                )
                    .into_response();
            }
            if let (Some(teid), Some(addr)) = (
                body.get("gnbN3Teid").and_then(|v| v.as_str()),
                body.get("gnbN3Addr").and_then(|v| v.as_str()),
            ) {
                HO_SWITCHES.lock().unwrap().push((teid.into(), addr.into()));
            }
            axum::http::StatusCode::OK.into_response()
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            axum::routing::post(mock_modify),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        // The UE lives on the SOURCE association (RAN-UE 4), NH chain seeded.
        let kamf = [0x91u8; 32];
        let kgnb0 = aka::kgnb(&kamf, 0);
        let amf_ue_id = 0x191u64;
        let supi = "imsi-999700000000191";
        let mut ctx = UeContext::new(4, RegState::Registered, Some(supi.into()));
        ctx.kamf = Some(kamf);
        ctx.nh_chain = Some((kgnb0, 0));
        ctx.ue_ambr = Some((900_000_000, 400_000_000));
        ctx.allowed_nssai = Some(vec![(1, Some([1, 2, 3]))]);
        ctx.replayed_ue_sec_cap = Some([0x20, 0x20]);
        ctx.sm_refs.insert(5, ("ctx-n2ho".into(), format!("http://{smf_addr}")));
        let mut src_ues = HashMap::new();
        src_ues.insert(amf_ue_id, ctx);

        // Source + target associations; the target advertises gNB id 0x77.
        let (src_tx, mut src_rx) = tokio::sync::mpsc::unbounded_channel();
        let (tgt_tx, mut tgt_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let mut links = GNB_LINKS.lock().unwrap();
            links.push(GnbLink { tacs: Vec::new(), gnb_id: None, tx: src_tx.clone() });
            links.push(GnbLink { tacs: Vec::new(), gnb_id: Some(0x77), tx: tgt_tx.clone() });
        }
        UE_DIRECTORY.lock().unwrap().insert(supi.into(), (amf_ue_id, src_tx.clone()));

        // 1. Handover Required arrives on the SOURCE association (direct
        // forwarding available).
        let required = ngap::handover_required(
            amf_ue_id, 4, 0x77, "999", "70", &[0, 0, 2], &[5], true, b"s2t".to_vec(),
        );
        on_handover_required(&mut src_ues, &amf_smf, &required, &src_tx).await;
        // The target association received the Handover Request: rotated {NCC, NH},
        // the UPF's UL F-TEID (from the mock SMF), the source's container.
        let nh1 = aka::nh(&kamf, &kgnb0);
        let ho_request = loop {
            match tgt_rx.recv().await {
                Some(UeCmd::Forward { pdu, label }) => {
                    assert_eq!(label, "HandoverRequest");
                    break *pdu;
                }
                // Broadcasts from parallel tests sharing the global registry
                // (Page / TakeUe probes) — dropping a TakeUe's reply answers None.
                Some(_) => continue,
                None => panic!("target link closed"),
            }
        };
        assert_eq!(
            ngap::handover_request_params(&ho_request),
            Some((
                amf_ue_id,
                1,
                nh1,
                vec![(5, 1, std::net::Ipv4Addr::new(127, 0, 0, 1))],
                b"s2t".to_vec()
            ))
        );

        // The source association's select loop (simulated): owns the context,
        // services TakeUe, and captures forwarded PDUs (the Handover Command).
        let src_captured: std::sync::Arc<StdMutex<Vec<(NGAP_PDU, &'static str)>>> =
            std::sync::Arc::new(StdMutex::new(Vec::new()));
        let src_captured_w = src_captured.clone();
        tokio::spawn(async move {
            let mut ues = src_ues;
            while let Some(cmd) = src_rx.recv().await {
                match cmd {
                    UeCmd::TakeUe { amf_ue_id, reply } => {
                        let dls = on_take_ue(&mut ues, amf_ue_id, reply);
                        src_captured_w.lock().unwrap().extend(dls);
                    }
                    UeCmd::Forward { pdu, label } => {
                        src_captured_w.lock().unwrap().push((*pdu, label));
                    }
                    _ => {}
                }
            }
        });

        // 2. The target acknowledges: its DL F-TEID plus a DL FORWARDING F-TEID
        // for the in-flight data → Handover Command to the source.
        let ack = ngap::handover_request_acknowledge(
            amf_ue_id,
            9,
            &[(
                5,
                0xAA,
                std::net::Ipv4Addr::new(10, 0, 9, 5),
                Some((0xBB, std::net::Ipv4Addr::new(10, 0, 9, 6))),
            )],
            b"t2s".to_vec(),
        );
        on_handover_request_ack(&amf_smf, &ack).await;
        let mut command_seen = false;
        for _ in 0..50 {
            {
                let captured = src_captured.lock().unwrap();
                if let Some((pdu, _)) = captured.iter().find(|(_, l)| *l == "HandoverCommand") {
                    assert_eq!(
                        ngap::handover_command_params(pdu),
                        Some((
                            amf_ue_id,
                            4,
                            vec![(5, 0xBB, std::net::Ipv4Addr::new(10, 0, 9, 6))],
                            b"t2s".to_vec()
                        )),
                        "old RAN-UE-NGAP-ID, the target's forwarding F-TEID, and its container"
                    );
                    command_seen = true;
                }
            }
            if command_seen {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(command_seen, "Handover Command reached the source association");

        // 3. The UE arrives: Handover Notify on the TARGET association.
        let notify = ngap::handover_notify(amf_ue_id, 9, "999", "70", &[0, 0, 2]);
        let mut tgt_ues = HashMap::new();
        on_handover_notify(&mut tgt_ues, &amf_smf, &notify, &tgt_tx).await;

        // The context moved: target RAN-UE-ID, new TAC, the rotated NH chain.
        let moved = tgt_ues.get(&amf_ue_id).expect("context taken over");
        assert_eq!(moved.ran_ue_id, 9);
        assert_eq!(moved.tac, Some([0, 0, 2]));
        assert_eq!(moved.nh_chain, Some((nh1, 1)));
        // The UPF downlink re-pointed to the target's admitted DL F-TEID.
        assert_eq!(
            HO_SWITCHES.lock().unwrap().as_slice(),
            [("000000aa".to_string(), "10.0.9.5".to_string())]
        );
        // The source association released its gNB (successful handover, old RAN-UE 4).
        let released = src_captured.lock().unwrap();
        let release = released
            .iter()
            .find(|(_, l)| *l == "UEContextReleaseCommand (successful handover)")
            .expect("source released");
        assert_eq!(ngap::parse_ue_context_release_command(&release.0), Some((amf_ue_id, 4, None)));
        // The SBI callback directory re-points to the target association.
        let (_, dir_tx) = UE_DIRECTORY.lock().unwrap().get(supi).cloned().expect("directory");
        assert!(dir_tx.same_channel(&tgt_tx));
        assert!(HANDOVERS.lock().unwrap().get(&amf_ue_id).is_none(), "handover consumed");
        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// The N2-handover failure paths: an unknown target fails the preparation, a
    /// target rejection fails it back to the source, a source cancel releases the
    /// target's prepared context, and the TNGRELOCprep / TNGRELOCoverall expiries
    /// clean up abandoned handovers.
    #[tokio::test]
    async fn n2_handover_failure_paths_clean_up() {
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");
        let kamf = [0xa1u8; 32];
        let kgnb0 = aka::kgnb(&kamf, 0);
        let (src_tx, mut src_rx) = tokio::sync::mpsc::unbounded_channel();
        let (tgt_tx, mut tgt_rx) = tokio::sync::mpsc::unbounded_channel();
        GNB_LINKS
            .lock()
            .unwrap()
            .push(GnbLink { tacs: Vec::new(), gnb_id: Some(0x88), tx: tgt_tx.clone() });

        let seed_ctx = |ues: &mut HashMap<u64, UeContext>, id: u64| {
            let mut ctx = UeContext::new(4, RegState::Registered, Some(format!("imsi-99970{id}")));
            ctx.kamf = Some(kamf);
            ctx.nh_chain = Some((kgnb0, 0));
            ues.insert(id, ctx);
        };
        // Pull the next Forward off a link, skipping foreign broadcasts.
        async fn next_forward(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<UeCmd>,
        ) -> (NGAP_PDU, &'static str) {
            loop {
                match rx.recv().await {
                    Some(UeCmd::Forward { pdu, label }) => return (*pdu, label),
                    Some(_) => continue,
                    None => panic!("link closed"),
                }
            }
        }

        // (a) Unknown target gNB → immediate preparation failure to the source.
        let mut ues = HashMap::new();
        seed_ctx(&mut ues, 0x1a1);
        let required =
            ngap::handover_required(0x1a1, 4, 0xEE, "999", "70", &[0, 0, 1], &[5], false, vec![]);
        let (fail, _) =
            on_handover_required(&mut ues, &amf_smf, &required, &src_tx).await.expect("failed");
        assert_eq!(
            ngap::handover_preparation_failure_params(&fail),
            Some((0x1a1, 4, Some(ngap::CauseRadioNetwork::UNKNOWN_TARGET_ID)))
        );
        assert!(HANDOVERS.lock().unwrap().get(&0x1a1).is_none());

        // (b) The target rejects (Handover Failure) → the source gets a
        // preparation failure and the in-flight entry is dropped.
        let required =
            ngap::handover_required(0x1a1, 4, 0x88, "999", "70", &[0, 0, 1], &[], false, vec![]);
        assert!(on_handover_required(&mut ues, &amf_smf, &required, &src_tx).await.is_none());
        let _ = next_forward(&mut tgt_rx).await; // the HandoverRequest
        on_handover_failure(&ngap::handover_failure(
            0x1a1,
            ngap::CauseRadioNetwork::HO_TARGET_NOT_ALLOWED,
        ));
        let (fail, label) = next_forward(&mut src_rx).await;
        assert_eq!(label, "HandoverPreparationFailure (target rejected)");
        assert_eq!(
            ngap::handover_preparation_failure_params(&fail),
            Some((0x1a1, 4, Some(ngap::CauseRadioNetwork::HO_TARGET_NOT_ALLOWED)))
        );
        assert!(HANDOVERS.lock().unwrap().get(&0x1a1).is_none());

        // (c) A source cancel after the target acknowledged: the target's prepared
        // context is released and the source gets a Cancel Acknowledge.
        let required =
            ngap::handover_required(0x1a1, 4, 0x88, "999", "70", &[0, 0, 1], &[], false, vec![]);
        assert!(on_handover_required(&mut ues, &amf_smf, &required, &src_tx).await.is_none());
        let _ = next_forward(&mut tgt_rx).await; // the HandoverRequest
        on_handover_request_ack(&amf_smf, &ngap::handover_request_acknowledge(0x1a1, 9, &[], vec![])).await;
        let _ = next_forward(&mut src_rx).await; // the HandoverCommand
        let (ack, _) = on_handover_cancel(&amf_smf, &ngap::handover_cancel(
            0x1a1,
            4,
            ngap::CauseRadioNetwork::HANDOVER_CANCELLED,
        ))
        .await
        .expect("acknowledged");
        assert_eq!(ngap::handover_cancel_ack_params(&ack), Some((0x1a1, 4)));
        let (release, label) = next_forward(&mut tgt_rx).await;
        assert_eq!(label, "UEContextReleaseCommand (handover cancelled)");
        assert_eq!(ngap::parse_ue_context_release_command(&release), Some((0x1a1, 9, None)));
        assert_eq!(
            ngap::release_command_radio_cause(&release),
            Some(ngap::CauseRadioNetwork::HANDOVER_CANCELLED)
        );
        assert!(HANDOVERS.lock().unwrap().get(&0x1a1).is_none());

        // (d) TNGRELOCprep expiry: an unanswered preparation fails to the source.
        let required =
            ngap::handover_required(0x1a1, 4, 0x88, "999", "70", &[0, 0, 1], &[], false, vec![]);
        assert!(on_handover_required(&mut ues, &amf_smf, &required, &src_tx).await.is_none());
        let _ = next_forward(&mut tgt_rx).await;
        expire_handover_prep(0x1a1, std::time::Duration::from_millis(20)).await;
        let (fail, label) = next_forward(&mut src_rx).await;
        assert_eq!(label, "HandoverPreparationFailure (TNGRELOCprep expiry)");
        assert_eq!(
            ngap::handover_preparation_failure_params(&fail),
            Some((0x1a1, 4, Some(ngap::CauseRadioNetwork::TNGRELOCPREP_EXPIRY)))
        );
        assert!(HANDOVERS.lock().unwrap().get(&0x1a1).is_none());

        // (e) TNGRELOCoverall expiry: a commanded handover whose UE never arrives
        // is dropped and the target's prepared context released.
        let required =
            ngap::handover_required(0x1a1, 4, 0x88, "999", "70", &[0, 0, 1], &[], false, vec![]);
        assert!(on_handover_required(&mut ues, &amf_smf, &required, &src_tx).await.is_none());
        let _ = next_forward(&mut tgt_rx).await;
        on_handover_request_ack(&amf_smf, &ngap::handover_request_acknowledge(0x1a1, 9, &[], vec![])).await;
        let _ = next_forward(&mut src_rx).await; // the HandoverCommand
        // Prep expiry does nothing once commanded.
        expire_handover_prep(0x1a1, std::time::Duration::from_millis(10)).await;
        assert!(HANDOVERS.lock().unwrap().get(&0x1a1).is_some(), "commanded — prep expiry no-op");
        expire_handover_overall(0x1a1, amf_smf.clone(), std::time::Duration::from_millis(20)).await;
        let (release, label) = next_forward(&mut tgt_rx).await;
        assert_eq!(label, "UEContextReleaseCommand (TNGRELOCoverall expiry)");
        assert_eq!(
            ngap::release_command_radio_cause(&release),
            Some(ngap::CauseRadioNetwork::TNGRELOCOVERALL_EXPIRY)
        );
        assert!(HANDOVERS.lock().unwrap().get(&0x1a1).is_none());
    }

    /// Cross-association takeover: the PathSwitchRequest arrives on the TARGET
    /// gNB's association while the UE context lives with the SOURCE's. The target
    /// pulls the context over (UeCmd::TakeUe), the source association releases its
    /// gNB's stale side (UEContextReleaseCommand, cause successful-handover), and
    /// the SBI callback directory re-points to the target association.
    #[tokio::test]
    async fn path_switch_takes_over_the_ue_and_releases_the_source() {
        use std::sync::Mutex as StdMutex;

        // Mock SMF for the downlink re-point.
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            axum::routing::post(|| async { axum::http::StatusCode::OK }),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        // The SOURCE association: its select loop (simulated) owns the UE context
        // and services TakeUe; its release downlinks are captured.
        let kamf = [0x81u8; 32];
        let kgnb0 = aka::kgnb(&kamf, 0);
        let amf_ue_id = 0x181u64;
        let supi = "imsi-999700000000181";
        let mut ctx = UeContext::new(4, RegState::Registered, Some(supi.into()));
        ctx.kamf = Some(kamf);
        ctx.nh_chain = Some((kgnb0, 0));
        ctx.sm_refs.insert(5, ("ctx-ho5".into(), format!("http://{smf_addr}")));
        let (src_tx, mut src_rx) = tokio::sync::mpsc::unbounded_channel();
        let src_released: std::sync::Arc<StdMutex<Vec<(NGAP_PDU, &'static str)>>> =
            std::sync::Arc::new(StdMutex::new(Vec::new()));
        let src_released_w = src_released.clone();
        tokio::spawn(async move {
            let mut src_ues = HashMap::new();
            src_ues.insert(amf_ue_id, ctx);
            while let Some(cmd) = src_rx.recv().await {
                if let UeCmd::TakeUe { amf_ue_id, reply } = cmd {
                    let dls = on_take_ue(&mut src_ues, amf_ue_id, reply);
                    src_released_w.lock().unwrap().extend(dls);
                }
            }
        });
        // The TARGET association: registered too (skipped by the same_channel
        // filter), with an empty UE map.
        let (tgt_tx, _tgt_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let mut links = GNB_LINKS.lock().unwrap();
            links.push(GnbLink { tacs: Vec::new(), gnb_id: None, tx: src_tx.clone() });
            links.push(GnbLink { tacs: Vec::new(), gnb_id: None, tx: tgt_tx.clone() });
        }
        // The SBI callback surface currently reaches the UE via the source.
        UE_DIRECTORY.lock().unwrap().insert(supi.into(), (amf_ue_id, src_tx.clone()));

        // The path switch lands on the TARGET association.
        let req = ngap::path_switch_request(
            amf_ue_id,
            9,
            "999",
            "70",
            &[0, 0, 2],
            &[0x20, 0x20],
            &[(5, 0x99, std::net::Ipv4Addr::new(10, 0, 9, 4))],
        );
        let mut tgt_ues = HashMap::new();
        let (ack, _) =
            on_path_switch(&mut tgt_ues, &amf_smf, &req, &tgt_tx).await.expect("acknowledged");

        // The context moved to the target association and was switched there.
        let moved = tgt_ues.get(&amf_ue_id).expect("context taken over");
        assert_eq!(moved.ran_ue_id, 9);
        assert_eq!(moved.nh_chain, Some((aka::nh(&kamf, &kgnb0), 1)));
        assert_eq!(
            ngap::path_switch_ack_security(&ack),
            Some((1, aka::nh(&kamf, &kgnb0), vec![5]))
        );
        // The source association released its gNB's stale UE context.
        let released = src_released.lock().unwrap();
        assert_eq!(released.len(), 1, "one release toward the source gNB");
        let (release_pdu, label) = &released[0];
        assert_eq!(*label, "UEContextReleaseCommand (successful handover)");
        assert_eq!(
            ngap::parse_ue_context_release_command(release_pdu),
            Some((amf_ue_id, 4, None)),
            "addressed by the OLD RAN-UE-NGAP-ID"
        );
        assert_eq!(
            ngap::release_command_radio_cause(release_pdu),
            Some(ngap::CauseRadioNetwork::SUCCESSFUL_HANDOVER)
        );
        // The SBI callback directory re-points to the target association.
        let (dir_id, dir_tx) = UE_DIRECTORY.lock().unwrap().get(supi).cloned().expect("directory");
        assert_eq!(dir_id, amf_ue_id);
        assert!(dir_tx.same_channel(&tgt_tx), "callbacks now reach the target association");
        assert!(!dir_tx.same_channel(&src_tx));
        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// Initial Context Setup (TS 38.413 §8.3.1): on Security Mode Complete the AMF
    /// establishes the UE context at the gNB with ONE InitialContextSetupRequest —
    /// K_gNB (derived from K_AMF + the SM Complete's uplink NAS COUNT), the UE's
    /// security capabilities, the AM policy outputs (UE-AMBR / RFSP / mobility
    /// restriction), and the protected Registration Accept as its NAS-PDU.
    #[tokio::test]
    async fn security_mode_complete_triggers_initial_context_setup() {
        let (ki, ke) = ([0xddu8; 16], [0xeeu8; 16]);
        let kamf = [0x77u8; 32];
        let amf_ue_id = 0x161u64;
        let mut ctx = UeContext::new(8, RegState::SecurityMode, Some("imsi-999700000000161".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.kamf = Some(kamf);
        ctx.replayed_ue_sec_cap = Some([0x20, 0x20]);
        ctx.rfsp = Some(7);
        // A UE-AMBR already known (subscribed); the failed re-fetch below must keep it.
        ctx.subscribed_ue_ambr = Some((600_000_000, 300_000_000));
        ctx.area_restriction = Some((vec![[0, 0, 1]], Vec::new()));
        ctx.registration_area = vec![[0, 0, 1], [0, 0, 2]];

        // The UE sends the Security Mode Complete; the AMF verifies it (this is
        // what advances the uplink NAS COUNT the K_gNB derivation uses).
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let smc = ue_sec.protect(&nas::security_mode_complete(), nas::sht::INTEGRITY_CIPHERED, 0);
        assert!(ctx.sec.as_mut().unwrap().unprotect(&smc, 0).is_some());
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);

        // Bogus NRF base: am-data fetch + AM policy creation fail gracefully.
        let dls = on_security_mode_complete(&mut ues, amf_ue_id, "http://127.0.0.1:1").await;
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["InitialContextSetupRequest (RegistrationAccept)"]
        );
        let (got_amf, got_ran, ic) =
            ngap::initial_context_setup_params(&dls[0].0).expect("ICS parses");
        assert_eq!((got_amf, got_ran), (amf_ue_id, 8));
        // K_gNB = KDF(K_AMF, UL NAS COUNT of the SM Complete = 0).
        assert_eq!(ic.security_key, aka::kgnb(&kamf, 0));
        // The NH chain is seeded from the delivered K_gNB (NCC 0).
        assert_eq!(ues.get(&amf_ue_id).unwrap().nh_chain, Some((ic.security_key, 0)));
        assert_eq!(ic.ue_sec_cap, [0x20, 0x20], "capabilities replayed to the RAN");
        assert_eq!(ic.ue_ambr, Some((600_000_000, 300_000_000)));
        assert_eq!(ic.rfsp, Some(7));
        assert_eq!(ic.area_restriction, Some((vec![[0, 0, 1]], Vec::new())));
        // The gNB relays the NAS-PDU; the UE verifies the Registration Accept and
        // reads its registration area.
        let accept = ue_sec.unprotect(&ic.nas, 1).expect("UE verifies the accept");
        assert_eq!(nas::gmm_message_type(&accept), Some(nas::Nas5gmmMessageType::RegistrationAccept));
        assert_eq!(
            nas::registration_area_from_registration_accept(&accept),
            Some(vec![[0, 0, 1], [0, 0, 2]])
        );
        GUTI_DIRECTORY.lock().unwrap().remove(&(amf_ue_id as u32));
    }

    /// The registration area assigned at registration: the serving gNB's Supported
    /// TA List ∪ the UE's TAI (no duplicate), capped at 16; an unregistered
    /// association (no NG Setup) yields just the UE's TAI.
    #[test]
    fn registration_area_combines_gnb_tas_and_ue_tai() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        GNB_LINKS
            .lock()
            .unwrap()
            .push(GnbLink { tacs: vec![[0, 0, 0x81], [0, 0, 0x82]], gnb_id: None, tx: tx.clone() });

        // gNB TAs + a new UE TAI.
        assert_eq!(
            registration_area_for(Some([0, 0, 0x83]), &tx),
            vec![[0, 0, 0x81], [0, 0, 0x82], [0, 0, 0x83]]
        );
        // The UE's TAI already served → no duplicate.
        assert_eq!(
            registration_area_for(Some([0, 0, 0x81]), &tx),
            vec![[0, 0, 0x81], [0, 0, 0x82]]
        );
        // An association with no GNB_LINKS entry (or no ULI) degrades gracefully.
        let (other, _rx2) = tokio::sync::mpsc::unbounded_channel();
        assert_eq!(registration_area_for(Some([0, 0, 0x84]), &other), vec![[0, 0, 0x84]]);
        assert_eq!(registration_area_for(None, &other), Vec::<[u8; 3]>::new());
    }

    /// T3513: the page is retransmitted until the UE resumes (the retained context
    /// is consumed) or the attempts exhaust — and stops early on a resume.
    #[tokio::test]
    async fn t3513_retransmits_until_resume_or_exhaust() {
        let tmsi = 0x0000_0141u32;
        let supi = "imsi-999700000000141";
        let ue_tac = [0u8, 0, 0x79]; // unique to this test
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        GNB_LINKS.lock().unwrap().push(GnbLink { tacs: vec![ue_tac], gnb_id: None, tx });
        let my_pages = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<UeCmd>| {
            let mut hits = 0;
            while let Ok(cmd) = rx.try_recv() {
                if matches!(cmd, UeCmd::Page { tmsi: t, .. } if t == tmsi) {
                    hits += 1;
                }
            }
            hits
        };

        // Never answered → exactly max_sends pages, context stays retained.
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.tac = Some(ue_tac);
        RETAINED.lock().unwrap().insert(tmsi, ctx);
        page_with_retx(supi.into(), tmsi, std::time::Duration::from_millis(20), 3).await;
        assert_eq!(my_pages(&mut rx), 3, "T3513 exhausted after max_sends attempts");
        assert!(RETAINED.lock().unwrap().contains_key(&tmsi), "context stays retained");

        // Answered after the first page → the loop stops early.
        let task = tokio::spawn(page_with_retx(
            supi.into(),
            tmsi,
            std::time::Duration::from_millis(20),
            5,
        ));
        loop {
            match rx.recv().await {
                Some(UeCmd::Page { tmsi: t, .. }) if t == tmsi => break,
                Some(_) => continue,
                None => panic!("link closed"),
            }
        }
        RETAINED.lock().unwrap().remove(&tmsi); // the Service Request consumed it
        task.await.unwrap();
        assert!(my_pages(&mut rx) <= 1, "paging stopped once the UE resumed");
    }

    /// An AM policy change for a CM-IDLE UE: the UpdateNotify is held in the
    /// retained context (202), the UE is paged, and the change is applied when the
    /// UE resumes with a Service Request — the resume downlinks carry the UE Context
    /// Modification (RFSP + UE-AMBR) and the Configuration Update Command with the
    /// new Mobility Restriction List.
    #[tokio::test]
    async fn am_policy_update_for_a_cm_idle_ue_pages_and_applies_on_resume() {
        let (ki, ke) = ([0x99u8; 16], [0xaau8; 16]);
        let supi = "imsi-999700000000121";
        let tmsi = 0x0000_0121u32;

        // A retained CM-IDLE context (no PDU sessions — the policy path is the point).
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.guti_tmsi = Some(tmsi);
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.kamf = Some([0x21u8; 32]);
        ctx.ue_ambr = Some((2_000_000_000, 1_000_000_000));
        RETAINED.lock().unwrap().insert(tmsi, ctx);

        // A mock gNB association link to observe the page (no NG Setup yet — an
        // empty TA list is still paged, fail-open).
        let (gnb_tx, mut gnb_rx) = tokio::sync::mpsc::unbounded_channel();
        GNB_LINKS.lock().unwrap().push(GnbLink { tacs: Vec::new(), gnb_id: None, tx: gnb_tx });

        // The PCF pushes the UpdateNotify while the UE is idle → 202 (held + paged).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(listener, namf_callback_router()).await.unwrap() });
        let client = sbi_core::h2c_client();
        let policy = serde_json::json!({
            "rfsp": 9,
            "ueAmbr": { "uplink": "111 Mbps", "downlink": "222 Mbps" },
            "servAreaRes": { "restrictionType": "ALLOWED_AREAS", "tacs": ["000003"] }
        });
        let status = client
            .post(format!("http://{addr}/npcf-callback/v1/am-policy-notify/{supi}"))
            .json(&policy)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 202, "held for the CM-IDLE UE");
        // The gNB link received a Page for this TMSI (tolerate pages broadcast by
        // parallel tests sharing the global registry).
        let mut paged = false;
        for _ in 0..10 {
            match gnb_rx.recv().await {
                Some(UeCmd::Page { tmsi: t, .. }) if t == tmsi => {
                    paged = true;
                    break;
                }
                Some(_) => continue,
                None => break,
            }
        }
        assert!(paged, "CM-IDLE UE paged for the policy change");
        // The change is held in the retained context (latest wins) — all three
        // attributes were present in the notify, so each is a `Set`.
        assert_eq!(
            RETAINED.lock().unwrap().get(&tmsi).unwrap().pending_am_policy,
            Some(PendingAmPolicy {
                ue_ambr: FieldUpdate::Set((222_000_000, 111_000_000)),
                rfsp: FieldUpdate::Set(9),
                area_restriction: FieldUpdate::Set((vec![[0, 0, 3]], Vec::new())),
            })
        );
        // A completely unknown UE still yields 404.
        let status = client
            .post(format!("http://{addr}/npcf-callback/v1/am-policy-notify/imsi-000"))
            .json(&policy)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404);

        // The UE answers the page with a protected Service Request; the resume
        // applies the held policy after the Service Accept.
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let sr = ue_sec.protect(
            &nas::decode_nas_5gs_message(&nas::service_request(1, 0, tmsi)).unwrap(),
            nas::sht::INTEGRITY_CIPHERED,
            0,
        );
        let pdu = ngap::initial_ue_message_with_stmsi(4, tmsi, sr);
        let init = as_initial_ue(&pdu);
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");
        let mut ues = HashMap::new();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let dls = on_service_request(&mut ues, &amf_smf, init, tmsi, &tx).await;

        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            [
                "InitialContextSetupRequest (ServiceAccept)",
                "UEContextModificationRequest (RFSP)",
                "DownlinkNASTransport (ConfigurationUpdateCommand)",
            ]
        );
        let (amf_ue_id, restored) = ues.iter().next().expect("context restored");
        assert_eq!(restored.ue_ambr, Some((222_000_000, 111_000_000)), "UE-AMBR applied");
        assert_eq!(restored.rfsp, Some(9), "RFSP applied");
        assert_eq!(restored.area_restriction, Some((vec![[0, 0, 3]], Vec::new())));
        assert_eq!(restored.pending_am_policy, None, "pending change consumed");
        // The RAN sees the new policy: RFSP + UE-AMBR in the UE Context
        // Modification, the service area on the CUC's transport.
        assert_eq!(
            ngap::ue_context_modification_params(&dls[1].0),
            Some((*amf_ue_id, 4, Some(9), Some((222_000_000, 111_000_000))))
        );
        assert_eq!(
            ngap::area_restriction_from_downlink_nas(&dls[2].0),
            Some((vec![[0, 0, 3]], Vec::new()))
        );
        // The UE verifies the Service Accept (the ICS NAS-PDU) then the
        // Configuration Update Command.
        let (_a, _r, ic) = ngap::initial_context_setup_params(&dls[0].0).expect("ICS parses");
        let accept = ue_sec.unprotect(&ic.nas, 1).expect("Service Accept");
        assert_eq!(nas::gmm_message_type(&accept), Some(nas::Nas5gmmMessageType::ServiceAccept));
        let cuc = ue_sec.unprotect(&downlink_nas_pdu(&dls[2].0).unwrap(), 1).expect("CUC");
        assert_eq!(
            nas::gmm_message_type(&cuc),
            Some(nas::Nas5gmmMessageType::ConfigurationUpdateCommand)
        );
        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// Service Request resume: a CM-IDLE UE (retained by 5G-TMSI) comes back with a
    /// protected Service Request; the AMF restores its context under a fresh
    /// AMF-UE-NGAP-ID, re-activates the PDU session at the SMF, and sends a Service
    /// Accept + N2 PDU Session Resource Setup — back to CM-CONNECTED.
    #[tokio::test]
    async fn service_request_resumes_a_cm_idle_ue() {
        use axum::http::StatusCode;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        // Mock SMF: an ACTIVATING UpdateSMContext returns the session's N2 info.
        static ACTIVATIONS: AtomicUsize = AtomicUsize::new(0);
        async fn mock_modify(
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::response::Response {
            use axum::response::IntoResponse;
            if body.get("upCnxState").and_then(|v| v.as_str()) == Some("ACTIVATING") {
                ACTIVATIONS.fetch_add(1, AtomicOrdering::Relaxed);
                return (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "upN3Teid": "00000001", "upN3Addr": "127.0.0.1", "ueIpv4Addr": "10.45.0.2"
                    })),
                )
                    .into_response();
            }
            StatusCode::OK.into_response()
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new().route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            axum::routing::post(mock_modify),
        );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        // A CM-IDLE UE retained by its 5G-TMSI, with a NAS security context + K_AMF
        // + one PDU session (as AN release would have left it).
        let (ki, ke) = ([0x55u8; 16], [0x66u8; 16]);
        let kamf = [0x91u8; 32];
        let supi = "imsi-999700000000091";
        let tmsi = 0x0000_0091u32;
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.guti_tmsi = Some(tmsi);
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.kamf = Some(kamf);
        ctx.sm_refs.insert(5, ("ctx-5".into(), format!("http://{smf_addr}")));
        RETAINED.lock().unwrap().insert(tmsi, ctx);

        // The UE builds a protected Service Request (its own security context).
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let sr = ue_sec.protect(
            &nas::decode_nas_5gs_message(&nas::service_request(1, 0, tmsi)).unwrap(),
            nas::sht::INTEGRITY_CIPHERED,
            0,
        );
        let pdu = ngap::initial_ue_message_with_stmsi(3, tmsi, sr);
        let init = as_initial_ue(&pdu);
        assert_eq!(ngap::fiveg_s_tmsi_from_initial_ue(init), Some(tmsi));

        let mut ues = HashMap::new();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let dls = on_service_request(&mut ues, &amf_smf, init, tmsi, &tx).await;

        // The AS context is re-established with a single Initial Context Setup
        // carrying a fresh K_gNB, the Service Accept as its NAS-PDU, and the
        // reactivated PDU session set up **inline** (no trailing setup message).
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["InitialContextSetupRequest (ServiceAccept)"]
        );
        assert_eq!(ACTIVATIONS.load(AtomicOrdering::Relaxed), 1, "SMF asked to re-activate the session");
        // The session rides the ICS with the UPF's UL N3 F-TEID (from the mock SMF).
        assert_eq!(
            ngap::initial_context_setup_request_session_ids(&dls[0].0),
            vec![(5, 1, std::net::Ipv4Addr::new(127, 0, 0, 1))]
        );
        // The context is restored into the association (CM-CONNECTED) and removed
        // from the retained store; the directory points at the new AMF-UE-NGAP-ID.
        assert!(RETAINED.lock().unwrap().get(&tmsi).is_none(), "retained context consumed");
        let (_id, restored) = ues.iter().next().expect("context restored into the association");
        assert_eq!(restored.cm_state, CmState::Connected);
        assert_eq!(restored.suci.as_deref(), Some(supi));
        assert_eq!(restored.sm_refs.len(), 1, "PDU session carried over");
        assert!(UE_DIRECTORY.lock().unwrap().contains_key(supi), "reachable again over N2");

        // The fresh K_gNB is bound to the Service Request's UL NAS COUNT (0), and
        // the NH chain is re-seeded from it.
        let (_a, _r, ic) = ngap::initial_context_setup_params(&dls[0].0).expect("ICS parses");
        assert_eq!(ic.security_key, aka::kgnb(&kamf, 0), "fresh K_gNB from the SR's UL NAS COUNT");
        assert_eq!(restored.nh_chain, Some((ic.security_key, 0)), "NH chain re-seeded");
        // The UE decodes the Service Accept (the ICS NAS-PDU) under its own context.
        let accept = ue_sec.unprotect(&ic.nas, 1).expect("UE verifies the Service Accept");
        assert_eq!(nas::gmm_message_type(&accept), Some(nas::Nas5gmmMessageType::ServiceAccept));

        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// A resuming UE whose Service Request carries a PDU Session Status IE listing
    /// only some of its sessions: the AMF releases the sessions the UE dropped, keeps
    /// (and reactivates) the rest, and advertises its reconciled active set back in
    /// the Service Accept's PDU Session Status IE.
    #[tokio::test]
    async fn service_request_reconciles_dropped_pdu_session() {
        use axum::http::StatusCode;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Mutex as StdMutex;

        static ACTIVATIONS: AtomicUsize = AtomicUsize::new(0);
        static RELEASED: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
        async fn mock_modify(
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::response::Response {
            use axum::response::IntoResponse;
            if body.get("upCnxState").and_then(|v| v.as_str()) == Some("ACTIVATING") {
                ACTIVATIONS.fetch_add(1, AtomicOrdering::Relaxed);
                return (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "upN3Teid": "00000001", "upN3Addr": "127.0.0.1", "ueIpv4Addr": "10.45.0.2"
                    })),
                )
                    .into_response();
            }
            StatusCode::OK.into_response()
        }
        async fn mock_release(
            axum::extract::Path(sm_ref): axum::extract::Path<String>,
        ) -> StatusCode {
            RELEASED.lock().unwrap().push(sm_ref);
            StatusCode::NO_CONTENT
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new()
            .route(
                "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
                axum::routing::post(mock_modify),
            )
            .route(
                "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/release",
                axum::routing::post(mock_release),
            );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        // A retained CM-IDLE UE with two PDU sessions (5, 6).
        let (ki, ke) = ([0x55u8; 16], [0x66u8; 16]);
        let kamf = [0x92u8; 32];
        let supi = "imsi-999700000000092";
        let tmsi = 0x0000_0092u32;
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.guti_tmsi = Some(tmsi);
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.kamf = Some(kamf);
        ctx.sm_refs.insert(5, ("ctx-5".into(), format!("http://{smf_addr}")));
        ctx.sm_refs.insert(6, ("ctx-6".into(), format!("http://{smf_addr}")));
        RETAINED.lock().unwrap().insert(tmsi, ctx);

        // The UE resumes with a Service Request whose PDU Session Status lists only
        // session 5 — it has locally released session 6.
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let sr = ue_sec.protect(
            &nas::decode_nas_5gs_message(&nas::service_request_with_pdu_status(1, 0, tmsi, &[5]))
                .unwrap(),
            nas::sht::INTEGRITY_CIPHERED,
            0,
        );
        let pdu = ngap::initial_ue_message_with_stmsi(3, tmsi, sr);
        let init = as_initial_ue(&pdu);

        let mut ues = HashMap::new();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let dls = on_service_request(&mut ues, &amf_smf, init, tmsi, &tx).await;

        // Session 6 (dropped by the UE) is released at the SMF; only session 5 is
        // reactivated and rides the ICS inline.
        assert_eq!(RELEASED.lock().unwrap().as_slice(), ["ctx-6".to_string()], "dropped session released");
        assert_eq!(ACTIVATIONS.load(AtomicOrdering::Relaxed), 1, "only the kept session reactivated");
        assert_eq!(
            ngap::initial_context_setup_request_session_ids(&dls[0].0),
            vec![(5, 1, std::net::Ipv4Addr::new(127, 0, 0, 1))]
        );
        let (_id, restored) = ues.iter().next().expect("context restored");
        assert_eq!(restored.sm_refs.keys().copied().collect::<Vec<_>>(), vec![5], "only session 5 kept");

        // The Service Accept advertises the reconciled active set (5) so the UE drops
        // anything else it still held.
        let (_a, _r, ic) = ngap::initial_context_setup_params(&dls[0].0).expect("ICS parses");
        let accept = ue_sec.unprotect(&ic.nas, 1).expect("UE verifies the Service Accept");
        assert_eq!(nas::pdu_session_status_from_accept(&accept), Some(vec![5]));

        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// The gNB's InitialContextSetupResponse for an ICS that set up sessions inline
    /// drives UpdateSMContext with each admitted session's gNB DL F-TEID (the
    /// downlink install), and releases each session the gNB rejected
    /// (PDUSessionResourceFailedToSetupListCxtRes) at the SMF, dropping it from the
    /// UE context.
    #[tokio::test]
    async fn ics_response_installs_inline_session_downlinks() {
        use std::sync::Mutex as StdMutex;

        static INSTALLED: StdMutex<Vec<(String, String)>> = StdMutex::new(Vec::new());
        static RELEASED: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
        async fn mock_modify(axum::Json(body): axum::Json<serde_json::Value>) -> axum::http::StatusCode {
            if let (Some(t), Some(a)) = (
                body.get("gnbN3Teid").and_then(|v| v.as_str()),
                body.get("gnbN3Addr").and_then(|v| v.as_str()),
            ) {
                INSTALLED.lock().unwrap().push((t.into(), a.into()));
            }
            axum::http::StatusCode::OK
        }
        async fn mock_release(
            axum::extract::Path(sm_ref): axum::extract::Path<String>,
        ) -> axum::http::StatusCode {
            RELEASED.lock().unwrap().push(sm_ref);
            axum::http::StatusCode::NO_CONTENT
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new()
            .route(
                "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
                axum::routing::post(mock_modify),
            )
            .route(
                "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/release",
                axum::routing::post(mock_release),
            );
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        let amf_ue_id = 0x231u64;
        let mut ctx = UeContext::new(3, RegState::Registered, Some("imsi-999700000000231".into()));
        ctx.sm_refs.insert(5, ("ctx-icsr".into(), format!("http://{smf_addr}")));
        ctx.sm_refs.insert(6, ("ctx-icsr-6".into(), format!("http://{smf_addr}")));
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);

        // The gNB admits PSI 5 (DL F-TEID 0xAB @ 10.0.1.2) and rejects PSI 6.
        let resp = ngap::initial_context_setup_response_with_results(
            amf_ue_id,
            3,
            &[(5, 0xAB, std::net::Ipv4Addr::new(10, 0, 1, 2))],
            &[(6, ngap::CauseRadioNetwork::MULTIPLE_PDU_SESSION_ID_INSTANCES)],
        );
        on_initial_context_setup_response(&mut ues, &amf_smf, &resp).await;
        assert_eq!(
            INSTALLED.lock().unwrap().as_slice(),
            [("000000ab".to_string(), "10.0.1.2".to_string())],
            "UpdateSMContext installed the admitted session's DL F-TEID"
        );
        assert_eq!(
            RELEASED.lock().unwrap().as_slice(),
            ["ctx-icsr-6".to_string()],
            "the rejected session was released at the SMF"
        );
        let refs = &ues[&amf_ue_id].sm_refs;
        assert!(refs.contains_key(&5), "admitted session kept");
        assert!(!refs.contains_key(&6), "rejected session dropped from the UE context");

        // A response with no inline sessions (registration ICS) installs/releases nothing.
        INSTALLED.lock().unwrap().clear();
        RELEASED.lock().unwrap().clear();
        on_initial_context_setup_response(
            &mut ues,
            &amf_smf,
            &ngap::initial_context_setup_response(amf_ue_id, 3),
        )
        .await;
        assert!(INSTALLED.lock().unwrap().is_empty());
        assert!(RELEASED.lock().unwrap().is_empty());
    }

    /// A network-initiated PDU session modification builds the N2 PDU Session
    /// Resource Modify (new session AMBR + flows) carrying a UE-decodable N1 PDU
    /// Session Modification Command.
    #[test]
    fn network_modification_signals_ran_and_ue() {
        let (ki, ke) = ([0x33u8; 16], [0x44u8; 16]);
        let mut ctx = UeContext::new(7, RegState::Registered, Some("imsi-999700000000001".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.sm_refs.insert(5, ("ctx-5".into(), "http://smf".into()));
        let mut ues = HashMap::new();
        ues.insert(1u64, ctx);

        // The SMF's re-authorized QoS, parsed as the callback surface would.
        let body = serde_json::json!({
            "pduSessionId": 5,
            "sessionAmbr": { "uplink": "50 Mbps", "downlink": "100 Mbps" },
            "qosFlows": [ { "qfi": 1, "fiveQi": 9 }, { "qfi": 2, "fiveQi": 1, "gbr": {
                "gfbrDl": "10 Mbps", "gfbrUl": "10 Mbps", "mfbrDl": "20 Mbps", "mfbrUl": "20 Mbps" } } ]
        });
        let (ngap_flows, nas_flows) = pdu_session::parse_qos_flows(&body);
        let m = ModifyPolicy {
            amf_ue_id: 1,
            psi: 5,
            ambr_nas: nas::session_ambr_from_bitrates("50 Mbps", "100 Mbps").unwrap(),
            session_ambr_dl_bps: 100_000_000,
            session_ambr_ul_bps: 50_000_000,
            ngap_flows,
            nas_flows,
            released_qfis: vec![3], // release QFI 3 toward the RAN/UE
        };
        let downlinks = on_network_modification(&mut ues, &m);
        assert_eq!(
            downlinks.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["PDUSessionResourceModifyRequest"]
        );

        // The N2 PDU decodes as a PDU Session Resource Modify...
        let back = NGAP_PDU::decode(&downlinks[0].0.encode().unwrap()).unwrap();
        assert_eq!(back.procedure_name(), "PDUSessionResourceModify");
        // ...and the UE verifies its embedded N1 PDU Session Modification Command (0xCB)
        // carrying a delete for the released QFI 3.
        let (psi, nas_bytes) = ngap::nas_pdu_from_modify_request(&back).expect("N1 in the modify");
        assert_eq!(psi, 5);
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let msg = ue_sec.unprotect(&nas_bytes, 1).expect("UE verifies the modification command");
        let (sm_psi, container) =
            nas::sm_container_from_dl_nas_transport(&msg).expect("N1 SM container");
        assert_eq!(sm_psi, 5);
        assert_eq!(container[3], 0xcb, "5GSM PDU Session Modification Command");
        assert!(container.windows(3).any(|w| w == [3, 0x40, 0x00]), "N1 deletes released QFI 3");

        // A psi the UE has no session for is a no-op.
        let m_bad = ModifyPolicy { psi: 9, ..m.clone() };
        assert!(on_network_modification(&mut ues, &m_bad).is_empty(), "no session for psi 9");
    }

    /// A Nudm_SDM data-change refreshes the UE's cached subscription view AND pushes
    /// it: a UE-AMBR change updates the RAN (UE Context Modification) and nudges the
    /// UE (Configuration Update Command); an NSSAI-only change nudges the UE; a no-op
    /// change / unknown UE signals nothing.
    #[tokio::test]
    async fn sdm_data_change_pushes_to_ran_and_ue() {
        let (ki, ke) = ([0x71u8; 16], [0x72u8; 16]);
        let amf_ue_id = 0x51u64;
        let mut ctx = UeContext::new(2, RegState::Registered, Some("imsi-999700000000051".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.rfsp = Some(5);
        ctx.ue_ambr = Some((1_000_000, 1_000_000));
        ctx.allowed_nssai = Some(vec![(1, Some([1, 2, 3]))]);
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        // A UE-AMBR + NSSAI change updates the stored view and pushes both signals.
        let dls = on_sdm_data_change(
            &mut ues,
            amf_ue_id,
            Some((2_000_000, 500_000)),
            Some(vec![(1, None), (2, None)]),
            &tx,
        );
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            [
                "UEContextModificationRequest (subscribed UE-AMBR)",
                "DownlinkNASTransport (ConfigurationUpdateCommand)"
            ]
        );
        assert_eq!(ues[&amf_ue_id].ue_ambr, Some((2_000_000, 500_000)));
        assert_eq!(ues[&amf_ue_id].allowed_nssai, Some(vec![(1, None), (2, None)]));
        // The RAN gets the new UE-AMBR (RFSP re-sent); the UE verifies the Config Update.
        let back = NGAP_PDU::decode(&dls[0].0.encode().unwrap()).unwrap();
        let (_a, _r, rfsp, ambr) = ngap::ue_context_modification_params(&back).unwrap();
        assert_eq!((rfsp, ambr), (Some(5), Some((2_000_000, 500_000))));
        let cuc = downlink_nas_pdu(&dls[1].0).expect("N1 in the DL NAS transport");
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let msg = ue_sec.unprotect(&cuc, 1).expect("UE verifies the Configuration Update Command");
        assert_eq!(nas::gmm_message_type(&msg), Some(nas::Nas5gmmMessageType::ConfigurationUpdateCommand));
        // The command carries the new allowed NSSAI inline; and — the previously-
        // allowed slice 1/010203 was dropped (a narrowing) — asks the UE to re-register.
        assert_eq!(
            nas::allowed_nssai_from_configuration_update_command(&msg),
            vec![(1, None), (2, None)]
        );
        assert!(nas::configuration_update_registration_requested(&msg), "narrowing → re-register");
        // An NSSAI-carrying command requests acknowledgement and is tracked for
        // retransmission under T3555 until the UE's Configuration Update Complete.
        assert!(nas::configuration_update_acknowledgement_requested(&msg), "ack requested");
        assert!(
            ues[&amf_ue_id].pending_config_update.is_some(),
            "the outstanding command is tracked (T3555 armed)"
        );
        assert_eq!(ues[&amf_ue_id].pending_config_update.as_ref().unwrap().attempts, 1);

        // A widening (slice 3 added, none removed) carries the new NSSAI but does NOT
        // request re-registration.
        let dls = on_sdm_data_change(
            &mut ues,
            amf_ue_id,
            Some((2_000_000, 500_000)),
            Some(vec![(1, None), (2, None), (3, None)]),
            &tx,
        );
        let cuc = downlink_nas_pdu(&dls[0].0).expect("N1 in the DL NAS transport");
        let msg = ue_sec.unprotect(&cuc, 1).expect("UE verifies the widening Config Update");
        assert_eq!(
            nas::allowed_nssai_from_configuration_update_command(&msg),
            vec![(1, None), (2, None), (3, None)]
        );
        assert!(!nas::configuration_update_registration_requested(&msg), "widening → no re-register");

        // A no-op change signals nothing; an unknown UE is a no-op.
        assert!(on_sdm_data_change(&mut ues, amf_ue_id, None, None, &tx).is_empty());
        assert!(on_sdm_data_change(&mut ues, 999, Some((1, 1)), None, &tx).is_empty());
    }

    /// A subscribed-NSSAI change that removes a slice releases the UE's PDU sessions
    /// on that (now-disallowed) slice; sessions on still-allowed slices are kept.
    #[tokio::test]
    async fn sdm_narrowing_releases_sessions_on_removed_slice() {
        let (ki, ke) = ([0x81u8; 16], [0x82u8; 16]);
        let amf_ue_id = 0x61u64;
        let mut ctx = UeContext::new(3, RegState::Registered, Some("imsi-999700000000061".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.allowed_nssai = Some(vec![(1, Some([1, 1, 1])), (2, Some([2, 2, 2]))]);
        ctx.sm_refs.insert(5, ("ctx-5".into(), "http://smf".into()));
        ctx.sm_refs.insert(6, ("ctx-6".into(), "http://smf".into()));
        ctx.session_snssai.insert(5, (1, Some([1, 1, 1])));
        ctx.session_snssai.insert(6, (2, Some([2, 2, 2])));
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        // Slice 2 removed from the allowed NSSAI → the session on slice 2 (psi 6) is
        // released; the UE is told (Config Update); psi 5 (slice 1) is untouched.
        let dls = on_sdm_data_change(
            &mut ues,
            amf_ue_id,
            None,
            Some(vec![(1, Some([1, 1, 1]))]),
            &tx,
        );
        let labels: Vec<_> = dls.iter().map(|(_, l)| *l).collect();
        assert!(labels.contains(&"DownlinkNASTransport (ConfigurationUpdateCommand)"));
        let rel: Vec<_> =
            dls.iter().filter(|(_, l)| *l == "PDUSessionResourceReleaseCommand").collect();
        assert_eq!(rel.len(), 1, "one release, for the removed-slice session");
        let back = NGAP_PDU::decode(&rel[0].0.encode().unwrap()).unwrap();
        assert_eq!(ngap::nas_pdu_from_release_command(&back).unwrap().0, 6, "psi 6 released");

        let ctx = &ues[&amf_ue_id];
        assert!(ctx.releasing.contains(&6), "session on the removed slice is releasing");
        assert!(!ctx.releasing.contains(&5), "session on a still-allowed slice kept");
        assert_eq!(ctx.allowed_nssai, Some(vec![(1, Some([1, 1, 1]))]));
    }

    /// The UE's Configuration Update Complete is recognised (acknowledged, no
    /// downlink) rather than falling through as an unhandled uplink NAS message — and
    /// it clears the outstanding command so T3555 stops retransmitting.
    #[tokio::test]
    async fn config_update_complete_is_recognised() {
        let amf_auth = auth::AmfAuth::new("http://127.0.0.1:1", "999", "70");
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");
        let amf_ue_id = 0x91u64;
        let mut ctx = UeContext::new(5, RegState::Registered, Some("imsi-999700000000091".into()));
        ctx.sec = Some(nas::NasSecurityContext::new([0x1u8; 16], [0x2u8; 16], NAS_NIA, NAS_NEA));
        // An outstanding acknowledgement-requested command is awaiting the ack.
        ctx.pending_config_update = Some(PendingConfigUpdate {
            cuc: nas::configuration_update_command_with_nssai(&[(1, None)], false, true),
            area_restriction: None,
            attempts: 2,
        });
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        let out = dispatch_uplink_nas(
            &mut ues,
            &amf_auth,
            &amf_smf,
            amf_ue_id,
            nas::configuration_update_complete(),
            &tx,
        )
        .await;
        assert!(out.is_none(), "acknowledged with no downlink");
        assert!(
            ues[&amf_ue_id].pending_config_update.is_none(),
            "the Complete cleared the outstanding command (T3555 stopped)"
        );
    }

    /// T3555: an acknowledgement-requested Configuration Update Command is
    /// retransmitted on each expiry (re-protected with a fresh NAS COUNT) up to
    /// T3555_MAX_SENDS; if the UE still never acknowledges, the exhausted procedure
    /// escalates to an implicit deregistration (the RAN context is released, ours
    /// dropped).
    #[tokio::test]
    async fn config_update_retransmits_then_deregisters() {
        let (ki, ke) = ([0x63u8; 16], [0x64u8; 16]);
        let amf_ue_id = 0x77u64;
        let mut ctx = UeContext::new(3, RegState::Registered, Some("imsi-999700000000077".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.pending_config_update = Some(PendingConfigUpdate {
            cuc: nas::configuration_update_command_with_nssai(&[(1, None), (2, None)], true, true),
            // A service area rides the command → each retransmission re-attaches the MRL.
            area_restriction: Some((vec![[0, 0, 5]], Vec::new())),
            attempts: 1, // the initial send already went out
        });
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);

        // Each expiry up to the cap retransmits the command; the UE decodes it and sees
        // the same allowed NSSAI + the re-registration/ack request.
        for attempt in 2..=T3555_MAX_SENDS {
            let dls = on_t3555_expiry(&mut ues, amf_ue_id, &tx);
            assert_eq!(dls.len(), 1, "retransmitted (attempt {attempt})");
            assert_eq!(dls[0].1, "DownlinkNASTransport (ConfigurationUpdateCommand)");
            let cuc = downlink_nas_pdu(&dls[0].0).expect("N1 in the DL NAS transport");
            let msg = ue_sec.unprotect(&cuc, 1).expect("UE verifies the retransmission");
            assert_eq!(
                nas::allowed_nssai_from_configuration_update_command(&msg),
                vec![(1, None), (2, None)]
            );
            assert!(nas::configuration_update_acknowledgement_requested(&msg));
            // The service area is re-attached to each retransmission's transport (MRL).
            assert_eq!(
                ngap::area_restriction_from_downlink_nas(&dls[0].0),
                Some((vec![[0, 0, 5]], Vec::new())),
                "MRL re-sent on the retransmission"
            );
            assert_eq!(ues[&amf_ue_id].pending_config_update.as_ref().unwrap().attempts, attempt);
        }
        // The cap is reached → the next expiry escalates: the UE is treated as
        // unreachable and implicitly deregistered — the RAN context is released and the
        // local context dropped, so it stops retransmitting forever.
        let dls = on_t3555_expiry(&mut ues, amf_ue_id, &tx);
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["UEContextReleaseCommand"],
            "give-up implicitly deregisters the UE (releases the RAN side)"
        );
        assert!(!ues.contains_key(&amf_ue_id), "local context dropped on give-up");
        // A stale expiry after the context is gone is a harmless no-op.
        assert!(on_t3555_expiry(&mut ues, amf_ue_id, &tx).is_empty());
    }

    /// A subscribed UE-AMBR change (Nudm_SDM) while a PCF AM-policy override is in
    /// effect: the subscribed value is stored but not signalled — the PCF override
    /// still governs the effective UE-AMBR.
    #[test]
    fn sdm_ambr_change_yields_to_pcf_override() {
        let (ki, ke) = ([0x91u8; 16], [0x92u8; 16]);
        let amf_ue_id = 0x71u64;
        let mut ctx = UeContext::new(2, RegState::Registered, Some("imsi-999700000000071".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.pcf_ue_ambr = Some((5_000_000, 5_000_000));
        ctx.subscribed_ue_ambr = Some((1_000_000, 1_000_000));
        ctx.recompute_ue_ambr();
        assert_eq!(ctx.ue_ambr, Some((5_000_000, 5_000_000)), "the PCF override wins");
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        // A new subscribed UE-AMBR: stored, but the effective (PCF) is unchanged so
        // nothing is signalled.
        let dls = on_sdm_data_change(&mut ues, amf_ue_id, Some((2_000_000, 800_000)), None, &tx);
        assert!(dls.is_empty(), "no re-signal while the PCF override governs");
        let ctx = &ues[&amf_ue_id];
        assert_eq!(ctx.subscribed_ue_ambr, Some((2_000_000, 800_000)), "subscribed value stored");
        assert_eq!(ctx.ue_ambr, Some((5_000_000, 5_000_000)), "effective still the PCF override");
    }

    /// Shared harness: a mock SMF whose `release` route records the finalised SM
    /// contexts into a per-test accumulator (State, not a static — the release
    /// tests run in parallel), plus an AmfSmf and the SMF base URL.
    async fn release_test_smf(
    ) -> (pdu_session::AmfSmf, String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::sync::{Arc, Mutex as StdMutex};
        type Released = Arc<StdMutex<Vec<String>>>;
        async fn mock_release(
            axum::extract::State(released): axum::extract::State<Released>,
            axum::extract::Path(sm_ref): axum::extract::Path<String>,
        ) -> axum::http::StatusCode {
            released.lock().unwrap().push(sm_ref);
            axum::http::StatusCode::NO_CONTENT
        }
        let released: Released = Arc::new(StdMutex::new(Vec::new()));
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = axum::Router::new()
            .route(
                "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/release",
                axum::routing::post(mock_release),
            )
            .with_state(released.clone());
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });
        (pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70"), format!("http://{smf_addr}"), released)
    }

    /// A network-initiated PDU session release: the AMF sends the N2 Release Command
    /// carrying a UE-decodable N1 Release Command; the gNB's Release Response frees
    /// the RAN side but the session is finalised at the SMF only when the UE's N1
    /// Release Complete arrives (TS 23.502 §4.3.4).
    #[tokio::test]
    async fn network_release_finalises_on_ue_complete() {
        let (amf_smf, smf_base, released) = release_test_smf().await;
        let (ki, ke) = ([0x33u8; 16], [0x44u8; 16]);
        let amf_ue_id = 0x7a1u64;
        let mut ctx = UeContext::new(9, RegState::Registered, Some("imsi-999700000000201".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.sm_refs.insert(5, ("ctx-5".into(), smf_base));
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();
        let amf_auth = auth::AmfAuth::new("http://127.0.0.1:1", "999", "70");

        // N2 Release Command built; the UE decodes the embedded N1 Release Command.
        let dls = on_network_release(&mut ues, amf_ue_id, &[5], nas::sm_cause::REGULAR_DEACTIVATION, &tx);
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["PDUSessionResourceReleaseCommand"]
        );
        let back = NGAP_PDU::decode(&dls[0].0.encode().unwrap()).unwrap();
        let (psi, nas_bytes) = ngap::nas_pdu_from_release_command(&back).expect("N1 in the release");
        assert_eq!(psi, 5);
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let msg = ue_sec.unprotect(&nas_bytes, 1).expect("UE verifies the Release Command");
        let (sm_psi, container) =
            nas::sm_container_from_dl_nas_transport(&msg).expect("N1 SM container");
        assert_eq!(sm_psi, 5);
        assert_eq!(&container[..], &[0x2e, 5, 0, 0xd3, nas::sm_cause::REGULAR_DEACTIVATION]);
        assert!(ues[&amf_ue_id].releasing.contains(&5), "release pending");

        // The gNB's Release Response frees the RAN side but does NOT finalise: the
        // session is still tracked at the SMF, awaiting the UE's complete.
        on_release_response(&ues, &ngap::pdu_session_resource_release_response(amf_ue_id, 9, 5));
        assert!(released.lock().unwrap().is_empty(), "not finalised on the N2 response");
        assert!(ues[&amf_ue_id].sm_refs.contains_key(&5), "session kept until the complete");

        // The UE's PDU Session Release Complete (over UL NAS) finalises it.
        let complete = nas::decode_nas_5gs_message(&nas::ul_nas_transport_sm(
            5,
            nas::pdu_session_release_complete(5, 0),
            None,
            None,
        ))
        .unwrap();
        let out =
            dispatch_uplink_nas(&mut ues, &amf_auth, &amf_smf, amf_ue_id, complete, &tx).await;
        assert!(out.is_none(), "release complete produces no downlink");
        assert_eq!(released.lock().unwrap().as_slice(), ["ctx-5".to_string()]);
        assert!(!ues[&amf_ue_id].sm_refs.contains_key(&5), "session dropped");
        assert!(!ues[&amf_ue_id].releasing.contains(&5), "no longer releasing");

        // A late guard-timer firing is idempotent — the session is already gone.
        finalize_release(&mut ues, &amf_smf, amf_ue_id, 5).await;
        assert_eq!(released.lock().unwrap().len(), 1, "no double release");

        // A release for a session the UE doesn't have is a no-op.
        assert!(on_network_release(&mut ues, amf_ue_id, &[9], 36, &tx).is_empty(), "no session for psi 9");
    }

    /// The release guard: if the UE never sends its Release Complete, the guard
    /// timer's expiry finalises the release at the SMF anyway (no stranded session).
    #[tokio::test]
    async fn network_release_guard_finalises_a_silent_ue() {
        let (amf_smf, smf_base, released) = release_test_smf().await;
        let amf_ue_id = 0x7b2u64;
        let mut ctx = UeContext::new(9, RegState::Registered, Some("imsi-999700000000202".into()));
        ctx.sec = Some(nas::NasSecurityContext::new([0x1u8; 16], [0x2u8; 16], NAS_NIA, NAS_NEA));
        ctx.sm_refs.insert(5, ("ctx-guard".into(), smf_base));
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        on_network_release(&mut ues, amf_ue_id, &[5], nas::sm_cause::REGULAR_DEACTIVATION, &tx);
        on_release_response(&ues, &ngap::pdu_session_resource_release_response(amf_ue_id, 9, 5));
        assert!(released.lock().unwrap().is_empty(), "still pending, no complete yet");

        // The guard fires (what UeCmd::ReleaseGuardExpiry's arm invokes).
        finalize_release(&mut ues, &amf_smf, amf_ue_id, 5).await;
        assert_eq!(released.lock().unwrap().as_slice(), ["ctx-guard".to_string()]);
        assert!(!ues[&amf_ue_id].sm_refs.contains_key(&5), "session finalised by the guard");
    }

    /// One release request naming multiple sessions fans out to a per-session N2
    /// Release Command (each carrying its own N1); every session finalises
    /// independently on its own N1 complete.
    #[tokio::test]
    async fn multi_session_release_fans_out_per_session() {
        let (amf_smf, smf_base, released) = release_test_smf().await;
        let (ki, ke) = ([0x5u8; 16], [0x6u8; 16]);
        let amf_ue_id = 0x9c3u64;
        let mut ctx = UeContext::new(4, RegState::Registered, Some("imsi-999700000000205".into()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.sm_refs.insert(5, ("ctx-m5".into(), smf_base.clone()));
        ctx.sm_refs.insert(6, ("ctx-m6".into(), smf_base));
        let mut ues = HashMap::new();
        ues.insert(amf_ue_id, ctx);
        let (tx, _rx) = unbounded_channel::<UeCmd>();

        // Release both sessions in one call → one N2 Release Command per session,
        // each targeting a distinct PSI, both marked releasing.
        let dls = on_network_release(&mut ues, amf_ue_id, &[5, 6], nas::sm_cause::REGULAR_DEACTIVATION, &tx);
        assert_eq!(dls.len(), 2, "one N2 Release Command per session");
        let mut psis: Vec<u8> = dls
            .iter()
            .map(|(pdu, _)| {
                let back = NGAP_PDU::decode(&pdu.encode().unwrap()).unwrap();
                ngap::nas_pdu_from_release_command(&back).unwrap().0
            })
            .collect();
        psis.sort_unstable();
        assert_eq!(psis, vec![5, 6]);
        assert!(
            ues[&amf_ue_id].releasing.contains(&5) && ues[&amf_ue_id].releasing.contains(&6),
            "both sessions releasing"
        );

        // Each session finalises independently on its own N1 Release Complete.
        let amf_auth = auth::AmfAuth::new("http://127.0.0.1:1", "999", "70");
        for psi in [5u8, 6] {
            let complete = nas::decode_nas_5gs_message(&nas::ul_nas_transport_sm(
                psi,
                nas::pdu_session_release_complete(psi, 0),
                None,
                None,
            ))
            .unwrap();
            dispatch_uplink_nas(&mut ues, &amf_auth, &amf_smf, amf_ue_id, complete, &tx).await;
        }
        let mut done = released.lock().unwrap().clone();
        done.sort();
        assert_eq!(done, vec!["ctx-m5".to_string(), "ctx-m6".to_string()]);
        assert!(ues[&amf_ue_id].sm_refs.is_empty(), "both sessions dropped");
        assert!(ues[&amf_ue_id].releasing.is_empty(), "nothing left releasing");
    }

    /// A network-initiated release for a CM-IDLE UE: no N2 to signal, so the AMF
    /// releases the retained session at the SMF now and drops it from the retained
    /// context — the UE is told on its next return by PDU Session Status
    /// reconciliation (design/90).
    #[tokio::test]
    async fn cm_idle_pdu_session_release() {
        let (_amf_smf, smf_base, released) = release_test_smf().await;

        // A retained CM-IDLE UE with two sessions (not in UE_DIRECTORY).
        let supi = "imsi-999700000000193";
        let tmsi = 0x0000_00C1u32;
        let mut ctx = UeContext::new(0, RegState::Registered, Some(supi.into()));
        ctx.cm_state = CmState::Idle;
        ctx.guti_tmsi = Some(tmsi);
        ctx.sm_refs.insert(5, ("ctx-idle-5".into(), smf_base.clone()));
        ctx.sm_refs.insert(6, ("ctx-idle-6".into(), smf_base));
        RETAINED.lock().unwrap().insert(tmsi, ctx);

        // The AMF's callback surface; the SMF asks to release session 5.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(listener, namf_callback_router()).await.unwrap() });
        let client = sbi_core::h2c_client();
        let status = client
            .post(format!("http://{addr}/namf-comm/v1/ue-contexts/{supi}/release"))
            .json(&serde_json::json!({ "pduSessionId": 5 }))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 202, "CM-IDLE release accepted");

        // Session 5 released at the SMF and dropped from the retained context; 6 kept.
        assert_eq!(released.lock().unwrap().as_slice(), ["ctx-idle-5".to_string()]);
        {
            let retained = RETAINED.lock().unwrap();
            let sm_refs = &retained.get(&tmsi).unwrap().sm_refs;
            assert!(!sm_refs.contains_key(&5), "released session dropped");
            assert!(sm_refs.contains_key(&6), "other session kept");
        }

        // A multi-session request (`pduSessionIds`) releasing the remaining session 6
        // (and an unheld 9) → 202; session 6 finalised, 9 skipped.
        let status = client
            .post(format!("http://{addr}/namf-comm/v1/ue-contexts/{supi}/release"))
            .json(&serde_json::json!({ "pduSessionIds": [6, 9] }))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 202, "multi-session CM-IDLE release accepted");
        {
            let mut done = released.lock().unwrap().clone();
            done.sort();
            assert_eq!(done, vec!["ctx-idle-5".to_string(), "ctx-idle-6".to_string()]);
            assert!(RETAINED.lock().unwrap().get(&tmsi).unwrap().sm_refs.is_empty(), "all sessions gone");
        }

        // A release naming only sessions the UE doesn't hold → 404.
        let status = client
            .post(format!("http://{addr}/namf-comm/v1/ue-contexts/{supi}/release"))
            .json(&serde_json::json!({ "pduSessionId": 9 }))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404);

        RETAINED.lock().unwrap().remove(&tmsi);
    }

    /// A subscription-withdrawal callback reaches the UE's association; the
    /// network-initiated deregistration waits on T3522 and completes when the
    /// UE's Deregistration Accept arrives.
    #[tokio::test]
    async fn subscription_withdrawal_deregisters_the_ue() {
        // Directory entry wired to a test channel (as serve_gnb would).
        let supi = "imsi-999700000000042";
        let (tx, mut rx) = unbounded_channel::<UeCmd>();
        UE_DIRECTORY.lock().unwrap().insert(supi.to_string(), (42, tx.clone()));

        // The callback surface turns the POST into a Start command.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(l, namf_callback_router()).await.unwrap() });
        let resp = sbi_core::h2c_client()
            .post(format!("http://{addr}/namf-callback/v1/{supi}/dereg-notify"))
            .json(&serde_json::json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 204);
        assert!(
            matches!(rx.recv().await, Some(UeCmd::Start(42))),
            "association told to deregister UE 42"
        );

        // Unknown SUPI → 404.
        let resp = sbi_core::h2c_client()
            .post(format!("http://{addr}/namf-callback/v1/imsi-000/dereg-notify"))
            .json(&serde_json::json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404);

        // Start: the request goes out, T3522 is armed, the contexts stay.
        let (ki, ke) = ([0x11u8; 16], [0x22u8; 16]);
        let mut ctx = UeContext::new(9, RegState::Registered, Some(supi.to_string()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        let mut ues = HashMap::new();
        ues.insert(42u64, ctx);
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70"); // no session → unused

        let downlinks = on_network_deregistration(&mut ues, &amf_smf, 42, &tx, 3600).await;
        assert_eq!(
            downlinks.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["DownlinkNASTransport (DeregistrationRequest)"],
            "no release yet — waiting on the accept"
        );
        assert_eq!(ues.get(&42).and_then(|c| c.dereg_attempts), Some(1), "context kept, armed");
        assert!(!UE_DIRECTORY.lock().unwrap().contains_key(supi), "directory entry dropped");
        // A duplicate Start is ignored while the procedure runs.
        assert!(on_network_deregistration(&mut ues, &amf_smf, 42, &tx, 3600).await.is_empty());
        // UE side: the request verifies and is the UE-terminated variant.
        let nas_bytes = downlink_nas_pdu(&downlinks[0].0).expect("NAS PDU");
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let msg = ue_sec.unprotect(&nas_bytes, 1).expect("UE verifies the request");
        assert_eq!(
            nas::gmm_message_type(&msg),
            Some(nas::Nas5gmmMessageType::DeregistrationRequestToUe)
        );

        // The UE's Deregistration Accept completes the procedure.
        let amf_auth = auth::AmfAuth::new("http://127.0.0.1:1", "999", "70");
        let done = dispatch_uplink_nas(
            &mut ues,
            &amf_auth,
            &amf_smf,
            42,
            nas::deregistration_accept_to_ue(),
            &tx,
        )
        .await
        .expect("a release to send");
        assert_eq!(done.1, "UEContextReleaseCommand");
        assert_eq!(
            ngap::parse_ue_context_release_command(&done.0),
            Some((42, 9, Some(ngap::CauseNas::DEREGISTER)))
        );
        assert!(!ues.contains_key(&42), "AMF context dropped on accept");

        // A stale T3522 expiry after completion is a no-op.
        assert!(on_t3522_expiry(&mut ues, 42, &tx, 3600).is_empty());
    }

    /// A UE that never answers: T3522 retransmits the request, then aborts and
    /// releases the contexts anyway.
    #[tokio::test]
    async fn t3522_retransmits_then_aborts() {
        let supi = "imsi-999700000000043";
        let (tx, mut rx) = unbounded_channel::<UeCmd>();
        let (ki, ke) = ([0x11u8; 16], [0x22u8; 16]);
        let mut ctx = UeContext::new(11, RegState::Registered, Some(supi.to_string()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        let mut ues = HashMap::new();
        ues.insert(43u64, ctx);
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70");

        // Start with an instant timer: the expiry lands on the channel.
        let downlinks = on_network_deregistration(&mut ues, &amf_smf, 43, &tx, 0).await;
        assert_eq!(downlinks.len(), 1, "initial request");
        assert!(matches!(rx.recv().await, Some(UeCmd::T3522Expiry(43))), "T3522 fired");

        // Expiries 2..=T3522_MAX_SENDS retransmit; the next one aborts.
        for attempt in 2..=T3522_MAX_SENDS {
            let dls = on_t3522_expiry(&mut ues, 43, &tx, 3600);
            assert_eq!(
                dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
                ["DownlinkNASTransport (DeregistrationRequest)"],
                "retransmission {attempt}"
            );
            assert_eq!(ues.get(&43).and_then(|c| c.dereg_attempts), Some(attempt));
        }
        let dls = on_t3522_expiry(&mut ues, 43, &tx, 3600);
        assert_eq!(
            dls.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["UEContextReleaseCommand"],
            "exhausted — abort releases the RAN side"
        );
        assert!(!ues.contains_key(&43), "context dropped on abort");
    }

    /// A UE whose requested slices are all unsubscribed is rejected at registration
    /// with 5GMM cause #62 (rejected NSSAI attached) and its context is released.
    #[tokio::test]
    async fn unsubscribed_slices_reject_registration_with_cause_62() {
        use subscriber_db::{DataSet, ProvisionedDataStore, SubscriberStore};

        let supi = "imsi-999700000000001";

        // NRF + UDR (am-data: subscribed slice 1/010203 only) + NRF-registered UDM.
        let store = std::sync::Arc::new(subscriber_db::InMemoryStore::new());
        store
            .put_provisioned(
                DataSet::Am,
                supi,
                "99970",
                &serde_json::json!({ "nssai": { "defaultSingleNssais": [{ "sst": 1, "sd": "010203" }] } }),
            )
            .unwrap();
        let store: std::sync::Arc<dyn SubscriberStore> = store;
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udr_l, sbi_core::nudr::router(store)).await.unwrap() });

        let udr = std::sync::Arc::new(sbi_core::nudr::UdrClient::new(format!("http://{udr_addr}")));
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udm_l, sbi_core::nudm::router(udr)).await.unwrap() });

        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let nrf_store = sbi_core::nnrf::NrfStore::default();
        tokio::spawn(async move { sbi_core::run_on(nrf_l, sbi_core::nnrf::router(nrf_store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");
        let mut profile =
            sbi_core::nnrf::NfProfile::new("udm-1", "UDM", udm_addr.ip().to_string());
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

        // A secured UE context that requested only the unsubscribed slice 9.
        let (ki, ke) = ([0x11u8; 16], [0x22u8; 16]);
        let mut ctx = UeContext::new(7, RegState::SecurityMode, Some(supi.to_string()));
        ctx.sec = Some(nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA));
        ctx.requested_nssai = vec![(9, None)];
        let mut ues = HashMap::new();
        ues.insert(1u64, ctx);

        let downlinks = on_security_mode_complete(&mut ues, 1, &nrf_base).await;
        assert_eq!(
            downlinks.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            ["DownlinkNASTransport (RegistrationReject)", "UEContextReleaseCommand"],
            "the reject is followed by the gNB-side context release"
        );
        assert!(!ues.contains_key(&1), "UE context released after the reject");

        // The release command addresses the same UE pair with a NAS cause.
        assert_eq!(
            ngap::parse_ue_context_release_command(&downlinks[1].0),
            Some((1, 7, Some(ngap::CauseNas::NORMAL_RELEASE)))
        );

        // UE side: verify/decipher and check the cause + rejected NSSAI.
        let nas_bytes = downlink_nas_pdu(&downlinks[0].0).expect("NAS PDU in the downlink");
        let mut ue_sec = nas::NasSecurityContext::new(ki, ke, NAS_NIA, NAS_NEA);
        let msg = ue_sec.unprotect(&nas_bytes, 1).expect("UE verifies the reject");
        assert_eq!(
            nas::parse_registration_reject(&msg),
            Some((
                nas::mm_cause::NO_NETWORK_SLICES_AVAILABLE,
                vec![((9, None), nas::nssai_cause::NOT_AVAILABLE_IN_PLMN)],
                Some(nas::GprsTimer2::from_secs(REG_REJECT_BACKOFF_SECS).octet()),
            ))
        );
    }

    fn initial_ue_message(ran_ue_id: u32) -> NGAP_PDU {
        ngap::initial_ue_message_with_nas(ran_ue_id, registration_request())
    }

    fn as_initial_ue(pdu: &NGAP_PDU) -> &InitialUEMessage {
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
            panic!("expected InitiatingMessage");
        };
        let InitiatingMessageValue::Id_InitialUEMessage(msg) = value else {
            panic!("expected InitialUEMessage");
        };
        msg
    }

    fn as_uplink(pdu: &NGAP_PDU) -> &UplinkNASTransport {
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
            panic!("expected InitiatingMessage");
        };
        let InitiatingMessageValue::Id_UplinkNASTransport(msg) = value else {
            panic!("expected UplinkNASTransport");
        };
        msg
    }

    fn test_subscriber() -> aka::SubscriberKey {
        aka::SubscriberKey {
            k: hex!("465b5ce8b199b49faa5f0a2ee238a6bc"),
            opc: hex!("cd63cb71954a9f4e48a5994e37a02baf"),
            amf: hex!("8000"),
        }
    }

    #[test]
    fn registration_with_suci_is_identified() {
        let mut ues = HashMap::new();
        let pdu = initial_ue_message(7);
        match on_initial_ue(&mut ues, as_initial_ue(&pdu), 100, &unbounded_channel().0) {
            Some(InitialUeOutcome::Identified { ran_ue_id, supi }) => {
                assert_eq!(ran_ue_id, 7);
                // The SUCI is deconcealed (null scheme) to an `imsi-<MCC><MNC>…` SUPI —
                // the form the UDM keys on — not left as a `suci-…` string.
                assert!(
                    supi.starts_with("imsi-99970"),
                    "SUCI should deconceal to an imsi- SUPI with MCC 999 / MNC 70, got: {supi}"
                );
            }
            _ => panic!("expected Identified"),
        }
        assert_eq!(ues.get(&100).unwrap().state, RegState::Identified);
    }

    #[test]
    fn unidentified_initial_ue_needs_identity() {
        let mut ues = HashMap::new();
        let pdu = ngap::initial_ue_message_with_nas(8, nas::identity_request_suci());
        match on_initial_ue(&mut ues, as_initial_ue(&pdu), 200, &unbounded_channel().0) {
            Some(InitialUeOutcome::NeedIdentity(dl)) => {
                assert_eq!(dl.procedure_name(), "DownlinkNASTransport");
            }
            _ => panic!("expected NeedIdentity"),
        }
        assert_eq!(ues.get(&200).unwrap().state, RegState::IdentityRequested);
    }

    #[test]
    fn uplink_correlates_by_amf_ue_id() {
        let mut ues = HashMap::new();
        on_initial_ue(&mut ues, as_initial_ue(&initial_ue_message(7)), 100, &unbounded_channel().0);
        let known = ngap::uplink_nas_transport(100, 7, registration_request());
        assert_eq!(uplink_amf_ue_id(as_uplink(&known)), Some(100));
        assert!(ues.contains_key(&100));
        let unknown = ngap::uplink_nas_transport(999, 7, registration_request());
        assert_eq!(uplink_amf_ue_id(as_uplink(&unknown)), Some(999));
        assert!(!ues.contains_key(&999));
    }

    /// Spin an NRF + UDR (with `supi` provisioned) + UDM + AUSF (NRF-registered)
    /// — the backend a real authentication run needs. Returns the NRF base URL.
    async fn spin_auth_backend(supi: &str, sub: aka::SubscriberKey) -> String {
        use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, NrfClient, NrfStore};

        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        tokio::spawn(async move {
            sbi_core::run_on(nrf_l, sbi_core::nnrf::router(NrfStore::default())).await.unwrap()
        });

        let udr_store = std::sync::Arc::new(subscriber_db::InMemoryStore::new());
        udr_store.provision(supi, sub);
        let udr_store: std::sync::Arc<dyn subscriber_db::SubscriberStore> = udr_store;
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udr_l, sbi_core::nudr::router(udr_store)).await.unwrap() });

        let udr_client = std::sync::Arc::new(sbi_core::nudr::UdrClient::new(format!("http://{udr_addr}")));
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udm_l, sbi_core::nudm::router(udr_client)).await.unwrap() });

        let ausf_state = sbi_core::nausf::AusfState::new(format!("http://{udm_addr}"));
        let ausf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ausf_addr = ausf_l.local_addr().unwrap();
        tokio::spawn(async move {
            sbi_core::run_on(ausf_l, sbi_core::nausf::router(ausf_state)).await.unwrap()
        });

        let mut profile = NfProfile::new("ausf-1", "AUSF", ausf_addr.ip().to_string());
        profile.nf_services = Some(vec![NfService {
            service_instance_id: "nausf-auth-1".into(),
            service_name: "nausf-auth".into(),
            scheme: "http".into(),
            ip_end_points: vec![IpEndPoint {
                ipv4_address: Some(ausf_addr.ip().to_string()),
                port: Some(ausf_addr.port()),
            }],
        }]);
        NrfClient::new(format!("http://{nrf_addr}")).register(&profile).await.unwrap();
        format!("http://{nrf_addr}")
    }

    /// A returning UE registers with the 5G-GUTI a previous Registration Accept
    /// assigned: the AMF resolves it from the GUTI directory — no Identity
    /// Request round trip — and re-authenticates. An unknown GUTI (e.g. lost on
    /// an AMF restart) falls back to the Identity Request.
    #[test]
    fn guti_reregistration_resolves_without_identity_request() {
        // A SUPI no other test touches (UE_DIRECTORY / GUTI_DIRECTORY are
        // process-wide statics shared across parallel tests).
        let supi = "imsi-999700000000052";
        GUTI_DIRECTORY.lock().unwrap().insert(0x4252, supi.to_string());

        // Known GUTI → identified straight away, caps/NSSAI captured.
        let mut ues = HashMap::new();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let pdu = ngap::initial_ue_message_with_nas(
            8,
            nas::registration_request_with_guti("999", "70", 0x4252, &[0x20, 0x20]),
        );
        match on_initial_ue(&mut ues, as_initial_ue(&pdu), 500, &tx) {
            Some(InitialUeOutcome::Identified { supi: got, .. }) => assert_eq!(got, supi),
            other => panic!("expected Identified, got {other:?}"),
        }
        let ctx = ues.get(&500).unwrap();
        assert_eq!(ctx.state, RegState::Identified);
        assert_eq!(ctx.replayed_ue_sec_cap, Some([0x20, 0x20]));
        assert!(UE_DIRECTORY.lock().unwrap().contains_key(supi));

        // Unknown GUTI → Identity Request, with the caps kept for the resume.
        let pdu = ngap::initial_ue_message_with_nas(
            9,
            nas::registration_request_with_guti("999", "70", 0xDEAD_BEEF, &[0x20, 0x20]),
        );
        match on_initial_ue(&mut ues, as_initial_ue(&pdu), 501, &tx) {
            Some(InitialUeOutcome::NeedIdentity(dl)) => {
                let req = nas::decode_nas_5gs_message(&downlink_nas_pdu(&dl).unwrap()).unwrap();
                assert_eq!(
                    nas::gmm_message_type(&req),
                    Some(nas::Nas5gmmMessageType::IdentityRequest)
                );
            }
            other => panic!("expected NeedIdentity, got {other:?}"),
        }
        let ctx = ues.get(&501).unwrap();
        assert_eq!(ctx.state, RegState::IdentityRequested);
        assert_eq!(ctx.replayed_ue_sec_cap, Some([0x20, 0x20]), "caps kept for the resume");

        GUTI_DIRECTORY.lock().unwrap().remove(&0x4252);
        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// The Identity Response resumes a paused registration: the AMF deconceals
    /// the SUCI and answers with the Authentication Request (previously the
    /// response was silently dropped — a dead end).
    #[tokio::test]
    async fn identity_response_resumes_registration_at_authentication() {
        // A SUPI no other test touches: UE_DIRECTORY / GUTI_DIRECTORY are
        // process-wide statics shared across parallel tests.
        let supi = "imsi-999700000000031";
        let nrf_base = spin_auth_backend(supi, test_subscriber()).await;
        let amf_auth = auth::AmfAuth::new(nrf_base, "999", "70");
        let amf_smf = pdu_session::AmfSmf::new("http://127.0.0.1:1", "999", "70"); // unused

        // A UE parked on the Identity Request (e.g. after an unknown GUTI).
        let mut ues = HashMap::new();
        ues.insert(600u64, UeContext::new(77, RegState::IdentityRequested, None));
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let resp =
            nas::decode_nas_5gs_message(&nas::identity_response_suci("999", "70", "0000000031"))
                .unwrap();
        let (dl, label) = dispatch_uplink_nas(&mut ues, &amf_auth, &amf_smf, 600, resp, &tx)
            .await
            .expect("a downlink to send");
        assert_eq!(label, "DownlinkNASTransport (AuthenticationRequest)");
        let auth_req = nas::decode_nas_5gs_message(&downlink_nas_pdu(&dl).unwrap()).unwrap();
        assert!(nas::parse_authentication_request(&downlink_nas_pdu(&dl).unwrap()).is_some());
        assert_eq!(
            nas::gmm_message_type(&auth_req),
            Some(nas::Nas5gmmMessageType::AuthenticationRequest)
        );
        let ctx = ues.get(&600).unwrap();
        assert_eq!(ctx.state, RegState::Authenticating);
        assert_eq!(ctx.suci.as_deref(), Some(supi));
        assert!(ctx.auth.is_some(), "pending AKA challenge stored");
        assert!(UE_DIRECTORY.lock().unwrap().contains_key(supi));

        // An Identity Response outside the IdentityRequested state is refused.
        let resp =
            nas::decode_nas_5gs_message(&nas::identity_response_suci("999", "70", "0000000031"))
                .unwrap();
        assert!(
            dispatch_uplink_nas(&mut ues, &amf_auth, &amf_smf, 600, resp, &tx).await.is_none(),
            "unexpected Identity Response ignored"
        );

        UE_DIRECTORY.lock().unwrap().remove(supi);
    }

    /// SQN resync: a UE whose USIM is ahead answers the challenge with an
    /// Authentication Failure (#21) carrying an AUTS; the AMF re-runs
    /// Nausf_UEAuthentication with it (AUSF→UDM→UDR/ARPF adopt the SQN) and the
    /// **fresh** challenge authenticates end to end.
    #[tokio::test]
    async fn resync_recovers_from_a_synch_failure() {
        let supi = "imsi-999700000000061";
        let sub = test_subscriber();
        let nrf_base = spin_auth_backend(supi, sub.clone()).await;
        let amf_auth = auth::AmfAuth::new(nrf_base, "999", "70");

        // First challenge; the UE's USIM is far ahead → it returns an AUTS for its
        // own SQN instead of a RES*.
        let (pending1, req1) = amf_auth.begin(supi).await.unwrap();
        let (rand1, _autn1) = nas::parse_authentication_request(&req1).unwrap();
        let sqn_ms = [0, 0, 0, 0, 0xFF, 0x00];
        let auts = aka::compute_auts(&sub, &rand1, &sqn_ms);
        let failure = nas::decode_nas_5gs_message(&nas::authentication_failure_synch(&auts)).unwrap();
        let (cause, got_auts) = nas::authentication_failure_info(&failure).unwrap();
        assert_eq!(cause, nas::GMM_CAUSE_SYNCH_FAILURE);
        assert_eq!(got_auts.as_deref(), Some(&auts[..]));

        // Resync → a fresh challenge on the adopted SQN.
        let (pending2, req2) = amf_auth.resync(&pending1, supi, &auts).await.unwrap();
        let (rand2, autn2) = nas::parse_authentication_request(&req2).unwrap();
        assert_ne!(rand2, rand1, "a new challenge was issued");

        // The UE accepts the fresh AUTN (its SQN is now in range) and RES* confirms.
        let res_star = aka::ue_compute_res_star(&sub, &rand2, &autn2, "999", "70")
            .expect("resync'd AUTN verifies at the UE");
        let outcome = amf_auth.finish(&pending2, &res_star).await.unwrap();
        assert!(outcome.success, "authentication succeeds after resync");
        assert_eq!(outcome.supi.as_deref(), Some(supi));
    }

    /// A second synch failure is not retried (at most one resync per procedure):
    /// the registration aborts — the UE context is dropped and the gNB is told to
    /// release it. No network needed (the abort path never re-authenticates).
    #[tokio::test]
    async fn repeated_synch_failure_aborts() {
        let amf_auth = auth::AmfAuth::new("http://127.0.0.1:1", "999", "70");
        let mut ues = HashMap::new();
        let mut ctx = UeContext::new(88, RegState::Authenticating, Some("imsi-x".into()));
        ctx.resync_attempted = true; // a resync already happened for this UE
        ues.insert(700u64, ctx);

        let failure =
            nas::decode_nas_5gs_message(&nas::authentication_failure_synch(&[0u8; 14])).unwrap();
        let (_, label) = on_authentication_failure(&mut ues, &amf_auth, 700, &failure)
            .await
            .expect("a release command");
        assert_eq!(label, "UEContextReleaseCommand");
        assert!(!ues.contains_key(&700), "context dropped on abort");
    }

    #[test]
    fn algorithm_negotiation_picks_the_best_common() {
        // UE_SEC_CAP (EA0-2/IA0-2) → the AMF's top preference, 128-NEA2/128-NIA2.
        assert_eq!(select_algo(0xE0, &NEA_PRIORITY), Some(2));
        assert_eq!(select_algo(0xE0, &NIA_PRIORITY), Some(2));

        // A UE supporting only NEA1/NIA1 (bit 7 = 0x40) negotiates down to them.
        assert_eq!(select_algo(0x40, &NEA_PRIORITY), Some(1));
        assert_eq!(select_algo(0x40, &NIA_PRIORITY), Some(1));

        // A UE offering only null ciphering (NEA0, bit 8 = 0x80) gets NEA0…
        assert_eq!(select_algo(0x80, &NEA_PRIORITY), Some(0));
        // …but null integrity is never selected (NIA0 not in the priority list).
        assert_eq!(select_algo(0x80, &NIA_PRIORITY), None);

        // NEA3/NIA3 only (bit 5 = 0x10) is still supported, below 2 and 1.
        assert_eq!(select_algo(0x10, &NEA_PRIORITY), Some(3));
        assert_eq!(select_algo(0x10, &NIA_PRIORITY), Some(3));

        // The bit test itself: EA2 is 0x20, IA1 is 0x40.
        assert!(ue_supports_algo(0x20, 2) && !ue_supports_algo(0x20, 1));
    }

    /// End-to-end negotiation: a UE that supports only 128-NEA1/128-NIA1 gets those
    /// selected, and — because the NAS keys are algorithm-bound — a UE deriving keys
    /// with the *negotiated* algorithms verifies the Security Mode Command. With the
    /// old hardcoded NEA2/NIA2 this UE could never have completed security mode.
    #[tokio::test]
    async fn security_mode_uses_the_negotiated_algorithms() {
        let supi = "imsi-999700000000071";
        let sub = test_subscriber();
        let nrf_base = spin_auth_backend(supi, sub.clone()).await;
        let amf_auth = auth::AmfAuth::new(nrf_base, "999", "70");

        // Authenticate to obtain K_SEAF.
        let (pending, req) = amf_auth.begin(supi).await.unwrap();
        let (rand, autn) = nas::parse_authentication_request(&req).unwrap();
        let res_star = aka::ue_compute_res_star(&sub, &rand, &autn, "999", "70").unwrap();
        let kseaf_hex = amf_auth.finish(&pending, &res_star).await.unwrap().kseaf.unwrap();

        // The AMF negotiates against a UE advertising ONLY 128-NEA1/128-NIA1.
        let ue_cap = [0x40u8, 0x40u8];
        let (mut amf_sec, smc_bytes, nea, nia, _kamf) =
            establish_security(&kseaf_hex, supi, ue_cap).expect("establish security");
        assert_eq!((nea, nia), (1, 1), "negotiated down to NEA1/NIA1");

        // The UE derives NAS keys with the NEGOTIATED algorithms and verifies the SMC.
        let kseaf: [u8; 32] = hex::decode(&kseaf_hex).unwrap().try_into().unwrap();
        let keys = aka::nas_keys(&aka::kamf(&kseaf, supi, &ABBA), nea, nia);
        let mut ue_sec = nas::NasSecurityContext::new(keys.knas_int, keys.knas_enc, nia, nea);
        let smc = ue_sec.unprotect(&smc_bytes, 1).expect("UE verifies SMC under negotiated keys");
        assert_eq!(nas::gmm_message_type(&smc), Some(nas::Nas5gmmMessageType::SecurityModeCommand));

        // Keys derived with the WRONG (default NEA2/NIA2) algorithms cannot verify it —
        // proving the selection actually bound the keys.
        let wrong = aka::nas_keys(&aka::kamf(&kseaf, supi, &ABBA), 2, 2);
        let mut wrong_sec = nas::NasSecurityContext::new(wrong.knas_int, wrong.knas_enc, 2, 2);
        assert!(wrong_sec.unprotect(&smc_bytes, 1).is_none(), "NEA2/NIA2 keys reject the NEA1 SMC");

        // SMC Complete round-trips under the negotiated context.
        let up = ue_sec.protect(&nas::security_mode_complete(), nas::sht::INTEGRITY_CIPHERED, 0);
        assert!(amf_sec.unprotect(&up, 0).is_some(), "AMF verifies SMC Complete");
    }

    /// The payoff: authenticate, then complete registration with NAS security —
    /// SMC ⇄ SMC Complete, Registration Accept ⇄ Registration Complete.
    #[tokio::test]
    async fn full_registration_completes() {
        let supi = "imsi-999700000000001";
        let sub = test_subscriber();
        let nrf_base = spin_auth_backend(supi, sub.clone()).await;

        // ── Authentication ──
        let amf_auth = auth::AmfAuth::new(nrf_base, "999", "70");
        let (pending, nas_req) = amf_auth.begin(supi).await.unwrap();
        let (rand, autn) = nas::parse_authentication_request(&nas_req).unwrap();
        let res_star = aka::ue_compute_res_star(&sub, &rand, &autn, "999", "70").unwrap();
        let nas_resp = nas::authentication_response(&res_star);
        let res = nas::res_star_from_authentication_response(
            &nas::decode_nas_5gs_message(&nas_resp).unwrap(),
        )
        .unwrap()
        .to_vec();
        let outcome = amf_auth.finish(&pending, &res).await.unwrap();
        assert!(outcome.success);
        let kseaf_hex = outcome.kseaf.unwrap();

        // ── AMF derives NAS security + Security Mode Command ──
        let (mut amf_sec, smc_bytes, _, _, _kamf) =
            establish_security(&kseaf_hex, supi, UE_SEC_CAP).expect("establish security");

        // ── UE derives the same NAS keys and verifies the SMC ──
        let kseaf: [u8; 32] = hex::decode(&kseaf_hex).unwrap().try_into().unwrap();
        let kamf = aka::kamf(&kseaf, supi, &ABBA);
        let keys = aka::nas_keys(&kamf, NAS_NEA, NAS_NIA);
        let mut ue_sec = nas::NasSecurityContext::new(keys.knas_int, keys.knas_enc, NAS_NIA, NAS_NEA);
        let smc = ue_sec.unprotect(&smc_bytes, 1).expect("UE verifies SMC");
        assert_eq!(nas::gmm_message_type(&smc), Some(nas::Nas5gmmMessageType::SecurityModeCommand));

        // ── UE → Security Mode Complete; AMF verifies ──
        let up = ue_sec.protect(&nas::security_mode_complete(), nas::sht::INTEGRITY_CIPHERED, 0);
        let got = amf_sec.unprotect(&up, 0).expect("AMF verifies SMC Complete");
        assert_eq!(nas::gmm_message_type(&got), Some(nas::Nas5gmmMessageType::SecurityModeComplete));

        // ── AMF → Registration Accept (protected, with allowed + rejected NSSAIs);
        // UE decodes ──
        let allowed = [(1u8, Some([0x01, 0x02, 0x03]))];
        let rejected = [(5u8, None)];
        let dl = amf_sec.protect(
            &nas::registration_accept("999", "70", 1, &allowed, &rejected, T3512_SECS, &[], None),
            nas::sht::INTEGRITY_CIPHERED,
            1,
        );
        let accept = ue_sec.unprotect(&dl, 1).expect("UE decodes Registration Accept");
        assert_eq!(nas::gmm_message_type(&accept), Some(nas::Nas5gmmMessageType::RegistrationAccept));
        assert_eq!(nas::allowed_nssai_from_registration_accept(&accept), allowed.to_vec());
        assert_eq!(
            nas::rejected_nssai_from_registration_accept(&accept),
            vec![((5, None), nas::nssai_cause::NOT_AVAILABLE_IN_PLMN)]
        );

        // ── UE → Registration Complete; AMF verifies ──
        let up = ue_sec.protect(&nas::registration_complete(), nas::sht::INTEGRITY_CIPHERED, 0);
        let got = amf_sec.unprotect(&up, 0).expect("AMF verifies Registration Complete");
        assert_eq!(nas::gmm_message_type(&got), Some(nas::Nas5gmmMessageType::RegistrationComplete));
    }
}
