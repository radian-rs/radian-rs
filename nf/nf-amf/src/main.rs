//! AMF — Access and Mobility Management Function: **full registration slice**.
//!
//! Terminates N2 (NGAP/SCTP, TS 38.413) and drives a UE through a complete
//! registration, joining the N2 (binary) and SBI (JSON) planes:
//!
//! 1. `InitialUEMessage` → identify from the RegistrationRequest SUCI (or ask).
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
use std::sync::Arc;

use anyhow::Context;
use nas::{Nas5gmmMessage, Nas5gmmMessageType, Nas5gsMessage};
use ngap::{
    InitialUEMessage, InitialUEMessageProtocolIEs_EntryValue, InitiatingMessage,
    InitiatingMessageValue, NGAP_PDU, PDUSessionResourceSetupResponseProtocolIEs_EntryValue,
    SuccessfulOutcome, SuccessfulOutcomeValue, UplinkNASTransport,
    UplinkNASTransportProtocolIEs_EntryValue,
};
use sctp_rs::{
    ConnectedSocket, NotificationOrData, SendData, SendInfo, Socket, SocketToAssociation,
};
use tracing::{error, info, warn};

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
/// NRF the AMF uses to discover the AUSF.
const NRF_BASE: &str = "http://127.0.0.1:8000";

// NAS security parameters the AMF selects.
const NAS_NEA: u8 = 2; // 128-NEA2 (AES-CTR)
const NAS_NIA: u8 = 2; // 128-NIA2 (AES-CMAC)
const NGKSI: u8 = 0;
const ABBA: [u8; 2] = [0x00, 0x00];
/// Replayed UE security capabilities (advertises EA0-2 / IA0-2).
const UE_SEC_CAP: [u8; 2] = [0xE0, 0xE0];

/// Allocator for AMF-UE-NGAP-IDs (one per UE the AMF takes context of).
static NEXT_AMF_UE_ID: AtomicU64 = AtomicU64::new(1);

/// Where a UE is in the registration flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegState {
    IdentityRequested,
    Identified,
    Authenticating,
    SecurityMode,
    Registered,
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
    /// The UE's advertised 5GS security capabilities `[EA, IA]`, replayed verbatim in the
    /// Security Mode Command (TS 24.501 §8.2.25) so the UE can detect a bidding-down attack.
    replayed_ue_sec_cap: Option<[u8; 2]>,
    /// SM context ref of an in-progress PDU session, to address its UpdateSMContext.
    sm_ref: Option<String>,
    /// The allowed NSSAI granted at registration (from am-data). `None` = the fetch
    /// failed or hasn't happened — slice admission then falls back to the SMF's check.
    allowed_nssai: Option<Vec<(u8, Option<[u8; 3]>)>>,
    /// The NSSAI the UE requested in its Registration Request (empty = IE omitted).
    requested_nssai: Vec<(u8, Option<[u8; 3]>)>,
}

/// What an `InitialUEMessage` asks the AMF to do next.
enum InitialUeOutcome {
    NeedIdentity(NGAP_PDU),
    Identified { ran_ue_id: u32, supi: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("amf");

    let amf_auth = Arc::new(auth::AmfAuth::new(NRF_BASE, PLMN_MCC, PLMN_MNC));
    let amf_smf = Arc::new(pdu_session::AmfSmf::new(NRF_BASE, PLMN_MCC, PLMN_MNC));

    let addr: SocketAddr = format!("0.0.0.0:{N2_PORT}").parse()?;
    let socket = Socket::new_v4(SocketToAssociation::OneToOne).context("create SCTP socket")?;
    socket.bind(addr).context("bind N2 SCTP")?;
    let listener = socket.listen(64).context("listen N2 SCTP")?;
    info!(%addr, ppid = NGAP_PPID, nrf = NRF_BASE, "N2 (NGAP/SCTP) listener up");

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
    loop {
        match conn.sctp_recv().await? {
            NotificationOrData::Notification(n) => info!("SCTP notification: {n:?}"),
            NotificationOrData::Data(data) => {
                if data.payload.is_empty() {
                    info!("gNB association closed");
                    return Ok(());
                }
                handle_ngap(&conn, &mut ues, &amf_auth, &amf_smf, &data.payload).await;
            }
        }
    }
}

/// Decode one NGAP PDU and dispatch it.
async fn handle_ngap(
    conn: &ConnectedSocket,
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_smf: &pdu_session::AmfSmf,
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
                let resp = ngap::ng_setup_response(AMF_NAME, PLMN_MCC, PLMN_MNC);
                send_or_log(conn, &resp, "NGSetupResponse").await;
            }
            InitiatingMessageValue::Id_InitialUEMessage(msg) => {
                let amf_ue_id = NEXT_AMF_UE_ID.fetch_add(1, Ordering::Relaxed);
                match on_initial_ue(ues, msg, amf_ue_id) {
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
                for (dl, label) in on_uplink_nas(ues, amf_auth, amf_smf, msg).await {
                    send_or_log(conn, &dl, label).await;
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
        _ => info!("unhandled PDU: {}", pdu.procedure_name()),
    }
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
    let Some(sm_ref) = ues.get(&amf_ue_id).and_then(|c| c.sm_ref.clone()) else {
        warn!("UE {amf_ue_id}: setup response but no SM context is tracked");
        return;
    };
    match amf_smf.update_sm_context(&sm_ref, gnb_teid, gnb_addr).await {
        Ok(()) => info!("UE {amf_ue_id}: PDU session {psi} downlink installed (gNB F-TEID {gnb_teid:#x})"),
        Err(e) => warn!("UE {amf_ue_id}: UpdateSMContext failed: {e}"),
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
) -> Option<InitialUeOutcome> {
    let ran_ue_id = initial_ue_ran_id(msg)?;
    let identity = initial_ue_nas_pdu(msg)
        .and_then(|b| nas::decode_nas_5gs_message(b).ok())
        .and_then(registration_identity);

    match identity {
        Some((supi, ue_sec_cap, requested_nssai)) => {
            let mut ctx = UeContext::new(ran_ue_id, RegState::Identified, Some(supi.clone()));
            ctx.replayed_ue_sec_cap = ue_sec_cap;
            ctx.requested_nssai = requested_nssai;
            ues.insert(amf_ue_id, ctx);
            Some(InitialUeOutcome::Identified { ran_ue_id, supi })
        }
        None => {
            ues.insert(amf_ue_id, UeContext::new(ran_ue_id, RegState::IdentityRequested, None));
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
            replayed_ue_sec_cap: None,
            sm_ref: None,
            allowed_nssai: None,
            requested_nssai: Vec::new(),
        }
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

    // Security Mode Complete may answer with more than one downlink (a
    // Registration Reject followed by the UE Context Release Command).
    if nas::gmm_message_type(&nas_msg) == Some(Nas5gmmMessageType::SecurityModeComplete) {
        return on_security_mode_complete(ues, amf_ue_id, NRF_BASE).await;
    }
    dispatch_uplink_nas(ues, amf_auth, amf_smf, amf_ue_id, nas_msg).await.into_iter().collect()
}

/// Handle one verified uplink NAS message that answers with at most one downlink.
async fn dispatch_uplink_nas(
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_smf: &pdu_session::AmfSmf,
    amf_ue_id: u64,
    nas_msg: Nas5gsMessage,
) -> Option<(NGAP_PDU, &'static str)> {
    match nas::gmm_message_type(&nas_msg) {
        Some(Nas5gmmMessageType::AuthenticationResponse) => {
            let res_star = nas::res_star_from_authentication_response(&nas_msg)?.to_vec();
            complete_authentication(ues, amf_auth, amf_ue_id, &res_star).await
        }
        Some(Nas5gmmMessageType::RegistrationComplete) => {
            let ctx = ues.get_mut(&amf_ue_id)?;
            ctx.state = RegState::Registered;
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
        Some(Nas5gmmMessageType::UlNasTransport) => {
            // A UE PDU session request: CreateSMContext at the SMF (N4 establishment),
            // then send the N2 PDU Session Resource Setup to the gNB with the UPF's N3
            // F-TEID. The N1 SM container is opaque to the AMF (TS 29.502 multipart later).
            let Some((psi, container)) = nas::sm_container_from_ul_nas_transport(&nas_msg) else {
                warn!("UE {amf_ue_id}: UL NAS Transport without an SM container");
                return None;
            };
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

            match amf_smf.create_sm_context(&supi, psi, &dnn, snssai).await {
                Ok(created) => {
                    // Build the N1 PDU Session Establishment Accept (UE IP from the SMF,
                    // echoing the request's PTI) and NAS-protect a DL NAS Transport carrying
                    // it — the gNB relays that to the UE. The N2 SM info carries the UPF F-TEID.
                    // S-NSSAI and session AMBR come from the subscriber's UDR sm-data
                    // (looked up by the SMF during CreateSMContext); the DNN echoes
                    // the UE's authorized request.
                    let accept = nas::pdu_session_establishment_accept(
                        psi,
                        pti,
                        created.ue_ip,
                        &dnn,
                        created.snssai_sst,
                        created.snssai_sd,
                        created.ambr,
                    );
                    let dl = nas::dl_nas_transport_sm(psi, accept);
                    let Some(ctx) = ues.get_mut(&amf_ue_id) else { return None };
                    ctx.sm_ref = Some(created.sm_ref);
                    let Some(sec) = ctx.sec.as_mut() else {
                        warn!("UE {amf_ue_id}: PDU session before NAS security is established");
                        return None;
                    };
                    let nas_accept = sec.protect(&dl, nas::sht::INTEGRITY_CIPHERED, 1);
                    let setup = ngap::pdu_session_resource_setup_request(
                        amf_ue_id, ran_ue_id, psi, 1, created.up_n3_teid, created.up_n3_addr, nas_accept,
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
async fn complete_authentication(
    ues: &mut HashMap<u64, UeContext>,
    amf_auth: &auth::AmfAuth,
    amf_ue_id: u64,
    res_star: &[u8],
) -> Option<(NGAP_PDU, &'static str)> {
    let Some(pending) = ues.get_mut(&amf_ue_id).and_then(|c| c.auth.take()) else {
        warn!("UE {amf_ue_id}: Authentication Response with no pending authentication");
        return None;
    };
    let outcome = match amf_auth.finish(&pending, res_star).await {
        Ok(o) => o,
        Err(e) => {
            warn!("UE {amf_ue_id}: authentication confirm failed: {e}");
            return None;
        }
    };
    if !outcome.success {
        warn!("UE {amf_ue_id}: authentication failed (RES* rejected)");
        return None;
    }
    let (Some(kseaf), Some(supi)) = (outcome.kseaf, outcome.supi) else {
        warn!("UE {amf_ue_id}: authenticated but AUSF returned no K_SEAF/SUPI");
        return None;
    };

    info!("UE {amf_ue_id} authenticated ({supi}); establishing NAS security");
    // Replay the UE's own advertised capabilities (falling back to the AMF default if the
    // UE didn't send them) so the Security Mode Command passes the UE's bidding-down check.
    let replayed = ues
        .get(&amf_ue_id)
        .and_then(|c| c.replayed_ue_sec_cap)
        .unwrap_or(UE_SEC_CAP);
    let Some((sec, smc_bytes)) = establish_security(&kseaf, &supi, &replayed) else {
        warn!("UE {amf_ue_id}: failed to derive NAS security context");
        return None;
    };
    let ctx = ues.get_mut(&amf_ue_id)?;
    ctx.sec = Some(sec);
    ctx.state = RegState::SecurityMode;
    let ran_ue_id = ctx.ran_ue_id;
    Some((
        ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, smc_bytes),
        "DownlinkNASTransport (SecurityModeCommand)",
    ))
}

/// Derive K_AMF + NAS keys from K_SEAF and build the protected Security Mode Command,
/// replaying `replayed_ue_sec_cap` (the UE's advertised capabilities) back to the UE.
fn establish_security(
    kseaf_hex: &str,
    supi: &str,
    replayed_ue_sec_cap: &[u8],
) -> Option<(nas::NasSecurityContext, Vec<u8>)> {
    let kseaf: [u8; 32] = hex::decode(kseaf_hex).ok()?.try_into().ok()?;
    let kamf = aka::kamf(&kseaf, supi, &ABBA);
    let keys = aka::nas_keys(&kamf, NAS_NEA, NAS_NIA);
    let mut sec = nas::NasSecurityContext::new(keys.knas_int, keys.knas_enc, NAS_NIA, NAS_NEA);
    let smc = nas::security_mode_command(NAS_NEA, NAS_NIA, NGKSI, replayed_ue_sec_cap);
    let bytes = sec.protect(&smc, nas::sht::INTEGRITY_NEW_CONTEXT, 1);
    Some((sec, bytes))
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
    let subscribed = match &supi {
        Some(supi) => fetch_subscribed_nssai(nrf_base, supi).await,
        None => None,
    };

    let Some(ctx) = ues.get_mut(&amf_ue_id) else {
        return Vec::new();
    };
    let ran_ue_id = ctx.ran_ue_id;
    let tmsi = amf_ue_id as u32;
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
    let Some(sec) = ctx.sec.as_mut() else {
        return Vec::new();
    };
    let accept = nas::registration_accept(PLMN_MCC, PLMN_MNC, tmsi, &allowed, &rejected);
    let bytes = sec.protect(&accept, nas::sht::INTEGRITY_CIPHERED, 1);
    info!(
        "UE {amf_ue_id}: SecurityModeComplete — sending Registration Accept \
         (allowed NSSAI: {allowed:?}, rejected: {rejected:?})"
    );
    vec![(
        ngap::downlink_nas_transport(amf_ue_id, ran_ue_id, bytes),
        "DownlinkNASTransport (RegistrationAccept)",
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

/// Fetch the subscriber's subscribed NSSAI from am-data via the NRF-discovered UDM
/// (Nudm_SDM): the subscribed default S-NSSAIs (`nssai.defaultSingleNssais`).
/// `None` on any failure — registration proceeds without the IE (fail-open; the
/// SMF's subscription check still gates session establishment).
async fn fetch_subscribed_nssai(nrf_base: &str, supi: &str) -> Option<Vec<(u8, Option<[u8; 3]>)>> {
    let udm =
        discover_nf(nrf_base, "UDM").await.map_err(|e| warn!("UDM discovery failed: {e}")).ok()?;
    let plmn = format!("{PLMN_MCC}{PLMN_MNC}");
    let am = sbi_core::nudm::NudmClient::new(udm)
        .get_am_data(supi, &plmn)
        .await
        .map_err(|e| warn!("Nudm_SDM am-data fetch failed: {e}"))
        .ok()??;
    let slices: Vec<(u8, Option<[u8; 3]>)> = am
        .pointer("/nssai/defaultSingleNssais")?
        .as_array()?
        .iter()
        .filter_map(|s| {
            let sst = u8::try_from(s.get("sst")?.as_u64()?).ok()?;
            let sd = s
                .get("sd")
                .and_then(|v| v.as_str())
                .and_then(|sd| hex::decode(sd).ok())
                .and_then(|b| <[u8; 3]>::try_from(b).ok());
            Some((sst, sd))
        })
        .collect();
    (!slices.is_empty()).then_some(slices)
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

/// From a decoded NAS RegistrationRequest, extract the identity the AMF needs: the
/// **SUPI** (deconcealed from the SUCI, TS 33.501) and the UE's advertised 5GS security
/// capabilities `[EA, IA]` (to replay in the Security Mode Command).
fn registration_identity(
    msg: Nas5gsMessage,
) -> Option<(String, Option<[u8; 2]>, Vec<(u8, Option<[u8; 3]>)>)> {
    let requested_nssai = nas::requested_nssai_from_registration_request(&msg);
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = msg else {
        return None;
    };
    let supi = reg.fgs_mobile_identity.as_suci().map(|s| nas::suci_to_supi(&s))?;
    let ue_sec_cap = reg
        .ue_security_capability
        .as_ref()
        .map(|c| [c.ea_byte(), c.ia_byte()]);
    Some((supi, ue_sec_cap, requested_nssai))
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

    const REG_REQUEST_HEX: &str = "7e004179000d0199f9070000000000000010022e08a020000000000000";

    fn registration_request() -> Vec<u8> {
        hex::decode(REG_REQUEST_HEX).unwrap()
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
        match on_initial_ue(&mut ues, as_initial_ue(&pdu), 100) {
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
        match on_initial_ue(&mut ues, as_initial_ue(&pdu), 200) {
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
        on_initial_ue(&mut ues, as_initial_ue(&initial_ue_message(7)), 100);
        let known = ngap::uplink_nas_transport(100, 7, registration_request());
        assert_eq!(uplink_amf_ue_id(as_uplink(&known)), Some(100));
        assert!(ues.contains_key(&100));
        let unknown = ngap::uplink_nas_transport(999, 7, registration_request());
        assert_eq!(uplink_amf_ue_id(as_uplink(&unknown)), Some(999));
        assert!(!ues.contains_key(&999));
    }

    /// The payoff: authenticate, then complete registration with NAS security —
    /// SMC ⇄ SMC Complete, Registration Accept ⇄ Registration Complete.
    #[tokio::test]
    async fn full_registration_completes() {
        use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, NrfClient, NrfStore};

        let supi = "imsi-999700000000001";
        let sub = test_subscriber();

        // Spin NRF, UDR (with the subscriber), UDM (fronting the UDR), and AUSF
        // (pointed at the UDM).
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        tokio::spawn(async move {
            sbi_core::run_on(nrf_l, sbi_core::nnrf::router(NrfStore::default())).await.unwrap()
        });

        let udr_store = std::sync::Arc::new(subscriber_db::InMemoryStore::new());
        udr_store.provision(supi, sub.clone());
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

        // ── Authentication ──
        let amf_auth = auth::AmfAuth::new(format!("http://{nrf_addr}"), "999", "70");
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
        let (mut amf_sec, smc_bytes) =
            establish_security(&kseaf_hex, supi, &UE_SEC_CAP).expect("establish security");

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
            &nas::registration_accept("999", "70", 1, &allowed, &rejected),
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
