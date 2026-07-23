//! NGAP — NG Application Protocol (TS 38.413), the N2 control protocol between
//! the (R)AN and the AMF. Wire encoding is **ASN.1 APER** — the 5GC's only
//! mandatory ASN.1 surface (see `design/02`).
//!
//! This crate wraps [`oxirush_ngap`] (re-exported below) so the ASN.1 dependency
//! stays behind one crate boundary, and adds AMF-side message builders. Shared by
//! the AMF (full PDU set) and the SMF (the N2-SM-info `*Transfer` IE subset).

// Re-export the generated NGAP types (`NGAP_PDU`, IEs, …) and the ergonomic macros.
pub use oxirush_ngap::ngap::*;
pub use oxirush_ngap::{build_ngap, build_ngap_ie, extract_ngap_ies, helpers};

use oxirush_ngap::helpers::{guami, plmn, s_nssai};

use std::net::Ipv4Addr;

use asn1_codecs::aper::AperCodec;
use asn1_codecs::PerCodecData;
use bitvec::order::Msb0;
use bitvec::vec::BitVec;

/// Build an `NGSetupResponse` (TS 38.413 §9.2.6.2) for the given AMF name / PLMN.
///
/// Mandatory IEs: AMFName, ServedGUAMIList, RelativeAMFCapacity, PLMNSupportList.
/// A single GUAMI (region/set/pointer = 1/1/0) and a single S-NSSAI (SST=1) are
/// advertised — enough for a gNB to complete NG Setup.
pub fn ng_setup_response(amf_name: &str, mcc: &str, mnc: &str) -> NGAP_PDU {
    build_ngap!(SuccessfulOutcome, NGSetup,
        REJECT, NGSetupResponse,
        REJECT AMFName(amf_name.to_string()),
        REJECT ServedGUAMIList(vec![ServedGUAMIItem {
            guami: guami(plmn(mcc, mnc), 1, 1, 0),
            backup_amf_name: None,
            ie_extensions: None,
        }]),
        IGNORE RelativeAMFCapacity(255u8),
        REJECT PLMNSupportList(vec![PLMNSupportItem {
            plmn_identity: plmn(mcc, mnc),
            slice_support_list: SliceSupportList(vec![SliceSupportItem {
                s_nssai: s_nssai(1, None),
                ie_extensions: None,
            }]),
            ie_extensions: None,
        }]),
    )
}

/// Build a minimal `InitialUEMessage` carrying a NAS PDU.
///
/// For tests and a UE/gNB simulator — a real gNB includes the full mandatory IE
/// set (UserLocationInformation, RRCEstablishmentCause, …). Here we carry only the
/// RAN UE NGAP ID and the NAS payload, which is sufficient for codec round-trips.
pub fn initial_ue_message_with_nas(ran_ue_id: u32, nas: Vec<u8>) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, InitialUEMessage,
        IGNORE, InitialUEMessage,
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT NAS_PDU(nas),
    )
}

/// Build a `DownlinkNASTransport` (TS 38.413 §9.2.5.3) carrying a NAS PDU from the
/// AMF to the UE, addressed by the AMF-UE-NGAP-ID / RAN-UE-NGAP-ID pair.
pub fn downlink_nas_transport(amf_ue_id: u64, ran_ue_id: u32, nas: Vec<u8>) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, DownlinkNASTransport,
        IGNORE, DownlinkNASTransport,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT NAS_PDU(nas),
    )
}

/// Build a `DownlinkNASTransport` carrying both a NAS PDU **and a Mobility
/// Restriction List** (TS 38.413 §9.2.5.3) — the AMF's way of handing the RAN a UE's
/// **service area restriction** (allowed / non-allowed tracking areas, TS 23.501
/// §5.3.4.1) alongside a NAS message such as the Registration Accept. TACs are the
/// 3-octet tracking area codes; an empty allowed/non-allowed slice omits that IE.
pub fn downlink_nas_transport_with_area_restriction(
    amf_ue_id: u64,
    ran_ue_id: u32,
    nas: Vec<u8>,
    mcc: &str,
    mnc: &str,
    allowed_tacs: &[[u8; 3]],
    not_allowed_tacs: &[[u8; 3]],
) -> NGAP_PDU {
    let mrl = mobility_restriction_list(mcc, mnc, allowed_tacs, not_allowed_tacs);
    build_ngap!(InitiatingMessage, DownlinkNASTransport,
        IGNORE, DownlinkNASTransport,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT NAS_PDU(nas),
        IGNORE MobilityRestrictionList(mrl),
    )
}

/// A `MobilityRestrictionList` (TS 38.413 §9.3.1.85) whose Service Area
/// Information carries the allowed / non-allowed TACs of one PLMN — shared by the
/// DownlinkNASTransport and Initial Context Setup carriers.
fn mobility_restriction_list(
    mcc: &str,
    mnc: &str,
    allowed_tacs: &[[u8; 3]],
    not_allowed_tacs: &[[u8; 3]],
) -> MobilityRestrictionList {
    let to_tacs = |ts: &[[u8; 3]]| ts.iter().map(|t| TAC(t.to_vec())).collect::<Vec<_>>();
    let area = ServiceAreaInformation_Item {
        plmn_identity: helpers::plmn(mcc, mnc),
        allowed_ta_cs: (!allowed_tacs.is_empty()).then(|| AllowedTACs(to_tacs(allowed_tacs))),
        not_allowed_ta_cs: (!not_allowed_tacs.is_empty())
            .then(|| NotAllowedTACs(to_tacs(not_allowed_tacs))),
        ie_extensions: None,
    };
    MobilityRestrictionList {
        serving_plmn: helpers::plmn(mcc, mnc),
        equivalent_plm_ns: None,
        rat_restrictions: None,
        forbidden_area_information: None,
        service_area_information: Some(ServiceAreaInformation(vec![area])),
        ie_extensions: None,
    }
}

/// Extract `(allowed_tacs, non_allowed_tacs)` from the Mobility Restriction List of a
/// `DownlinkNASTransport` (first Service Area Information item) — the RAN side / tests.
/// `None` when the message carries no mobility restriction.
pub fn area_restriction_from_downlink_nas(pdu: &NGAP_PDU) -> Option<(Vec<[u8; 3]>, Vec<[u8; 3]>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_DownlinkNASTransport(msg) = value else {
        return None;
    };
    let mrl = msg.protocol_i_es.0.iter().find_map(|e| match &e.value {
        DownlinkNASTransportProtocolIEs_EntryValue::Id_MobilityRestrictionList(m) => Some(m),
        _ => None,
    })?;
    let item = mrl.service_area_information.as_ref()?.0.first()?;
    let collect = |tacs: &[TAC]| {
        tacs.iter().filter_map(|t| <[u8; 3]>::try_from(t.0.as_slice()).ok()).collect::<Vec<_>>()
    };
    let allowed = item.allowed_ta_cs.as_ref().map(|a| collect(&a.0)).unwrap_or_default();
    let not_allowed = item.not_allowed_ta_cs.as_ref().map(|a| collect(&a.0)).unwrap_or_default();
    Some((allowed, not_allowed))
}

/// Build an `UplinkNASTransport` (TS 38.413 §9.2.5.4) carrying a NAS PDU from the
/// gNB/UE to the AMF — primarily for tests and a UE/gNB simulator.
pub fn uplink_nas_transport(amf_ue_id: u64, ran_ue_id: u32, nas: Vec<u8>) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, UplinkNASTransport,
        IGNORE, UplinkNASTransport,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT NAS_PDU(nas),
    )
}

/// Build a `UEContextReleaseCommand` (TS 38.413 §9.2.2.4) addressed by the
/// AMF/RAN UE-NGAP-ID pair, with a NAS cause (pick from [`CauseNas`]'s
/// constants). The gNB releases its UE context and answers with a
/// UE Context Release Complete.
pub fn ue_context_release_command(amf_ue_id: u64, ran_ue_id: u32, nas_cause: u8) -> NGAP_PDU {
    let ids = UE_NGAP_IDs::UE_NGAP_ID_pair(UE_NGAP_ID_pair {
        amf_ue_ngap_id: AMF_UE_NGAP_ID(amf_ue_id),
        ran_ue_ngap_id: RAN_UE_NGAP_ID(ran_ue_id),
        ie_extensions: None,
    });
    build_ngap!(InitiatingMessage, UEContextRelease,
        REJECT, UEContextReleaseCommand,
        REJECT UE_NGAP_IDs(ids),
        IGNORE Cause(Cause::Nas(CauseNas(nas_cause))),
    )
}

/// Build a `UEContextReleaseCommand` with a **radio-network cause** (pick from
/// [`CauseRadioNetwork`]'s constants) — e.g. *successful-handover* toward the
/// source gNB after an Xn path switch completed.
pub fn ue_context_release_command_radio(
    amf_ue_id: u64,
    ran_ue_id: u32,
    radio_cause: u8,
) -> NGAP_PDU {
    let ids = UE_NGAP_IDs::UE_NGAP_ID_pair(UE_NGAP_ID_pair {
        amf_ue_ngap_id: AMF_UE_NGAP_ID(amf_ue_id),
        ran_ue_ngap_id: RAN_UE_NGAP_ID(ran_ue_id),
        ie_extensions: None,
    });
    build_ngap!(InitiatingMessage, UEContextRelease,
        REJECT, UEContextReleaseCommand,
        REJECT UE_NGAP_IDs(ids),
        IGNORE Cause(Cause::RadioNetwork(CauseRadioNetwork(radio_cause))),
    )
}

/// The radio-network cause of a `UEContextReleaseCommand`, when it carries one
/// (gNB side / tests).
pub fn release_command_radio_cause(pdu: &NGAP_PDU) -> Option<u8> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_UEContextRelease(cmd) = value else {
        return None;
    };
    cmd.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        UEContextReleaseCommandProtocolIEs_EntryValue::Id_Cause(Cause::RadioNetwork(c)) => {
            Some(c.0)
        }
        _ => None,
    })
}

/// Extract `(AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, NAS cause)` from a
/// UEContextReleaseCommand (gNB side / tests).
pub fn parse_ue_context_release_command(pdu: &NGAP_PDU) -> Option<(u64, u32, Option<u8>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_UEContextRelease(cmd) = value else {
        return None;
    };
    let mut ids = None;
    let mut cause = None;
    for ie in &cmd.protocol_i_es.0 {
        match &ie.value {
            UEContextReleaseCommandProtocolIEs_EntryValue::Id_UE_NGAP_IDs(
                UE_NGAP_IDs::UE_NGAP_ID_pair(pair),
            ) => ids = Some((pair.amf_ue_ngap_id.0, pair.ran_ue_ngap_id.0)),
            UEContextReleaseCommandProtocolIEs_EntryValue::Id_Cause(Cause::Nas(c)) => {
                cause = Some(c.0)
            }
            _ => {}
        }
    }
    let (amf_ue_id, ran_ue_id) = ids?;
    Some((amf_ue_id, ran_ue_id, cause))
}

/// Build an `InitialUEMessage` carrying a **5G-S-TMSI** IE alongside the NAS PDU
/// (TS 38.413 §9.2.5.1) — a CM-IDLE UE resuming with a Service Request identifies
/// itself by 5G-S-TMSI, which the gNB relays from RRC. For tests / a gNB simulator.
pub fn initial_ue_message_with_stmsi(ran_ue_id: u32, tmsi: u32, nas: Vec<u8>) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, InitialUEMessage,
        IGNORE, InitialUEMessage,
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT NAS_PDU(nas),
        REJECT FiveG_S_TMSI(fiveg_s_tmsi(tmsi)),
    )
}

/// An NR user location (NR-CGI + TAI) at `tac` — gNB 1 / cell 0, for the builders.
fn nr_user_location(mcc: &str, mnc: &str, tac: &[u8; 3]) -> UserLocationInformation {
    UserLocationInformation::UserLocationInformationNR(UserLocationInformationNR {
        nr_cgi: helpers::nr_cgi(plmn(mcc, mnc), 1, 0),
        tai: helpers::tai(plmn(mcc, mnc), tac),
        time_stamp: None,
        ie_extensions: None,
    })
}

/// [`initial_ue_message_with_nas`] plus a **User Location Information** IE placing
/// the UE in tracking area `tac` — what a real gNB sends (TS 38.413 §9.2.5.1). For
/// tests / a gNB simulator; the AMF reads the TAI as the UE's registration area.
pub fn initial_ue_message_with_nas_at(
    ran_ue_id: u32,
    nas: Vec<u8>,
    mcc: &str,
    mnc: &str,
    tac: &[u8; 3],
) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, InitialUEMessage,
        IGNORE, InitialUEMessage,
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT NAS_PDU(nas),
        REJECT UserLocationInformation(nr_user_location(mcc, mnc, tac)),
    )
}

/// [`initial_ue_message_with_stmsi`] plus a **User Location Information** IE — a
/// CM-IDLE UE resuming from tracking area `tac`. For tests / a gNB simulator.
pub fn initial_ue_message_with_stmsi_at(
    ran_ue_id: u32,
    tmsi: u32,
    nas: Vec<u8>,
    mcc: &str,
    mnc: &str,
    tac: &[u8; 3],
) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, InitialUEMessage,
        IGNORE, InitialUEMessage,
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT NAS_PDU(nas),
        REJECT FiveG_S_TMSI(fiveg_s_tmsi(tmsi)),
        REJECT UserLocationInformation(nr_user_location(mcc, mnc, tac)),
    )
}

/// The UE's tracking area code from an `InitialUEMessage`'s User Location
/// Information (NR TAI) — the AMF records it as the UE's registration area.
pub fn tac_from_initial_ue(msg: &InitialUEMessage) -> Option<[u8; 3]> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        InitialUEMessageProtocolIEs_EntryValue::Id_UserLocationInformation(
            UserLocationInformation::UserLocationInformationNR(nr),
        ) => <[u8; 3]>::try_from(nr.tai.tac.0.as_slice()).ok(),
        _ => None,
    })
}

/// Build an `NGSetupRequest` (TS 38.413 §9.2.6.1) advertising the tracking areas
/// the gNB serves — for tests and a gNB simulator. Mandatory IEs: Global RAN Node
/// ID, Supported TA List, Default Paging DRX.
pub fn ng_setup_request(gnb_id: u32, mcc: &str, mnc: &str, tacs: &[[u8; 3]]) -> NGAP_PDU {
    let ta_list = SupportedTAList(
        tacs.iter()
            .map(|tac| SupportedTAItem {
                tac: TAC(tac.to_vec()),
                broadcast_plmn_list: BroadcastPLMNList(vec![BroadcastPLMNItem {
                    plmn_identity: plmn(mcc, mnc),
                    tai_slice_support_list: SliceSupportList(vec![SliceSupportItem {
                        s_nssai: s_nssai(1, None),
                        ie_extensions: None,
                    }]),
                    ie_extensions: None,
                }]),
                ie_extensions: None,
            })
            .collect(),
    );
    let node_id = GlobalRANNodeID::GlobalGNB_ID(helpers::global_gnb_id(plmn(mcc, mnc), gnb_id));
    build_ngap!(InitiatingMessage, NGSetup,
        REJECT, NGSetupRequest,
        REJECT GlobalRANNodeID(node_id),
        REJECT SupportedTAList(ta_list),
        IGNORE DefaultPagingDRX(PagingDRX(PagingDRX::V128)),
    )
}

/// The tracking area codes a gNB advertised in its `NGSetupRequest` Supported TA
/// List — the AMF uses them for registration-area paging. `None` for other PDUs.
pub fn supported_tacs_from_ng_setup(pdu: &NGAP_PDU) -> Option<Vec<[u8; 3]>> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_NGSetup(req) = value else {
        return None;
    };
    let list = req.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        NGSetupRequestProtocolIEs_EntryValue::Id_SupportedTAList(l) => Some(l),
        _ => None,
    })?;
    Some(
        list.0
            .iter()
            .filter_map(|item| <[u8; 3]>::try_from(item.tac.0.as_slice()).ok())
            .collect(),
    )
}

/// Build a 5G-S-TMSI IE from a 5G-TMSI (AMF Set ID 10 bits, AMF Pointer 6 bits,
/// 5G-TMSI 32 bits). Set ID / pointer are fixed (single-AMF core).
fn fiveg_s_tmsi(tmsi: u32) -> FiveG_S_TMSI {
    let mut set_id = BitVec::<u8, Msb0>::from_slice(&[0x00, 0x40]);
    set_id.truncate(10);
    let mut pointer = BitVec::<u8, Msb0>::from_slice(&[0x00]);
    pointer.truncate(6);
    FiveG_S_TMSI {
        amf_set_id: AMFSetID(set_id),
        amf_pointer: AMFPointer(pointer),
        five_g_tmsi: FiveG_TMSI(tmsi.to_be_bytes().to_vec()),
        ie_extensions: None,
    }
}

/// Build a `Paging` (TS 38.413 §9.2.5.4) — a **non-UE-associated** message the AMF
/// broadcasts to gNBs to page a CM-IDLE UE by its 5G-S-TMSI, restricted to the
/// tracking-area list. The UE answers with a Service Request.
pub fn paging(tmsi: u32, mcc: &str, mnc: &str, tacs: &[[u8; 3]]) -> NGAP_PDU {
    let tai_list = TAIListForPaging(
        tacs.iter()
            .map(|tac| TAIListForPagingItem {
                tai: helpers::tai(plmn(mcc, mnc), tac),
                ie_extensions: None,
            })
            .collect(),
    );
    build_ngap!(InitiatingMessage, Paging,
        IGNORE, Paging,
        IGNORE UEPagingIdentity(UEPagingIdentity::FiveG_S_TMSI(fiveg_s_tmsi(tmsi))),
        IGNORE TAIListForPaging(tai_list),
    )
}

/// The tracking areas a `Paging` message targets (TAI List for Paging) — the gNB
/// side / tests.
pub fn tacs_from_paging(pdu: &NGAP_PDU) -> Option<Vec<[u8; 3]>> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_Paging(paging) = value else {
        return None;
    };
    paging.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        PagingProtocolIEs_EntryValue::Id_TAIListForPaging(list) => Some(
            list.0
                .iter()
                .filter_map(|item| <[u8; 3]>::try_from(item.tai.tac.0.as_slice()).ok())
                .collect(),
        ),
        _ => None,
    })
}

/// Extract the paged UE's **5G-TMSI** from a `Paging` message (gNB side / tests).
pub fn tmsi_from_paging(pdu: &NGAP_PDU) -> Option<u32> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_Paging(paging) = value else {
        return None;
    };
    paging.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        PagingProtocolIEs_EntryValue::Id_UEPagingIdentity(UEPagingIdentity::FiveG_S_TMSI(t)) => {
            <[u8; 4]>::try_from(t.five_g_tmsi.0.as_slice()).ok().map(u32::from_be_bytes)
        }
        _ => None,
    })
}

/// Extract the **5G-TMSI** (u32) from an `InitialUEMessage`'s 5G-S-TMSI IE, if
/// present — the identity the AMF resolves against its retained CM-IDLE contexts.
pub fn fiveg_s_tmsi_from_initial_ue(msg: &InitialUEMessage) -> Option<u32> {
    msg.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        InitialUEMessageProtocolIEs_EntryValue::Id_FiveG_S_TMSI(t) => {
            <[u8; 4]>::try_from(t.five_g_tmsi.0.as_slice()).ok().map(u32::from_be_bytes)
        }
        _ => None,
    })
}

/// Build a `UEContextReleaseRequest` (TS 38.413 §9.2.2.3) — the **gNB-initiated**
/// request to release a UE's context (e.g. on RAN user inactivity). Carries the
/// UE-NGAP-ID pair + a RadioNetwork cause. Mainly for a gNB simulator / tests.
pub fn ue_context_release_request(amf_ue_id: u64, ran_ue_id: u32, radio_cause: u8) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, UEContextReleaseRequest,
        REJECT, UEContextReleaseRequest,
        REJECT AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        REJECT RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        IGNORE Cause(Cause::RadioNetwork(CauseRadioNetwork(radio_cause))),
    )
}

/// Extract `(AMF-UE-NGAP-ID, RAN-UE-NGAP-ID)` from a gNB `UEContextReleaseRequest`.
pub fn parse_ue_context_release_request(pdu: &NGAP_PDU) -> Option<(u64, u32)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_UEContextReleaseRequest(req) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id) = (None, None);
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            UEContextReleaseRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => {
                amf_ue_id = Some(id.0)
            }
            UEContextReleaseRequestProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(id) => {
                ran_ue_id = Some(id.0)
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?))
}

/// Everything the AMF hands the NG-RAN in an **Initial Context Setup Request**
/// (TS 38.413 §9.2.2.1) — also what [`initial_context_setup_params`] parses back.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InitialContext {
    /// Allowed NSSAI: `(SST, optional SD)` per slice.
    pub allowed_nssai: Vec<(u8, Option<[u8; 3]>)>,
    /// The UE's 5G security capabilities `[EA, IA]` (replayed from registration).
    pub ue_sec_cap: [u8; 2],
    /// K_gNB — the AS root key (Security Key IE, 256 bits).
    pub security_key: [u8; 32],
    /// UE Aggregate Maximum Bit Rate `(downlink, uplink)` bits/sec.
    pub ue_ambr: Option<(u64, u64)>,
    /// Index to RAT/Frequency Selection Priority.
    pub rfsp: Option<u16>,
    /// Service area restriction `(allowed_tacs, not_allowed_tacs)` — sent as a
    /// Mobility Restriction List.
    pub area_restriction: Option<(Vec<[u8; 3]>, Vec<[u8; 3]>)>,
    /// PDU sessions to set up **inline** at context establishment (TS 38.413
    /// §9.2.2.1, PDU Session Resource Setup List Cxt Req) — used on a Service
    /// Request resume so the sessions come back in one procedure instead of
    /// trailing PDU Session Resource Setup Requests. Empty at initial registration.
    pub pdu_sessions: Vec<IcsPduSession>,
    /// The NAS PDU the gNB relays to the UE (the protected Registration Accept).
    pub nas: Vec<u8>,
}

/// A PDU session to set up inline in an Initial Context Setup: its id, the UPF's
/// UL N3 F-TEID, and the QoS flows (the N2 SM info transfer the gNB acts on).
#[derive(Debug, Clone, PartialEq)]
pub struct IcsPduSession {
    pub psi: u8,
    pub flows: Vec<QosFlow>,
    pub upf_teid: u32,
    pub upf_addr: Ipv4Addr,
}

/// Build an `InitialContextSetupRequest` (TS 38.413 §9.2.2.1) — the AMF
/// establishes the UE context at the NG-RAN: GUAMI, allowed NSSAI, the UE's
/// security capabilities, **K_gNB** (the AS root key), the UE-AMBR / RFSP /
/// mobility restriction (when present), and the NAS PDU (Registration Accept)
/// the gNB relays to the UE. The gNB answers with an Initial Context Setup
/// Response.
pub fn initial_context_setup_request(
    amf_ue_id: u64,
    ran_ue_id: u32,
    mcc: &str,
    mnc: &str,
    ic: &InitialContext,
) -> NGAP_PDU {
    let mut ies = vec![
        build_ngap_ie!(InitialContextSetupRequest, REJECT AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id))),
        build_ngap_ie!(InitialContextSetupRequest, REJECT RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id))),
    ];
    if let Some((dl_bps, ul_bps)) = ic.ue_ambr {
        ies.push(build_ngap_ie!(InitialContextSetupRequest, REJECT UEAggregateMaximumBitRate(UEAggregateMaximumBitRate {
            ue_aggregate_maximum_bit_rate_dl: BitRate(dl_bps),
            ue_aggregate_maximum_bit_rate_ul: BitRate(ul_bps),
            ie_extensions: None,
        })));
    }
    // GUAMI: region/set/pointer 1/1/0, matching the served GUAMI advertised in the
    // NG Setup Response and the GUTIs the AMF assigns.
    ies.push(build_ngap_ie!(InitialContextSetupRequest, REJECT GUAMI(guami(plmn(mcc, mnc), 1, 1, 0))));
    ies.push(build_ngap_ie!(InitialContextSetupRequest, REJECT AllowedNSSAI(AllowedNSSAI(
        ic.allowed_nssai
            .iter()
            .map(|(sst, sd)| AllowedNSSAI_Item { s_nssai: s_nssai(*sst, *sd), ie_extensions: None })
            .collect(),
    ))));
    ies.push(build_ngap_ie!(InitialContextSetupRequest, REJECT UESecurityCapabilities(
        helpers::ue_security_capabilities(&ic.ue_sec_cap)
    )));
    ies.push(build_ngap_ie!(InitialContextSetupRequest, REJECT SecurityKey(SecurityKey(
        BitVec::<u8, Msb0>::from_slice(&ic.security_key)
    ))));
    if let Some((allowed, not_allowed)) = &ic.area_restriction {
        ies.push(build_ngap_ie!(InitialContextSetupRequest, IGNORE MobilityRestrictionList(
            mobility_restriction_list(mcc, mnc, allowed, not_allowed)
        )));
    }
    if let Some(rfsp) = ic.rfsp {
        ies.push(build_ngap_ie!(InitialContextSetupRequest, IGNORE IndexToRFSP(IndexToRFSP(rfsp))));
    }
    if !ic.pdu_sessions.is_empty() {
        let list = PDUSessionResourceSetupListCxtReq(
            ic.pdu_sessions
                .iter()
                .map(|s| {
                    // Resume/ICS-inline sessions carry IPv4 today; threading the
                    // session's real PDU type through resume is a design/131 Phase B item.
                    let transfer = encode_aper(&setup_request_transfer(
                        &s.flows,
                        s.upf_teid,
                        s.upf_addr,
                        PduSessionType::Ipv4,
                    ));
                    PDUSessionResourceSetupItemCxtReq {
                        pdu_session_id: PDUSessionID(s.psi),
                        nas_pdu: None, // no per-session N1 on resume; the accept is the ICS NAS-PDU
                        s_nssai: s_nssai(1, None),
                        pdu_session_resource_setup_request_transfer:
                            PDUSessionResourceSetupItemCxtReqPDUSessionResourceSetupRequestTransfer(transfer),
                        ie_extensions: None,
                    }
                })
                .collect(),
        );
        ies.push(build_ngap_ie!(InitialContextSetupRequest, REJECT PDUSessionResourceSetupListCxtReq(list)));
    }
    ies.push(build_ngap_ie!(InitialContextSetupRequest, IGNORE NAS_PDU(NAS_PDU(ic.nas.clone()))));
    // InitialContextSetup = procedure code 14 (TS 38.413 §9.3.5).
    NGAP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(14),
        criticality: Criticality(Criticality::REJECT),
        value: InitiatingMessageValue::Id_InitialContextSetup(InitialContextSetupRequest {
            protocol_i_es: InitialContextSetupRequestProtocolIEs(ies),
        }),
    })
}

/// Parse an `InitialContextSetupRequest` back into `(amf_ue_id, ran_ue_id,
/// InitialContext)` — the RAN side / tests.
pub fn initial_context_setup_params(pdu: &NGAP_PDU) -> Option<(u64, u32, InitialContext)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_InitialContextSetup(req) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id) = (None, None);
    let mut ic = InitialContext::default();
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_AllowedNSSAI(list) => {
                ic.allowed_nssai = list
                    .0
                    .iter()
                    .filter_map(|item| {
                        let sst = *item.s_nssai.sst.0.first()?;
                        let sd = item
                            .s_nssai
                            .sd
                            .as_ref()
                            .and_then(|sd| <[u8; 3]>::try_from(sd.0.as_slice()).ok());
                        Some((sst, sd))
                    })
                    .collect()
            }
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_UESecurityCapabilities(cap) => {
                let byte = |bv: &BitVec<u8, Msb0>| -> u8 {
                    bv.iter().take(8).enumerate().fold(0u8, |acc, (i, b)| {
                        acc | ((*b as u8) << (7 - i))
                    })
                };
                ic.ue_sec_cap =
                    [byte(&cap.n_rencryption_algorithms.0), byte(&cap.n_rintegrity_protection_algorithms.0)];
            }
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_SecurityKey(key) => {
                let bytes = key.0.as_raw_slice();
                if let Ok(k) = <[u8; 32]>::try_from(bytes) {
                    ic.security_key = k;
                }
            }
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_UEAggregateMaximumBitRate(v) => {
                ic.ue_ambr =
                    Some((v.ue_aggregate_maximum_bit_rate_dl.0, v.ue_aggregate_maximum_bit_rate_ul.0))
            }
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_IndexToRFSP(v) => {
                ic.rfsp = Some(v.0)
            }
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_MobilityRestrictionList(mrl) => {
                if let Some(item) = mrl.service_area_information.as_ref().and_then(|s| s.0.first()) {
                    let collect = |tacs: &[TAC]| {
                        tacs.iter()
                            .filter_map(|t| <[u8; 3]>::try_from(t.0.as_slice()).ok())
                            .collect::<Vec<_>>()
                    };
                    ic.area_restriction = Some((
                        item.allowed_ta_cs.as_ref().map(|a| collect(&a.0)).unwrap_or_default(),
                        item.not_allowed_ta_cs.as_ref().map(|a| collect(&a.0)).unwrap_or_default(),
                    ));
                }
            }
            InitialContextSetupRequestProtocolIEs_EntryValue::Id_NAS_PDU(nas) => {
                ic.nas = nas.0.clone()
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, ic))
}

/// Build an `InitialContextSetupResponse` (NG-RAN→AMF) — for tests and a gNB
/// simulator.
pub fn initial_context_setup_response(amf_ue_id: u64, ran_ue_id: u32) -> NGAP_PDU {
    build_ngap!(SuccessfulOutcome, InitialContextSetup,
        REJECT, InitialContextSetupResponse,
        IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        IGNORE RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
    )
}

/// `(amf_ue_id, ran_ue_id)` from a decoded `InitialContextSetupResponse`.
pub fn initial_context_setup_response_ids(pdu: &NGAP_PDU) -> Option<(u64, u32)> {
    let NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_InitialContextSetup(resp) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id) = (None, None);
    for ie in &resp.protocol_i_es.0 {
        match &ie.value {
            InitialContextSetupResponseProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => {
                amf_ue_id = Some(id.0)
            }
            InitialContextSetupResponseProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(id) => {
                ran_ue_id = Some(id.0)
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?))
}

/// The `(psi, UPF UL N3 F-TEID, addr)` per PDU session an `InitialContextSetup
/// Request` sets up inline (`PDUSessionResourceSetupListCxtReq`) — the RAN side /
/// tests. Empty when the ICS carries no sessions.
pub fn initial_context_setup_request_session_ids(pdu: &NGAP_PDU) -> Vec<(u8, u32, Ipv4Addr)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return Vec::new();
    };
    let InitiatingMessageValue::Id_InitialContextSetup(req) = value else {
        return Vec::new();
    };
    let Some(list) = req.protocol_i_es.0.iter().find_map(|e| match &e.value {
        InitialContextSetupRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListCxtReq(l) => Some(l),
        _ => None,
    }) else {
        return Vec::new();
    };
    list.0
        .iter()
        .filter_map(|item| {
            let mut codec =
                PerCodecData::from_slice_aper(&item.pdu_session_resource_setup_request_transfer.0);
            let transfer = PDUSessionResourceSetupRequestTransfer::aper_decode(&mut codec).ok()?;
            let fteid = transfer.protocol_i_es.0.iter().find_map(|e| match &e.value {
                PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue::Id_UL_NGU_UP_TNLInformation(u) => fteid_from_uptnl(u),
                _ => None,
            })?;
            Some((item.pdu_session_id.0, fteid.0, fteid.1))
        })
        .collect()
}

/// Build an `InitialContextSetupResponse` reporting the gNB's DL N3 F-TEID for each
/// PDU session set up inline (`PDUSessionResourceSetupListCxtRes`) — for tests and
/// a gNB simulator. `admitted` = `(psi, gnb_dl_teid, gnb_dl_addr)`. A convenience
/// wrapper over [`initial_context_setup_response_with_results`] with no failures.
pub fn initial_context_setup_response_with_sessions(
    amf_ue_id: u64,
    ran_ue_id: u32,
    admitted: &[(u8, u32, Ipv4Addr)],
) -> NGAP_PDU {
    initial_context_setup_response_with_results(amf_ue_id, ran_ue_id, admitted, &[])
}

/// Build an `InitialContextSetupResponse` reporting the gNB's per-PDU-session
/// results: `admitted` = `(psi, gnb_dl_teid, gnb_dl_addr)` set up successfully
/// (`PDUSessionResourceSetupListCxtRes`); `failed` = `(psi, radio-network cause)`
/// the gNB could not set up (`PDUSessionResourceFailedToSetupListCxtRes`). Either
/// list is omitted when empty. For tests and a gNB simulator.
pub fn initial_context_setup_response_with_results(
    amf_ue_id: u64,
    ran_ue_id: u32,
    admitted: &[(u8, u32, Ipv4Addr)],
    failed: &[(u8, u8)],
) -> NGAP_PDU {
    let mut ies = vec![
        build_ngap_ie!(InitialContextSetupResponse, IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id))),
        build_ngap_ie!(InitialContextSetupResponse, IGNORE RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id))),
    ];
    if !admitted.is_empty() {
        let list = PDUSessionResourceSetupListCxtRes(
            admitted
                .iter()
                .map(|(psi, teid, addr)| {
                    let transfer = encode_aper(&setup_response_transfer(1, *teid, *addr));
                    PDUSessionResourceSetupItemCxtRes {
                        pdu_session_id: PDUSessionID(*psi),
                        pdu_session_resource_setup_response_transfer:
                            PDUSessionResourceSetupItemCxtResPDUSessionResourceSetupResponseTransfer(transfer),
                        ie_extensions: None,
                    }
                })
                .collect(),
        );
        ies.push(build_ngap_ie!(InitialContextSetupResponse, IGNORE PDUSessionResourceSetupListCxtRes(list)));
    }
    if !failed.is_empty() {
        let list = PDUSessionResourceFailedToSetupListCxtRes(
            failed
                .iter()
                .map(|(psi, cause)| {
                    let transfer = encode_aper(&PDUSessionResourceSetupUnsuccessfulTransfer {
                        cause: Cause::RadioNetwork(CauseRadioNetwork(*cause)),
                        criticality_diagnostics: None,
                        ie_extensions: None,
                    });
                    PDUSessionResourceFailedToSetupItemCxtRes {
                        pdu_session_id: PDUSessionID(*psi),
                        pdu_session_resource_setup_unsuccessful_transfer:
                            PDUSessionResourceFailedToSetupItemCxtResPDUSessionResourceSetupUnsuccessfulTransfer(transfer),
                        ie_extensions: None,
                    }
                })
                .collect(),
        );
        ies.push(build_ngap_ie!(InitialContextSetupResponse, IGNORE PDUSessionResourceFailedToSetupListCxtRes(list)));
    }
    // InitialContextSetup = procedure code 14; the response is its successful outcome.
    NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode(14),
        criticality: Criticality(Criticality::REJECT),
        value: SuccessfulOutcomeValue::Id_InitialContextSetup(InitialContextSetupResponse {
            protocol_i_es: InitialContextSetupResponseProtocolIEs(ies),
        }),
    })
}

/// The `(psi, gNB DL N3 F-TEID, addr)` per PDU session set up inline, from a
/// decoded `InitialContextSetupResponse` — the AMF drives UpdateSMContext with
/// each. Empty when the response set up no sessions (e.g. at registration).
pub fn initial_context_setup_session_ids(pdu: &NGAP_PDU) -> Vec<(u8, u32, Ipv4Addr)> {
    let NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome { value, .. }) = pdu else {
        return Vec::new();
    };
    let SuccessfulOutcomeValue::Id_InitialContextSetup(resp) = value else {
        return Vec::new();
    };
    let Some(list) = resp.protocol_i_es.0.iter().find_map(|e| match &e.value {
        InitialContextSetupResponseProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListCxtRes(l) => Some(l),
        _ => None,
    }) else {
        return Vec::new();
    };
    list.0
        .iter()
        .filter_map(|item| {
            let mut codec =
                PerCodecData::from_slice_aper(&item.pdu_session_resource_setup_response_transfer.0);
            let transfer = PDUSessionResourceSetupResponseTransfer::aper_decode(&mut codec).ok()?;
            let (teid, addr) =
                fteid_from_uptnl(&transfer.dl_qos_flow_per_tnl_information.up_transport_layer_information)?;
            Some((item.pdu_session_id.0, teid, addr))
        })
        .collect()
}

/// The numeric value inside a [`Cause`], whatever its group — for logging a
/// failure without threading each group's constants. The group itself is dropped.
fn cause_value(cause: &Cause) -> u8 {
    match cause {
        Cause::RadioNetwork(c) => c.0,
        Cause::Transport(c) => c.0,
        Cause::Nas(c) => c.0,
        Cause::Protocol(c) => c.0,
        Cause::Misc(c) => c.0,
        Cause::Choice_Extensions(_) => 0xff,
    }
}

/// The `(psi, cause)` per PDU session the gNB could **not** set up inline
/// (`PDUSessionResourceFailedToSetupListCxtRes`), from a decoded `InitialContext
/// SetupResponse` — the AMF releases each at the SMF. Empty when every inline
/// session was admitted (or the ICS carried none).
pub fn initial_context_setup_failed_session_ids(pdu: &NGAP_PDU) -> Vec<(u8, u8)> {
    let NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome { value, .. }) = pdu else {
        return Vec::new();
    };
    let SuccessfulOutcomeValue::Id_InitialContextSetup(resp) = value else {
        return Vec::new();
    };
    let Some(list) = resp.protocol_i_es.0.iter().find_map(|e| match &e.value {
        InitialContextSetupResponseProtocolIEs_EntryValue::Id_PDUSessionResourceFailedToSetupListCxtRes(l) => Some(l),
        _ => None,
    }) else {
        return Vec::new();
    };
    list.0
        .iter()
        .map(|item| {
            let mut codec =
                PerCodecData::from_slice_aper(&item.pdu_session_resource_setup_unsuccessful_transfer.0);
            let cause = PDUSessionResourceSetupUnsuccessfulTransfer::aper_decode(&mut codec)
                .ok()
                .map(|t| cause_value(&t.cause))
                .unwrap_or(0xff);
            (item.pdu_session_id.0, cause)
        })
        .collect()
}

/// Build a `PathSwitchRequest` (TS 38.413 §9.2.3.21) — after an **Xn handover**
/// the target gNB asks the AMF to switch the downlink path: the UE's new location,
/// its security capabilities, and per PDU session the target's new DL N3 F-TEID.
/// For tests and a gNB simulator. `sessions` = `(psi, dl_teid, dl_addr)`.
pub fn path_switch_request(
    source_amf_ue_id: u64,
    ran_ue_id: u32,
    mcc: &str,
    mnc: &str,
    tac: &[u8; 3],
    ue_sec_cap: &[u8; 2],
    sessions: &[(u8, u32, Ipv4Addr)],
) -> NGAP_PDU {
    let list = PDUSessionResourceToBeSwitchedDLList(
        sessions
            .iter()
            .map(|(psi, teid, addr)| {
                let transfer = encode_aper(&PathSwitchRequestTransfer {
                    dl_ngu_up_tnl_information: gtp_tunnel(*teid, *addr),
                    dl_ngu_tnl_information_reused: None,
                    user_plane_security_information: None,
                    qos_flow_accepted_list: QosFlowAcceptedList(vec![QosFlowAcceptedItem {
                        qos_flow_identifier: QosFlowIdentifier(1),
                        ie_extensions: None,
                    }]),
                    ie_extensions: None,
                });
                PDUSessionResourceToBeSwitchedDLItem {
                    pdu_session_id: PDUSessionID(*psi),
                    path_switch_request_transfer:
                        PDUSessionResourceToBeSwitchedDLItemPathSwitchRequestTransfer(transfer),
                    ie_extensions: None,
                }
            })
            .collect(),
    );
    build_ngap!(InitiatingMessage, PathSwitchRequest,
        REJECT, PathSwitchRequest,
        REJECT RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        REJECT SourceAMF_UE_NGAP_ID(AMF_UE_NGAP_ID(source_amf_ue_id)),
        IGNORE UserLocationInformation(nr_user_location(mcc, mnc, tac)),
        IGNORE UESecurityCapabilities(helpers::ue_security_capabilities(ue_sec_cap)),
        REJECT PDUSessionResourceToBeSwitchedDLList(list),
    )
}

/// Parse a `PathSwitchRequest` — `(source_amf_ue_id, new_ran_ue_id, tac,
/// [(psi, new_dl_teid, new_dl_addr)])`. The AMF side.
pub fn path_switch_params(
    pdu: &NGAP_PDU,
) -> Option<(u64, u32, Option<[u8; 3]>, Vec<(u8, u32, Ipv4Addr)>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_PathSwitchRequest(req) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut tac) = (None, None, None);
    let mut sessions = Vec::new();
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            PathSwitchRequestProtocolIEs_EntryValue::Id_SourceAMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            PathSwitchRequestProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => ran_ue_id = Some(v.0),
            PathSwitchRequestProtocolIEs_EntryValue::Id_UserLocationInformation(
                UserLocationInformation::UserLocationInformationNR(nr),
            ) => tac = <[u8; 3]>::try_from(nr.tai.tac.0.as_slice()).ok(),
            PathSwitchRequestProtocolIEs_EntryValue::Id_PDUSessionResourceToBeSwitchedDLList(
                list,
            ) => {
                for item in &list.0 {
                    let mut codec =
                        PerCodecData::from_slice_aper(&item.path_switch_request_transfer.0);
                    if let Ok(t) = PathSwitchRequestTransfer::aper_decode(&mut codec) {
                        if let Some((teid, addr)) = fteid_from_uptnl(&t.dl_ngu_up_tnl_information) {
                            sessions.push((item.pdu_session_id.0, teid, addr));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, tac, sessions))
}

/// Build a `PathSwitchRequestAcknowledge` (TS 38.413 §9.2.3.22) — the AMF confirms
/// the switch and hands the target gNB a fresh **`{NCC, NH}`** pair
/// (Security Context IE) for vertical key derivation (TS 33.501 §6.9.2.3.3),
/// acknowledging each switched PDU session.
pub fn path_switch_request_acknowledge(
    amf_ue_id: u64,
    ran_ue_id: u32,
    ncc: u8,
    nh: &[u8; 32],
    switched_psis: &[u8],
) -> NGAP_PDU {
    let security = SecurityContext {
        next_hop_chaining_count: NextHopChainingCount(ncc),
        next_hop_nh: SecurityKey(BitVec::<u8, Msb0>::from_slice(nh)),
        ie_extensions: None,
    };
    let list = PDUSessionResourceSwitchedList(
        switched_psis
            .iter()
            .map(|psi| {
                let transfer = encode_aper(&PathSwitchRequestAcknowledgeTransfer {
                    ul_ngu_up_tnl_information: None,
                    security_indication: None,
                    ie_extensions: None,
                });
                PDUSessionResourceSwitchedItem {
                    pdu_session_id: PDUSessionID(*psi),
                    path_switch_request_acknowledge_transfer:
                        PDUSessionResourceSwitchedItemPathSwitchRequestAcknowledgeTransfer(transfer),
                    ie_extensions: None,
                }
            })
            .collect(),
    );
    build_ngap!(SuccessfulOutcome, PathSwitchRequest,
        REJECT, PathSwitchRequestAcknowledge,
        IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        IGNORE RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        REJECT SecurityContext(security),
        IGNORE PDUSessionResourceSwitchedList(list),
    )
}

/// `(ncc, nh, [switched psi])` from a decoded `PathSwitchRequestAcknowledge` — the
/// gNB side / tests.
pub fn path_switch_ack_security(pdu: &NGAP_PDU) -> Option<(u8, [u8; 32], Vec<u8>)> {
    let NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_PathSwitchRequest(ack) = value else {
        return None;
    };
    let mut security = None;
    let mut switched = Vec::new();
    for ie in &ack.protocol_i_es.0 {
        match &ie.value {
            PathSwitchRequestAcknowledgeProtocolIEs_EntryValue::Id_SecurityContext(s) => {
                let nh = <[u8; 32]>::try_from(s.next_hop_nh.0.as_raw_slice()).ok()?;
                security = Some((s.next_hop_chaining_count.0, nh));
            }
            PathSwitchRequestAcknowledgeProtocolIEs_EntryValue::Id_PDUSessionResourceSwitchedList(
                list,
            ) => switched = list.0.iter().map(|i| i.pdu_session_id.0).collect(),
            _ => {}
        }
    }
    let (ncc, nh) = security?;
    Some((ncc, nh, switched))
}

// ─── N2 handover (TS 38.413 §8.4.1–8.4.3) ──────────────────────────────────────
//
// Handover Required (source→AMF) → Handover Request (AMF→target, carrying the
// rotated {NH, NCC}) → Handover Request Acknowledge (target→AMF, the target's DL
// F-TEIDs) → Handover Command (AMF→source) → Handover Notify (target→AMF).

/// A `u32` gNB id from a `GNB_ID` bit string (24-bit encoding, [`helpers::global_gnb_id`]).
fn gnb_id_bits_to_u32(id: &GNB_ID) -> Option<u32> {
    let GNB_ID::GNB_ID(bits) = id else {
        return None;
    };
    Some(bits.0.iter().fold(0u32, |acc, b| (acc << 1) | (*b as u32)))
}

/// The gNB id a `NGSetupRequest`'s Global RAN Node ID advertises — the AMF keys
/// N2-handover target resolution on it.
pub fn gnb_id_from_ng_setup(pdu: &NGAP_PDU) -> Option<u32> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_NGSetup(req) = value else {
        return None;
    };
    req.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        NGSetupRequestProtocolIEs_EntryValue::Id_GlobalRANNodeID(GlobalRANNodeID::GlobalGNB_ID(
            g,
        )) => gnb_id_bits_to_u32(&g.gnb_id),
        _ => None,
    })
}

/// Build a `HandoverRequired` (TS 38.413 §9.2.3.1) — the source gNB asks the AMF
/// to prepare an N2 handover to `target_gnb_id`, listing the PDU sessions to move
/// and the RRC transparent container for the target. `direct_forwarding` sets the
/// per-session *Direct Forwarding Path Availability* (the source can forward
/// in-flight DL data straight to the target). For tests / a gNB simulator.
#[allow(clippy::too_many_arguments)]
pub fn handover_required(
    amf_ue_id: u64,
    ran_ue_id: u32,
    target_gnb_id: u32,
    mcc: &str,
    mnc: &str,
    tac: &[u8; 3],
    psis: &[u8],
    direct_forwarding: bool,
    container: Vec<u8>,
) -> NGAP_PDU {
    let target = TargetID::TargetRANNodeID(TargetRANNodeID {
        global_ran_node_id: GlobalRANNodeID::GlobalGNB_ID(helpers::global_gnb_id(
            plmn(mcc, mnc),
            target_gnb_id,
        )),
        selected_tai: helpers::tai(plmn(mcc, mnc), tac),
        ie_extensions: None,
    });
    let list = PDUSessionResourceListHORqd(
        psis.iter()
            .map(|psi| {
                let transfer = encode_aper(&HandoverRequiredTransfer {
                    direct_forwarding_path_availability: direct_forwarding.then(|| {
                        DirectForwardingPathAvailability(
                            DirectForwardingPathAvailability::DIRECT_PATH_AVAILABLE,
                        )
                    }),
                    ie_extensions: None,
                });
                PDUSessionResourceItemHORqd {
                    pdu_session_id: PDUSessionID(*psi),
                    handover_required_transfer: PDUSessionResourceItemHORqdHandoverRequiredTransfer(
                        transfer,
                    ),
                    ie_extensions: None,
                }
            })
            .collect(),
    );
    build_ngap!(InitiatingMessage, HandoverPreparation,
        REJECT, HandoverRequired,
        REJECT AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        REJECT RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        REJECT HandoverType(HandoverType(HandoverType::INTRA5GS)),
        IGNORE Cause(Cause::RadioNetwork(CauseRadioNetwork(CauseRadioNetwork::HANDOVER_DESIRABLE_FOR_RADIO_REASON))),
        REJECT TargetID(target),
        REJECT PDUSessionResourceListHORqd(list),
        REJECT SourceToTarget_TransparentContainer(SourceToTarget_TransparentContainer(container)),
    )
}

/// Parse a `HandoverRequired` — `(amf_ue_id, ran_ue_id, target_gnb_id, psis,
/// direct_forwarding, source→target container)`. The AMF side.
pub fn handover_required_params(
    pdu: &NGAP_PDU,
) -> Option<(u64, u32, u32, Vec<u8>, bool, Vec<u8>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_HandoverPreparation(req) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut target, mut container) = (None, None, None, None);
    let mut psis = Vec::new();
    let mut direct_forwarding = false;
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            HandoverRequiredProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => amf_ue_id = Some(v.0),
            HandoverRequiredProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => ran_ue_id = Some(v.0),
            HandoverRequiredProtocolIEs_EntryValue::Id_TargetID(TargetID::TargetRANNodeID(t)) => {
                if let GlobalRANNodeID::GlobalGNB_ID(g) = &t.global_ran_node_id {
                    target = gnb_id_bits_to_u32(&g.gnb_id);
                }
            }
            HandoverRequiredProtocolIEs_EntryValue::Id_PDUSessionResourceListHORqd(list) => {
                for item in &list.0 {
                    psis.push(item.pdu_session_id.0);
                    let mut codec =
                        PerCodecData::from_slice_aper(&item.handover_required_transfer.0);
                    if let Ok(t) = HandoverRequiredTransfer::aper_decode(&mut codec) {
                        if t.direct_forwarding_path_availability.is_some() {
                            direct_forwarding = true;
                        }
                    }
                }
            }
            HandoverRequiredProtocolIEs_EntryValue::Id_SourceToTarget_TransparentContainer(c) => {
                container = Some(c.0.clone())
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, target?, psis, direct_forwarding, container?))
}

/// Build a `HandoverRequest` (TS 38.413 §9.2.3.4) — the AMF asks the **target**
/// gNB to prepare resources: the UE's AMBR / security capabilities / allowed
/// NSSAI, the **`{NCC, NH}` pair** for vertical key derivation (TS 33.501
/// §6.9.2.3.2), the PDU sessions to set up (each with the UPF's UL N3 F-TEID +
/// QoS flows), and the source's transparent container.
#[allow(clippy::too_many_arguments)]
pub fn handover_request(
    amf_ue_id: u64,
    mcc: &str,
    mnc: &str,
    ue_ambr: (u64, u64),
    ue_sec_cap: &[u8; 2],
    ncc: u8,
    nh: &[u8; 32],
    allowed_nssai: &[(u8, Option<[u8; 3]>)],
    sessions: &[(u8, Vec<QosFlow>, u32, Ipv4Addr)],
    container: Vec<u8>,
) -> NGAP_PDU {
    let list = PDUSessionResourceSetupListHOReq(
        sessions
            .iter()
            .map(|(psi, flows, ul_teid, ul_addr)| {
                // Handover sessions carry IPv4 today; threading the real PDU type
                // through the handover path is a design/131 Phase B item.
                let transfer =
                    encode_aper(&setup_request_transfer(flows, *ul_teid, *ul_addr, PduSessionType::Ipv4));
                PDUSessionResourceSetupItemHOReq {
                    pdu_session_id: PDUSessionID(*psi),
                    s_nssai: s_nssai(1, None),
                    handover_request_transfer:
                        PDUSessionResourceSetupItemHOReqHandoverRequestTransfer(transfer),
                    ie_extensions: None,
                }
            })
            .collect(),
    );
    let security = SecurityContext {
        next_hop_chaining_count: NextHopChainingCount(ncc),
        next_hop_nh: SecurityKey(BitVec::<u8, Msb0>::from_slice(nh)),
        ie_extensions: None,
    };
    let nssai = AllowedNSSAI(
        allowed_nssai
            .iter()
            .map(|(sst, sd)| AllowedNSSAI_Item { s_nssai: s_nssai(*sst, *sd), ie_extensions: None })
            .collect(),
    );
    build_ngap!(InitiatingMessage, HandoverResourceAllocation,
        REJECT, HandoverRequest,
        REJECT AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        REJECT HandoverType(HandoverType(HandoverType::INTRA5GS)),
        IGNORE Cause(Cause::RadioNetwork(CauseRadioNetwork(CauseRadioNetwork::HANDOVER_DESIRABLE_FOR_RADIO_REASON))),
        REJECT UEAggregateMaximumBitRate(UEAggregateMaximumBitRate {
            ue_aggregate_maximum_bit_rate_dl: BitRate(ue_ambr.0),
            ue_aggregate_maximum_bit_rate_ul: BitRate(ue_ambr.1),
            ie_extensions: None,
        }),
        REJECT UESecurityCapabilities(helpers::ue_security_capabilities(ue_sec_cap)),
        REJECT SecurityContext(security),
        REJECT PDUSessionResourceSetupListHOReq(list),
        REJECT AllowedNSSAI(nssai),
        REJECT SourceToTarget_TransparentContainer(SourceToTarget_TransparentContainer(container)),
        REJECT GUAMI(guami(plmn(mcc, mnc), 1, 1, 0)),
    )
}

/// Parse a `HandoverRequest` — `(amf_ue_id, ncc, nh, [(psi, ul_teid, ul_addr)],
/// source→target container)`. The target-gNB side / tests.
pub fn handover_request_params(
    pdu: &NGAP_PDU,
) -> Option<(u64, u8, [u8; 32], Vec<(u8, u32, Ipv4Addr)>, Vec<u8>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_HandoverResourceAllocation(req) = value else {
        return None;
    };
    let (mut amf_ue_id, mut security, mut container) = (None, None, None);
    let mut sessions = Vec::new();
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            HandoverRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => amf_ue_id = Some(v.0),
            HandoverRequestProtocolIEs_EntryValue::Id_SecurityContext(s) => {
                let nh = <[u8; 32]>::try_from(s.next_hop_nh.0.as_raw_slice()).ok()?;
                security = Some((s.next_hop_chaining_count.0, nh));
            }
            HandoverRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListHOReq(list) => {
                for item in &list.0 {
                    let mut codec =
                        PerCodecData::from_slice_aper(&item.handover_request_transfer.0);
                    if let Ok(t) = PDUSessionResourceSetupRequestTransfer::aper_decode(&mut codec) {
                        let fteid = t.protocol_i_es.0.iter().find_map(|e| match &e.value {
                            PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue::Id_UL_NGU_UP_TNLInformation(u) => fteid_from_uptnl(u),
                            _ => None,
                        });
                        if let Some((teid, addr)) = fteid {
                            sessions.push((item.pdu_session_id.0, teid, addr));
                        }
                    }
                }
            }
            HandoverRequestProtocolIEs_EntryValue::Id_SourceToTarget_TransparentContainer(c) => {
                container = Some(c.0.clone())
            }
            _ => {}
        }
    }
    let (ncc, nh) = security?;
    Some((amf_ue_id?, ncc, nh, sessions, container?))
}

/// Build a `HandoverRequestAcknowledge` (TS 38.413 §9.2.3.5) — the target gNB
/// admits the PDU sessions, each with **its** DL N3 F-TEID and, when it accepts
/// data forwarding, a **DL forwarding F-TEID** the source can send in-flight
/// packets to; plus the target→source RRC container. For tests / a gNB simulator.
pub fn handover_request_acknowledge(
    amf_ue_id: u64,
    ran_ue_id: u32,
    admitted: &[(u8, u32, Ipv4Addr, Option<(u32, Ipv4Addr)>)],
    container: Vec<u8>,
) -> NGAP_PDU {
    let list = PDUSessionResourceAdmittedList(
        admitted
            .iter()
            .map(|(psi, teid, addr, forwarding)| {
                let transfer = encode_aper(&HandoverRequestAcknowledgeTransfer {
                    dl_ngu_up_tnl_information: gtp_tunnel(*teid, *addr),
                    dl_forwarding_up_tnl_information: forwarding
                        .map(|(fwd_teid, fwd_addr)| gtp_tunnel(fwd_teid, fwd_addr)),
                    security_result: None,
                    qos_flow_setup_response_list: QosFlowListWithDataForwarding(vec![
                        QosFlowItemWithDataForwarding {
                            qos_flow_identifier: QosFlowIdentifier(1),
                            data_forwarding_accepted: None,
                            ie_extensions: None,
                        },
                    ]),
                    qos_flow_failed_to_setup_list: None,
                    data_forwarding_response_drb_list: None,
                    ie_extensions: None,
                });
                PDUSessionResourceAdmittedItem {
                    pdu_session_id: PDUSessionID(*psi),
                    handover_request_acknowledge_transfer:
                        PDUSessionResourceAdmittedItemHandoverRequestAcknowledgeTransfer(transfer),
                    ie_extensions: None,
                }
            })
            .collect(),
    );
    build_ngap!(SuccessfulOutcome, HandoverResourceAllocation,
        REJECT, HandoverRequestAcknowledge,
        IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        IGNORE RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        IGNORE PDUSessionResourceAdmittedList(list),
        REJECT TargetToSource_TransparentContainer(TargetToSource_TransparentContainer(container)),
    )
}

/// Parse a `HandoverRequestAcknowledge` — `(amf_ue_id, target_ran_ue_id,
/// [(psi, target_dl_teid, target_dl_addr, forwarding_fteid)], target→source
/// container)`. The AMF side.
pub fn handover_request_ack_params(
    pdu: &NGAP_PDU,
) -> Option<(u64, u32, Vec<(u8, u32, Ipv4Addr, Option<(u32, Ipv4Addr)>)>, Vec<u8>)> {
    let NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_HandoverResourceAllocation(ack) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut container) = (None, None, None);
    let mut admitted = Vec::new();
    for ie in &ack.protocol_i_es.0 {
        match &ie.value {
            HandoverRequestAcknowledgeProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            HandoverRequestAcknowledgeProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            HandoverRequestAcknowledgeProtocolIEs_EntryValue::Id_PDUSessionResourceAdmittedList(
                list,
            ) => {
                for item in &list.0 {
                    let mut codec = PerCodecData::from_slice_aper(
                        &item.handover_request_acknowledge_transfer.0,
                    );
                    if let Ok(t) = HandoverRequestAcknowledgeTransfer::aper_decode(&mut codec) {
                        if let Some((teid, addr)) = fteid_from_uptnl(&t.dl_ngu_up_tnl_information) {
                            let forwarding = t
                                .dl_forwarding_up_tnl_information
                                .as_ref()
                                .and_then(fteid_from_uptnl);
                            admitted.push((item.pdu_session_id.0, teid, addr, forwarding));
                        }
                    }
                }
            }
            HandoverRequestAcknowledgeProtocolIEs_EntryValue::Id_TargetToSource_TransparentContainer(c) => {
                container = Some(c.0.clone())
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, admitted, container?))
}

/// Build a `HandoverCommand` (TS 38.413 §9.2.3.2) — the AMF tells the **source**
/// gNB to execute the handover, relaying the target's transparent container (the
/// source forwards it to the UE via RRC) and, per session accepting **data
/// forwarding**, the target's DL forwarding F-TEID the source sends in-flight
/// downlink packets to.
pub fn handover_command(
    amf_ue_id: u64,
    ran_ue_id: u32,
    forwarding: &[(u8, u32, Ipv4Addr)],
    container: Vec<u8>,
) -> NGAP_PDU {
    let mut ies = vec![
        build_ngap_ie!(HandoverCommand, REJECT AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id))),
        build_ngap_ie!(HandoverCommand, REJECT RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id))),
        build_ngap_ie!(HandoverCommand, REJECT HandoverType(HandoverType(HandoverType::INTRA5GS))),
    ];
    if !forwarding.is_empty() {
        let list = PDUSessionResourceHandoverList(
            forwarding
                .iter()
                .map(|(psi, teid, addr)| {
                    let transfer = encode_aper(&HandoverCommandTransfer {
                        dl_forwarding_up_tnl_information: Some(gtp_tunnel(*teid, *addr)),
                        qos_flow_to_be_forwarded_list: None,
                        data_forwarding_response_drb_list: None,
                        ie_extensions: None,
                    });
                    PDUSessionResourceHandoverItem {
                        pdu_session_id: PDUSessionID(*psi),
                        handover_command_transfer:
                            PDUSessionResourceHandoverItemHandoverCommandTransfer(transfer),
                        ie_extensions: None,
                    }
                })
                .collect(),
        );
        ies.push(build_ngap_ie!(HandoverCommand, IGNORE PDUSessionResourceHandoverList(list)));
    }
    ies.push(build_ngap_ie!(HandoverCommand, REJECT TargetToSource_TransparentContainer(
        TargetToSource_TransparentContainer(container)
    )));
    // HandoverPreparation = procedure code 12 (the command is its successful outcome).
    NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode(12),
        criticality: Criticality(Criticality::REJECT),
        value: SuccessfulOutcomeValue::Id_HandoverPreparation(HandoverCommand {
            protocol_i_es: HandoverCommandProtocolIEs(ies),
        }),
    })
}

/// `(amf_ue_id, ran_ue_id, [(psi, forwarding F-TEID)], target→source container)`
/// from a decoded `HandoverCommand` — the source-gNB side / tests.
pub fn handover_command_params(
    pdu: &NGAP_PDU,
) -> Option<(u64, u32, Vec<(u8, u32, Ipv4Addr)>, Vec<u8>)> {
    let NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_HandoverPreparation(cmd) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut container) = (None, None, None);
    let mut forwarding = Vec::new();
    for ie in &cmd.protocol_i_es.0 {
        match &ie.value {
            HandoverCommandProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => amf_ue_id = Some(v.0),
            HandoverCommandProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => ran_ue_id = Some(v.0),
            HandoverCommandProtocolIEs_EntryValue::Id_PDUSessionResourceHandoverList(list) => {
                for item in &list.0 {
                    let mut codec =
                        PerCodecData::from_slice_aper(&item.handover_command_transfer.0);
                    if let Ok(t) = HandoverCommandTransfer::aper_decode(&mut codec) {
                        if let Some((teid, addr)) =
                            t.dl_forwarding_up_tnl_information.as_ref().and_then(fteid_from_uptnl)
                        {
                            forwarding.push((item.pdu_session_id.0, teid, addr));
                        }
                    }
                }
            }
            HandoverCommandProtocolIEs_EntryValue::Id_TargetToSource_TransparentContainer(c) => {
                container = Some(c.0.clone())
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, forwarding, container?))
}

/// Build a `HandoverNotify` (TS 38.413 §9.2.3.6) — the target gNB reports the UE
/// arrived. For tests / a gNB simulator.
pub fn handover_notify(
    amf_ue_id: u64,
    ran_ue_id: u32,
    mcc: &str,
    mnc: &str,
    tac: &[u8; 3],
) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, HandoverNotification,
        IGNORE, HandoverNotify,
        REJECT AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        REJECT RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        IGNORE UserLocationInformation(nr_user_location(mcc, mnc, tac)),
    )
}

/// `(amf_ue_id, target_ran_ue_id, tac)` from a decoded `HandoverNotify` — the AMF side.
pub fn handover_notify_params(pdu: &NGAP_PDU) -> Option<(u64, u32, Option<[u8; 3]>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_HandoverNotification(msg) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut tac) = (None, None, None);
    for ie in &msg.protocol_i_es.0 {
        match &ie.value {
            HandoverNotifyProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => amf_ue_id = Some(v.0),
            HandoverNotifyProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => ran_ue_id = Some(v.0),
            HandoverNotifyProtocolIEs_EntryValue::Id_UserLocationInformation(
                UserLocationInformation::UserLocationInformationNR(nr),
            ) => tac = <[u8; 3]>::try_from(nr.tai.tac.0.as_slice()).ok(),
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, tac))
}

// ─── Handover failure paths (TS 38.413 §8.4) ───────────────────────────────────

/// Build a `HandoverPreparationFailure` (TS 38.413 §9.2.3.3) — the AMF tells the
/// **source** gNB the handover preparation failed (unknown target, target
/// rejection, TNGRELOCprep expiry, …). Radio-network cause.
pub fn handover_preparation_failure(amf_ue_id: u64, ran_ue_id: u32, radio_cause: u8) -> NGAP_PDU {
    build_ngap!(UnsuccessfulOutcome, HandoverPreparation,
        REJECT, HandoverPreparationFailure,
        IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        IGNORE RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        IGNORE Cause(Cause::RadioNetwork(CauseRadioNetwork(radio_cause))),
    )
}

/// `(amf_ue_id, ran_ue_id, radio cause)` from a decoded
/// `HandoverPreparationFailure` — the source-gNB side / tests.
pub fn handover_preparation_failure_params(pdu: &NGAP_PDU) -> Option<(u64, u32, Option<u8>)> {
    let NGAP_PDU::UnsuccessfulOutcome(UnsuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let UnsuccessfulOutcomeValue::Id_HandoverPreparation(msg) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut cause) = (None, None, None);
    for ie in &msg.protocol_i_es.0 {
        match &ie.value {
            HandoverPreparationFailureProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            HandoverPreparationFailureProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            HandoverPreparationFailureProtocolIEs_EntryValue::Id_Cause(Cause::RadioNetwork(c)) => {
                cause = Some(c.0)
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, cause))
}

/// Build a `HandoverFailure` (TS 38.413 §9.2.3.5A) — the **target** gNB tells the
/// AMF it cannot allocate resources for the handover. For tests / a gNB simulator.
pub fn handover_failure(amf_ue_id: u64, radio_cause: u8) -> NGAP_PDU {
    build_ngap!(UnsuccessfulOutcome, HandoverResourceAllocation,
        REJECT, HandoverFailure,
        IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        IGNORE Cause(Cause::RadioNetwork(CauseRadioNetwork(radio_cause))),
    )
}

/// `(amf_ue_id, radio cause)` from a decoded `HandoverFailure` — the AMF side.
pub fn handover_failure_params(pdu: &NGAP_PDU) -> Option<(u64, Option<u8>)> {
    let NGAP_PDU::UnsuccessfulOutcome(UnsuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let UnsuccessfulOutcomeValue::Id_HandoverResourceAllocation(msg) = value else {
        return None;
    };
    let (mut amf_ue_id, mut cause) = (None, None);
    for ie in &msg.protocol_i_es.0 {
        match &ie.value {
            HandoverFailureProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => amf_ue_id = Some(v.0),
            HandoverFailureProtocolIEs_EntryValue::Id_Cause(Cause::RadioNetwork(c)) => {
                cause = Some(c.0)
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, cause))
}

/// Build a `HandoverCancel` (TS 38.413 §9.2.3.7) — the **source** gNB aborts an
/// in-flight handover. For tests / a gNB simulator.
pub fn handover_cancel(amf_ue_id: u64, ran_ue_id: u32, radio_cause: u8) -> NGAP_PDU {
    build_ngap!(InitiatingMessage, HandoverCancel,
        REJECT, HandoverCancel,
        REJECT AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        REJECT RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        IGNORE Cause(Cause::RadioNetwork(CauseRadioNetwork(radio_cause))),
    )
}

/// `(amf_ue_id, ran_ue_id)` from a decoded `HandoverCancel` — the AMF side.
pub fn handover_cancel_params(pdu: &NGAP_PDU) -> Option<(u64, u32)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_HandoverCancel(msg) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id) = (None, None);
    for ie in &msg.protocol_i_es.0 {
        match &ie.value {
            HandoverCancelProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => amf_ue_id = Some(v.0),
            HandoverCancelProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => ran_ue_id = Some(v.0),
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?))
}

/// Build a `HandoverCancelAcknowledge` (TS 38.413 §9.2.3.8) — the AMF confirms
/// the cancellation to the source gNB.
pub fn handover_cancel_acknowledge(amf_ue_id: u64, ran_ue_id: u32) -> NGAP_PDU {
    build_ngap!(SuccessfulOutcome, HandoverCancel,
        REJECT, HandoverCancelAcknowledge,
        IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        IGNORE RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
    )
}

/// `(amf_ue_id, ran_ue_id)` from a decoded `HandoverCancelAcknowledge` — the
/// source-gNB side / tests.
pub fn handover_cancel_ack_params(pdu: &NGAP_PDU) -> Option<(u64, u32)> {
    let NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_HandoverCancel(msg) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id) = (None, None);
    for ie in &msg.protocol_i_es.0 {
        match &ie.value {
            HandoverCancelAcknowledgeProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            HandoverCancelAcknowledgeProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?))
}

/// Build a `PathSwitchRequestFailure` (TS 38.413 §9.2.3.23) — the AMF rejects a
/// path switch; each requested PDU session is reported released with a
/// radio-network cause in its unsuccessful transfer.
pub fn path_switch_request_failure(
    amf_ue_id: u64,
    ran_ue_id: u32,
    psis: &[u8],
    radio_cause: u8,
) -> NGAP_PDU {
    let list = PDUSessionResourceReleasedListPSFail(
        psis.iter()
            .map(|psi| {
                let transfer = encode_aper(&PathSwitchRequestUnsuccessfulTransfer {
                    cause: Cause::RadioNetwork(CauseRadioNetwork(radio_cause)),
                    ie_extensions: None,
                });
                PDUSessionResourceReleasedItemPSFail {
                    pdu_session_id: PDUSessionID(*psi),
                    path_switch_request_unsuccessful_transfer:
                        PDUSessionResourceReleasedItemPSFailPathSwitchRequestUnsuccessfulTransfer(
                            transfer,
                        ),
                    ie_extensions: None,
                }
            })
            .collect(),
    );
    build_ngap!(UnsuccessfulOutcome, PathSwitchRequest,
        REJECT, PathSwitchRequestFailure,
        IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        IGNORE RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
        IGNORE PDUSessionResourceReleasedListPSFail(list),
    )
}

/// `(amf_ue_id, ran_ue_id, [released psi])` from a decoded
/// `PathSwitchRequestFailure` — the gNB side / tests.
pub fn path_switch_failure_params(pdu: &NGAP_PDU) -> Option<(u64, u32, Vec<u8>)> {
    let NGAP_PDU::UnsuccessfulOutcome(UnsuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let UnsuccessfulOutcomeValue::Id_PathSwitchRequest(msg) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id) = (None, None);
    let mut psis = Vec::new();
    for ie in &msg.protocol_i_es.0 {
        match &ie.value {
            PathSwitchRequestFailureProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            PathSwitchRequestFailureProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            PathSwitchRequestFailureProtocolIEs_EntryValue::Id_PDUSessionResourceReleasedListPSFail(
                list,
            ) => psis = list.0.iter().map(|i| i.pdu_session_id.0).collect(),
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, psis))
}

/// Build a `UEContextModificationRequest` (TS 38.413 §9.2.2.7) — the AMF asks the
/// NG-RAN to update the UE context. Only the two UE-NGAP-IDs are mandatory; the
/// **Index to RAT/Frequency Selection Priority** (RFSP, TS 23.501 §5.3.4.3, steers
/// the UE to RAT/frequency layers) and the **UE Aggregate Maximum Bit Rate** are
/// optional and included only when supplied. This is the canonical vehicle for
/// pushing an access-and-mobility policy (RFSP / UE-AMBR) to the RAN after
/// registration or on a mid-connection change.
pub fn ue_context_modification_request(
    amf_ue_id: u64,
    ran_ue_id: u32,
    rfsp: Option<u16>,
    ue_ambr: Option<(u64, u64)>,
) -> NGAP_PDU {
    let mut ies = vec![
        build_ngap_ie!(UEContextModificationRequest, REJECT AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id))),
        build_ngap_ie!(UEContextModificationRequest, REJECT RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id))),
    ];
    if let Some(rfsp) = rfsp {
        // Index to RFSP (IE id 31), criticality ignore — advisory to the RAN.
        ies.push(build_ngap_ie!(UEContextModificationRequest, IGNORE IndexToRFSP(IndexToRFSP(rfsp))));
    }
    if let Some((dl_bps, ul_bps)) = ue_ambr {
        ies.push(build_ngap_ie!(UEContextModificationRequest, IGNORE UEAggregateMaximumBitRate(UEAggregateMaximumBitRate {
            ue_aggregate_maximum_bit_rate_dl: BitRate(dl_bps),
            ue_aggregate_maximum_bit_rate_ul: BitRate(ul_bps),
            ie_extensions: None,
        })));
    }
    // UEContextModification = procedure code 40 (TS 38.413 §9.3.5).
    NGAP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(40),
        criticality: Criticality(Criticality::REJECT),
        value: InitiatingMessageValue::Id_UEContextModification(UEContextModificationRequest {
            protocol_i_es: UEContextModificationRequestProtocolIEs(ies),
        }),
    })
}

/// Extract `(amf_ue_id, ran_ue_id, RFSP, UE-AMBR (dl,ul) bps)` from a
/// `UEContextModificationRequest` — the RAN side / tests.
pub fn ue_context_modification_params(
    pdu: &NGAP_PDU,
) -> Option<(u64, u32, Option<u16>, Option<(u64, u64)>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_UEContextModification(req) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut rfsp, mut ambr) = (None, None, None, None);
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            UEContextModificationRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => {
                amf_ue_id = Some(id.0)
            }
            UEContextModificationRequestProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(id) => {
                ran_ue_id = Some(id.0)
            }
            UEContextModificationRequestProtocolIEs_EntryValue::Id_IndexToRFSP(v) => {
                rfsp = Some(v.0)
            }
            UEContextModificationRequestProtocolIEs_EntryValue::Id_UEAggregateMaximumBitRate(v) => {
                ambr = Some((v.ue_aggregate_maximum_bit_rate_dl.0, v.ue_aggregate_maximum_bit_rate_ul.0))
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, rfsp, ambr))
}

/// Build a `UEContextModificationResponse` (NG-RAN→AMF) acknowledging the update —
/// for tests and a gNB simulator.
pub fn ue_context_modification_response(amf_ue_id: u64, ran_ue_id: u32) -> NGAP_PDU {
    build_ngap!(SuccessfulOutcome, UEContextModification,
        REJECT, UEContextModificationResponse,
        IGNORE AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(amf_ue_id)),
        IGNORE RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(ran_ue_id)),
    )
}

/// `(amf_ue_id, ran_ue_id)` from a decoded `UEContextModificationResponse`.
pub fn ue_context_modification_response_ids(pdu: &NGAP_PDU) -> Option<(u64, u32)> {
    let NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome { value, .. }) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_UEContextModification(resp) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id) = (None, None);
    for ie in &resp.protocol_i_es.0 {
        match &ie.value {
            UEContextModificationResponseProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => {
                amf_ue_id = Some(id.0)
            }
            UEContextModificationResponseProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(id) => {
                ran_ue_id = Some(id.0)
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?))
}

// ─── N2 PDU Session Resource Setup (TS 38.413 §9.2.1.1/§9.2.1.2) ───────────────
//
// The N2 SM information is carried as separately-APER-encoded `*Transfer` sub-PDUs
// embedded as octet strings inside the per-session items.

/// A GTP-U F-TEID as NGAP `UPTransportLayerInformation` (GTP tunnel): TEID + IPv4.
fn gtp_tunnel(teid: u32, addr: Ipv4Addr) -> UPTransportLayerInformation {
    UPTransportLayerInformation::GTPTunnel(GTPTunnel {
        transport_layer_address: TransportLayerAddress(BitVec::<u8, Msb0>::from_slice(&addr.octets())),
        gtp_teid: GTP_TEID(teid.to_be_bytes().to_vec()),
        ie_extensions: None,
    })
}

/// Extract `(TEID, IPv4)` from an NGAP GTP-tunnel F-TEID.
fn fteid_from_uptnl(info: &UPTransportLayerInformation) -> Option<(u32, Ipv4Addr)> {
    let UPTransportLayerInformation::GTPTunnel(t) = info else {
        return None;
    };
    let teid: [u8; 4] = t.gtp_teid.0.as_slice().try_into().ok()?;
    let addr: [u8; 4] = t.transport_layer_address.0.as_raw_slice().get(..4)?.try_into().ok()?;
    Some((u32::from_be_bytes(teid), Ipv4Addr::from(addr)))
}

/// Guaranteed bit rates for a GBR QoS flow, in bits/sec.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Gbr {
    pub gfbr_dl_bps: u64,
    pub gfbr_ul_bps: u64,
    pub mfbr_dl_bps: u64,
    pub mfbr_ul_bps: u64,
}

/// One authorized QoS flow (TS 23.501 §5.7) — QFI, 5QI, ARP, and GBR rates when
/// the flow is guaranteed-bit-rate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QosFlow {
    pub qfi: u8,
    pub five_qi: u8,
    pub arp_priority: u8,
    pub pre_empt_cap: bool,
    pub pre_empt_vuln: bool,
    pub gbr: Option<Gbr>,
}

impl QosFlow {
    /// The default non-GBR flow: QFI 1, 5QI 9, ARP priority 8, no pre-emption.
    pub fn default_non_gbr() -> Self {
        QosFlow { qfi: 1, five_qi: 9, arp_priority: 8, pre_empt_cap: false, pre_empt_vuln: false, gbr: None }
    }
}

/// The NGAP `QosFlowLevelQosParameters` (5QI + ARP + optional GBR) for one flow —
/// shared by the setup and the add-or-modify lists.
fn qos_flow_level_params(f: &QosFlow) -> QosFlowLevelQosParameters {
    QosFlowLevelQosParameters {
        qos_characteristics: QosCharacteristics::NonDynamic5QI(NonDynamic5QIDescriptor {
            five_qi: FiveQI(f.five_qi),
            priority_level_qos: None,
            averaging_window: None,
            maximum_data_burst_volume: None,
            ie_extensions: None,
        }),
        allocation_and_retention_priority: AllocationAndRetentionPriority {
            priority_level_arp: PriorityLevelARP(f.arp_priority),
            pre_emption_capability: Pre_emptionCapability(if f.pre_empt_cap {
                Pre_emptionCapability::MAY_TRIGGER_PRE_EMPTION
            } else {
                Pre_emptionCapability::SHALL_NOT_TRIGGER_PRE_EMPTION
            }),
            pre_emption_vulnerability: Pre_emptionVulnerability(if f.pre_empt_vuln {
                Pre_emptionVulnerability::PRE_EMPTABLE
            } else {
                Pre_emptionVulnerability::NOT_PRE_EMPTABLE
            }),
            ie_extensions: None,
        },
        gbr_qos_information: f.gbr.map(|g| GBR_QosInformation {
            maximum_flow_bit_rate_dl: BitRate(g.mfbr_dl_bps),
            maximum_flow_bit_rate_ul: BitRate(g.mfbr_ul_bps),
            guaranteed_flow_bit_rate_dl: BitRate(g.gfbr_dl_bps),
            guaranteed_flow_bit_rate_ul: BitRate(g.gfbr_ul_bps),
            notification_control: None,
            maximum_packet_loss_rate_dl: None,
            maximum_packet_loss_rate_ul: None,
            ie_extensions: None,
        }),
        reflective_qos_attribute: None,
        additional_qos_flow_information: None,
        ie_extensions: None,
    }
}

/// Build the NGAP `QosFlowSetupRequestList` from the authorized flows.
fn qos_flow_setup_list(flows: &[QosFlow]) -> QosFlowSetupRequestList {
    QosFlowSetupRequestList(
        flows
            .iter()
            .map(|f| QosFlowSetupRequestItem {
                qos_flow_identifier: QosFlowIdentifier(f.qfi),
                qos_flow_level_qos_parameters: qos_flow_level_params(f),
                e_rab_id: None,
                ie_extensions: None,
            })
            .collect(),
    )
}

/// Build the NGAP `QosFlowAddOrModifyRequestList` from the (updated) flows.
fn qos_flow_add_or_modify_list(flows: &[QosFlow]) -> QosFlowAddOrModifyRequestList {
    QosFlowAddOrModifyRequestList(
        flows
            .iter()
            .map(|f| QosFlowAddOrModifyRequestItem {
                qos_flow_identifier: QosFlowIdentifier(f.qfi),
                qos_flow_level_qos_parameters: Some(qos_flow_level_params(f)),
                e_rab_id: None,
                ie_extensions: None,
            })
            .collect(),
    )
}

/// APER-encode a standalone N2 SM-info `*Transfer` sub-PDU to octets.
fn encode_aper<T: AperCodec>(pdu: &T) -> Vec<u8> {
    let mut codec = PerCodecData::new_aper();
    pdu.aper_encode(&mut codec).expect("APER-encode SM-info transfer");
    codec.into_bytes()
}

/// The IP family of a PDU session, for the N2 PDU Session Type IE (TS 38.413
/// §9.3.1.51). Mirrors the NAS `PduSessionType` the SMF negotiates (design/131).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PduSessionType {
    #[default]
    Ipv4,
    Ipv6,
    Ipv4v6,
}

/// The N2 SM info the SMF gives the gNB: the UPF's UL N3 F-TEID + PDU type + QoS.
fn setup_request_transfer(
    flows: &[QosFlow],
    upf_teid: u32,
    upf_addr: Ipv4Addr,
    pdu_type: PduSessionType,
) -> PDUSessionResourceSetupRequestTransfer {
    let pdu_type_value = match pdu_type {
        PduSessionType::Ipv4 => PDUSessionType::IPV4,
        PduSessionType::Ipv6 => PDUSessionType::IPV6,
        PduSessionType::Ipv4v6 => PDUSessionType::IPV4V6,
    };
    PDUSessionResourceSetupRequestTransfer {
        protocol_i_es: PDUSessionResourceSetupRequestTransferProtocolIEs(vec![
            build_ngap_ie!(PDUSessionResourceSetupRequestTransfer, REJECT UL_NGU_UP_TNLInformation(gtp_tunnel(upf_teid, upf_addr))),
            build_ngap_ie!(PDUSessionResourceSetupRequestTransfer, REJECT PDUSessionType(PDUSessionType(pdu_type_value))),
            build_ngap_ie!(PDUSessionResourceSetupRequestTransfer, REJECT QosFlowSetupRequestList(qos_flow_setup_list(flows))),
        ]),
    }
}

/// The N2 SM info the gNB returns: its DL N3 F-TEID + accepted QoS flows.
fn setup_response_transfer(qfi: u8, gnb_teid: u32, gnb_addr: Ipv4Addr) -> PDUSessionResourceSetupResponseTransfer {
    PDUSessionResourceSetupResponseTransfer {
        dl_qos_flow_per_tnl_information: QosFlowPerTNLInformation {
            up_transport_layer_information: gtp_tunnel(gnb_teid, gnb_addr),
            associated_qos_flow_list: AssociatedQosFlowList(vec![AssociatedQosFlowItem {
                qos_flow_identifier: QosFlowIdentifier(qfi),
                qos_flow_mapping_indication: None,
                ie_extensions: None,
            }]),
            ie_extensions: None,
        },
        additional_dl_qos_flow_per_tnl_information: None,
        security_result: None,
        qos_flow_failed_to_setup_list: None,
        ie_extensions: None,
    }
}

/// Build a `PDUSessionResourceSetupRequest` (AMF→gNB) setting up one PDU session: the
/// N1 SM container (`nas`, a PDU Session Establishment Accept) for the UE, plus the N2
/// SM info carrying the UPF's UL N3 F-TEID.
pub fn pdu_session_resource_setup_request(
    amf_ue_id: u64,
    ran_ue_id: u32,
    psi: u8,
    flows: &[QosFlow],
    upf_teid: u32,
    upf_addr: Ipv4Addr,
    ue_ambr_dl_bps: u64,
    ue_ambr_ul_bps: u64,
    pdu_type: PduSessionType,
    nas: Vec<u8>,
) -> NGAP_PDU {
    let transfer = encode_aper(&setup_request_transfer(flows, upf_teid, upf_addr, pdu_type));
    build_ngap!(InitiatingMessage, PDUSessionResourceSetup,
        REJECT, PDUSessionResourceSetupRequest,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        // UE Aggregate Maximum Bit Rate (TS 38.413 §9.3.1.58) — the subscribed
        // UE-AMBR from am-data, so the gNB enforces the non-GBR rate cap.
        IGNORE UEAggregateMaximumBitRate(UEAggregateMaximumBitRate {
            ue_aggregate_maximum_bit_rate_dl: BitRate(ue_ambr_dl_bps),
            ue_aggregate_maximum_bit_rate_ul: BitRate(ue_ambr_ul_bps),
            ie_extensions: None,
        }),
        REJECT PDUSessionResourceSetupListSUReq(PDUSessionResourceSetupListSUReq(vec![
            PDUSessionResourceSetupItemSUReq {
                pdu_session_id: PDUSessionID(psi),
                pdu_session_nas_pdu: Some(NAS_PDU(nas)),
                s_nssai: s_nssai(1, None),
                pdu_session_resource_setup_request_transfer:
                    PDUSessionResourceSetupItemSUReqPDUSessionResourceSetupRequestTransfer(transfer),
                ie_extensions: None,
            },
        ])),
    )
}

/// Build a `PDUSessionResourceSetupResponse` (gNB→AMF) reporting the gNB's DL N3 F-TEID
/// for `psi` — for tests and a gNB simulator.
pub fn pdu_session_resource_setup_response(
    amf_ue_id: u64,
    ran_ue_id: u32,
    psi: u8,
    qfi: u8,
    gnb_teid: u32,
    gnb_addr: Ipv4Addr,
) -> NGAP_PDU {
    let transfer = encode_aper(&setup_response_transfer(qfi, gnb_teid, gnb_addr));
    build_ngap!(SuccessfulOutcome, PDUSessionResourceSetup,
        REJECT, PDUSessionResourceSetupResponse,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT PDUSessionResourceSetupListSURes(PDUSessionResourceSetupListSURes(vec![
            PDUSessionResourceSetupItemSURes {
                pdu_session_id: PDUSessionID(psi),
                pdu_session_resource_setup_response_transfer:
                    PDUSessionResourceSetupItemSUResPDUSessionResourceSetupResponseTransfer(transfer),
                ie_extensions: None,
            },
        ])),
    )
}

/// Extract `(pdu_session_id, gNB N3 TEID, gNB N3 IPv4)` from a decoded
/// `PDUSessionResourceSetupResponse` — the gNB F-TEID the AMF feeds to UpdateSMContext.
pub fn gnb_fteid_from_setup_response(pdu: &NGAP_PDU) -> Option<(u8, u32, Ipv4Addr)> {
    let NGAP_PDU::SuccessfulOutcome(so) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_PDUSessionResourceSetup(resp) = &so.value else {
        return None;
    };
    let list = resp.protocol_i_es.0.iter().find_map(|e| match &e.value {
        PDUSessionResourceSetupResponseProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListSURes(l) => Some(l),
        _ => None,
    })?;
    let item = list.0.first()?;
    let mut codec = PerCodecData::from_slice_aper(&item.pdu_session_resource_setup_response_transfer.0);
    let transfer = PDUSessionResourceSetupResponseTransfer::aper_decode(&mut codec).ok()?;
    let (teid, addr) = fteid_from_uptnl(&transfer.dl_qos_flow_per_tnl_information.up_transport_layer_information)?;
    Some((item.pdu_session_id.0, teid, addr))
}

/// gNB side: parse a `PDUSessionResourceSetupRequest` — `(AMF-UE-NGAP-ID,
/// RAN-UE-NGAP-ID, per-session (psi, UPF UL N3 TEID, UPF N3 IPv4, NAS-PDU))`. The
/// NAS-PDU is the (protected) DL NAS Transport the gNB relays to the UE; the F-TEID
/// is where the gNB tunnels uplink. For tests / a gNB simulator.
#[allow(clippy::type_complexity)]
pub fn pdu_session_resource_setup_request_params(
    pdu: &NGAP_PDU,
) -> Option<(u64, u32, Vec<(u8, u32, Ipv4Addr, Vec<u8>)>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_PDUSessionResourceSetup(req) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut list) = (None, None, None);
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListSUReq(l) => {
                list = Some(l)
            }
            _ => {}
        }
    }
    let sessions = list?
        .0
        .iter()
        .filter_map(|item| {
            let mut codec =
                PerCodecData::from_slice_aper(&item.pdu_session_resource_setup_request_transfer.0);
            let transfer = PDUSessionResourceSetupRequestTransfer::aper_decode(&mut codec).ok()?;
            let (teid, addr) = transfer.protocol_i_es.0.iter().find_map(|e| match &e.value {
                PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue::Id_UL_NGU_UP_TNLInformation(u) => fteid_from_uptnl(u),
                _ => None,
            })?;
            let nas = item.pdu_session_nas_pdu.as_ref().map(|n| n.0.clone()).unwrap_or_default();
            Some((item.pdu_session_id.0, teid, addr, nas))
        })
        .collect();
    Some((amf_ue_id?, ran_ue_id?, sessions))
}

/// The N2 SM info for a modification: the session AMBR, the add-or-modified QoS
/// flows, and the released QoS flows (`released_qfis`).
fn modify_request_transfer(
    flows: &[QosFlow],
    session_ambr_dl_bps: u64,
    session_ambr_ul_bps: u64,
    released_qfis: &[u8],
) -> PDUSessionResourceModifyRequestTransfer {
    let mut ies = vec![
        build_ngap_ie!(PDUSessionResourceModifyRequestTransfer, IGNORE PDUSessionAggregateMaximumBitRate(PDUSessionAggregateMaximumBitRate {
            pdu_session_aggregate_maximum_bit_rate_dl: BitRate(session_ambr_dl_bps),
            pdu_session_aggregate_maximum_bit_rate_ul: BitRate(session_ambr_ul_bps),
            ie_extensions: None,
        })),
    ];
    // The add-or-modify list must have ≥1 item (APER sz_lb=1) — include it only
    // when there are flows to add or modify.
    if !flows.is_empty() {
        ies.push(build_ngap_ie!(PDUSessionResourceModifyRequestTransfer, REJECT QosFlowAddOrModifyRequestList(qos_flow_add_or_modify_list(flows))));
    }
    // Released flows: tell the gNB to tear each down (5GC-generated reason).
    if !released_qfis.is_empty() {
        let list = QosFlowListWithCause(
            released_qfis
                .iter()
                .map(|q| QosFlowWithCauseItem {
                    qos_flow_identifier: QosFlowIdentifier(*q),
                    cause: Cause::RadioNetwork(CauseRadioNetwork(
                        CauseRadioNetwork::RELEASE_DUE_TO_5GC_GENERATED_REASON,
                    )),
                    ie_extensions: None,
                })
                .collect(),
        );
        ies.push(build_ngap_ie!(PDUSessionResourceModifyRequestTransfer, REJECT QosFlowToReleaseList(list)));
    }
    PDUSessionResourceModifyRequestTransfer {
        protocol_i_es: PDUSessionResourceModifyRequestTransferProtocolIEs(ies),
    }
}

/// Build a `PDUSessionResourceModifyRequest` (AMF→gNB) for a **mid-session QoS
/// change**: the N1 SM container (`nas`, a PDU Session Modification Command) for the
/// UE, plus the N2 SM info carrying the new session AMBR, the updated QoS flows, and
/// the released QoS flows (`released_qfis`).
pub fn pdu_session_resource_modify_request(
    amf_ue_id: u64,
    ran_ue_id: u32,
    psi: u8,
    flows: &[QosFlow],
    session_ambr_dl_bps: u64,
    session_ambr_ul_bps: u64,
    released_qfis: &[u8],
    nas: Vec<u8>,
) -> NGAP_PDU {
    let transfer =
        encode_aper(&modify_request_transfer(flows, session_ambr_dl_bps, session_ambr_ul_bps, released_qfis));
    build_ngap!(InitiatingMessage, PDUSessionResourceModify,
        REJECT, PDUSessionResourceModifyRequest,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT PDUSessionResourceModifyListModReq(PDUSessionResourceModifyListModReq(vec![
            PDUSessionResourceModifyItemModReq {
                pdu_session_id: PDUSessionID(psi),
                nas_pdu: Some(NAS_PDU(nas)),
                pdu_session_resource_modify_request_transfer:
                    PDUSessionResourceModifyItemModReqPDUSessionResourceModifyRequestTransfer(transfer),
                ie_extensions: None,
            },
        ])),
    )
}

/// Build a `PDUSessionResourceModifyResponse` (gNB→AMF) accepting the modification
/// of `psi` — for tests and a gNB simulator.
pub fn pdu_session_resource_modify_response(amf_ue_id: u64, ran_ue_id: u32, psi: u8) -> NGAP_PDU {
    let transfer = encode_aper(&PDUSessionResourceModifyResponseTransfer {
        dl_ngu_up_tnl_information: None,
        ul_ngu_up_tnl_information: None,
        qos_flow_add_or_modify_response_list: None,
        additional_dl_qos_flow_per_tnl_information: None,
        qos_flow_failed_to_add_or_modify_list: None,
        ie_extensions: None,
    });
    build_ngap!(SuccessfulOutcome, PDUSessionResourceModify,
        REJECT, PDUSessionResourceModifyResponse,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT PDUSessionResourceModifyListModRes(PDUSessionResourceModifyListModRes(vec![
            PDUSessionResourceModifyItemModRes {
                pdu_session_id: PDUSessionID(psi),
                pdu_session_resource_modify_response_transfer:
                    PDUSessionResourceModifyItemModResPDUSessionResourceModifyResponseTransfer(transfer),
                ie_extensions: None,
            },
        ])),
    )
}

/// Extract `(pdu_session_id, N1 NAS-PDU)` from a `PDUSessionResourceModifyRequest` —
/// the N1 SM container (PDU Session Modification Command) the gNB relays to the UE.
pub fn nas_pdu_from_modify_request(pdu: &NGAP_PDU) -> Option<(u8, Vec<u8>)> {
    let NGAP_PDU::InitiatingMessage(im) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_PDUSessionResourceModify(req) = &im.value else {
        return None;
    };
    let list = req.protocol_i_es.0.iter().find_map(|e| match &e.value {
        PDUSessionResourceModifyRequestProtocolIEs_EntryValue::Id_PDUSessionResourceModifyListModReq(l) => Some(l),
        _ => None,
    })?;
    let item = list.0.first()?;
    let nas = item.nas_pdu.as_ref()?.0.clone();
    Some((item.pdu_session_id.0, nas))
}

/// The `(amf_ue_id, ran_ue_id, [modified pdu_session_id])` reported by a decoded
/// `PDUSessionResourceModifyResponse` — the AMF's confirmation the gNB applied it.
pub fn modify_response_result(pdu: &NGAP_PDU) -> Option<(u64, u32, Vec<u8>)> {
    let NGAP_PDU::SuccessfulOutcome(so) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_PDUSessionResourceModify(resp) = &so.value else {
        return None;
    };
    let mut amf_ue_id = None;
    let mut ran_ue_id = None;
    let mut modified = Vec::new();
    for e in &resp.protocol_i_es.0 {
        match &e.value {
            PDUSessionResourceModifyResponseProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            PDUSessionResourceModifyResponseProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            PDUSessionResourceModifyResponseProtocolIEs_EntryValue::Id_PDUSessionResourceModifyListModRes(l) => {
                modified = l.0.iter().map(|it| it.pdu_session_id.0).collect()
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, modified))
}

/// Build a `PDUSessionResourceReleaseCommand` (TS 38.413 §9.2.1.6) — the AMF asks
/// the NG-RAN to release `psi`'s resources. The N1 **PDU Session Release Command**
/// rides as the NAS-PDU (the gNB relays it to the UE); the per-session transfer
/// carries a NAS *normal-release* cause. Network-initiated PDU session release
/// (TS 23.502 §4.3.4).
pub fn pdu_session_resource_release_command(
    amf_ue_id: u64,
    ran_ue_id: u32,
    psi: u8,
    nas: Vec<u8>,
) -> NGAP_PDU {
    let transfer = encode_aper(&PDUSessionResourceReleaseCommandTransfer {
        cause: Cause::Nas(CauseNas(CauseNas::NORMAL_RELEASE)),
        ie_extensions: None,
    });
    build_ngap!(InitiatingMessage, PDUSessionResourceRelease,
        REJECT, PDUSessionResourceReleaseCommand,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        IGNORE NAS_PDU(NAS_PDU(nas)),
        REJECT PDUSessionResourceToReleaseListRelCmd(PDUSessionResourceToReleaseListRelCmd(vec![
            PDUSessionResourceToReleaseItemRelCmd {
                pdu_session_id: PDUSessionID(psi),
                pdu_session_resource_release_command_transfer:
                    PDUSessionResourceToReleaseItemRelCmdPDUSessionResourceReleaseCommandTransfer(transfer),
                ie_extensions: None,
            },
        ])),
    )
}

/// Extract `(pdu_session_id, N1 NAS-PDU)` from a `PDUSessionResourceReleaseCommand` —
/// the N1 SM container (PDU Session Release Command) the gNB relays to the UE, and
/// the released session id. The gNB side / tests.
pub fn nas_pdu_from_release_command(pdu: &NGAP_PDU) -> Option<(u8, Vec<u8>)> {
    let NGAP_PDU::InitiatingMessage(im) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_PDUSessionResourceRelease(cmd) = &im.value else {
        return None;
    };
    let mut nas = None;
    let mut psi = None;
    for e in &cmd.protocol_i_es.0 {
        match &e.value {
            PDUSessionResourceReleaseCommandProtocolIEs_EntryValue::Id_NAS_PDU(n) => {
                nas = Some(n.0.clone())
            }
            PDUSessionResourceReleaseCommandProtocolIEs_EntryValue::Id_PDUSessionResourceToReleaseListRelCmd(l) => {
                psi = l.0.first().map(|it| it.pdu_session_id.0)
            }
            _ => {}
        }
    }
    Some((psi?, nas?))
}

/// Build a `PDUSessionResourceReleaseResponse` (gNB→AMF) confirming `psi`'s
/// resources were released — for tests and a gNB simulator.
pub fn pdu_session_resource_release_response(amf_ue_id: u64, ran_ue_id: u32, psi: u8) -> NGAP_PDU {
    let transfer = encode_aper(&PDUSessionResourceReleaseResponseTransfer { ie_extensions: None });
    build_ngap!(SuccessfulOutcome, PDUSessionResourceRelease,
        REJECT, PDUSessionResourceReleaseResponse,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        IGNORE PDUSessionResourceReleasedListRelRes(PDUSessionResourceReleasedListRelRes(vec![
            PDUSessionResourceReleasedItemRelRes {
                pdu_session_id: PDUSessionID(psi),
                pdu_session_resource_release_response_transfer:
                    PDUSessionResourceReleasedItemRelResPDUSessionResourceReleaseResponseTransfer(transfer),
                ie_extensions: None,
            },
        ])),
    )
}

/// The `(amf_ue_id, ran_ue_id, [released pdu_session_id])` reported by a decoded
/// `PDUSessionResourceReleaseResponse` — the AMF's confirmation the gNB released
/// the resources.
pub fn release_response_result(pdu: &NGAP_PDU) -> Option<(u64, u32, Vec<u8>)> {
    let NGAP_PDU::SuccessfulOutcome(so) = pdu else {
        return None;
    };
    let SuccessfulOutcomeValue::Id_PDUSessionResourceRelease(resp) = &so.value else {
        return None;
    };
    let mut amf_ue_id = None;
    let mut ran_ue_id = None;
    let mut released = Vec::new();
    for e in &resp.protocol_i_es.0 {
        match &e.value {
            PDUSessionResourceReleaseResponseProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            PDUSessionResourceReleaseResponseProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            PDUSessionResourceReleaseResponseProtocolIEs_EntryValue::Id_PDUSessionResourceReleasedListRelRes(l) => {
                released = l.0.iter().map(|it| it.pdu_session_id.0).collect()
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, released))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdu_session_resource_release_roundtrips() {
        // The command carries the N1 release command + the released psi; the gNB
        // parses both, and its response reports the released session back.
        let n1 = vec![0x2e, 5, 0, 0xd3, 36];
        let cmd = pdu_session_resource_release_command(7, 3, 5, n1.clone());
        let back = NGAP_PDU::decode(&cmd.encode().expect("encode")).expect("decode");
        assert_eq!(nas_pdu_from_release_command(&back), Some((5, n1)));

        let resp = pdu_session_resource_release_response(7, 3, 5);
        let back = NGAP_PDU::decode(&resp.encode().expect("encode")).expect("decode");
        assert_eq!(release_response_result(&back), Some((7, 3, vec![5])));
    }

    #[test]
    fn pdu_session_resource_setup_request_roundtrips() {
        let pdu = pdu_session_resource_setup_request(
            1,
            2,
            5,
            &[
                QosFlow::default_non_gbr(),
                QosFlow {
                    qfi: 2,
                    five_qi: 1,
                    arp_priority: 5,
                    pre_empt_cap: true,
                    pre_empt_vuln: false,
                    gbr: Some(Gbr {
                        gfbr_dl_bps: 100_000_000,
                        gfbr_ul_bps: 100_000_000,
                        mfbr_dl_bps: 200_000_000,
                        mfbr_ul_bps: 200_000_000,
                    }),
                },
            ],
            0x1111,
            Ipv4Addr::new(127, 0, 0, 1),
            2_000_000_000,
            1_000_000_000,
            PduSessionType::Ipv4,
            vec![0x2e, 0x05, 0x01, 0xc2],
        );
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(pdu, back, "the UE-AMBR IE survives the APER round trip");
        assert_eq!(back.procedure_name(), "PDUSessionResourceSetup");
        assert!(back.is_initiating());
    }

    #[test]
    fn setup_response_yields_gnb_fteid() {
        let gnb_addr = Ipv4Addr::new(10, 0, 0, 9);
        let pdu = pdu_session_resource_setup_response(1, 2, 5, 1, 0x5678, gnb_addr);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(gnb_fteid_from_setup_response(&back), Some((5, 0x5678, gnb_addr)));
    }

    /// The gNB-side parser recovers the AMF/RAN ids, the UPF UL F-TEID, and the
    /// relayed NAS-PDU from a setup request the AMF built.
    #[test]
    fn setup_request_params_recovers_fteid_and_nas() {
        let upf_addr = Ipv4Addr::new(127, 0, 0, 1);
        let nas = vec![0x7e, 0x02, 0xde, 0xad, 0xbe, 0xef, 0x00];
        let pdu = pdu_session_resource_setup_request(
            9,
            4,
            5,
            &[QosFlow::default_non_gbr()],
            0x1234,
            upf_addr,
            2_000_000_000,
            1_000_000_000,
            PduSessionType::Ipv4,
            nas.clone(),
        );
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        let (amf_ue_id, ran_ue_id, sessions) =
            pdu_session_resource_setup_request_params(&back).expect("params");
        assert_eq!((amf_ue_id, ran_ue_id), (9, 4));
        assert_eq!(sessions, vec![(5, 0x1234, upf_addr, nas)]);
    }

    #[test]
    fn modify_request_roundtrips() {
        let pdu = pdu_session_resource_modify_request(
            1,
            2,
            5,
            &[
                QosFlow::default_non_gbr(),
                QosFlow {
                    qfi: 2,
                    five_qi: 1,
                    arp_priority: 5,
                    pre_empt_cap: true,
                    pre_empt_vuln: false,
                    gbr: Some(Gbr {
                        gfbr_dl_bps: 10_000_000,
                        gfbr_ul_bps: 10_000_000,
                        mfbr_dl_bps: 20_000_000,
                        mfbr_ul_bps: 20_000_000,
                    }),
                },
            ],
            100_000_000,
            50_000_000,
            &[3], // release QFI 3
            vec![0x2e, 0x05, 0x00, 0xcb],
        );
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(pdu, back, "the AMBR + add-or-modify + release lists survive the APER round trip");
        assert_eq!(back.procedure_name(), "PDUSessionResourceModify");
        assert!(back.is_initiating());
    }

    #[test]
    fn modify_response_yields_result() {
        let pdu = pdu_session_resource_modify_response(7, 3, 5);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(modify_response_result(&back), Some((7, 3, vec![5])));
    }

    #[test]
    fn ng_setup_response_roundtrips() {
        let pdu = ng_setup_response("radian-amf", "999", "70");
        let bytes = pdu.encode().expect("APER encode");
        let back = NGAP_PDU::decode(&bytes).expect("APER decode");
        assert_eq!(pdu, back);
        assert_eq!(back.procedure_name(), "NGSetup");
        assert!(matches!(back, NGAP_PDU::SuccessfulOutcome(_)));
    }

    #[test]
    fn downlink_nas_transport_roundtrips() {
        let pdu = downlink_nas_transport(1, 2, vec![0x7e, 0x00, 0x5b, 0x01]);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(pdu, back);
        assert_eq!(back.procedure_name(), "DownlinkNASTransport");
        assert!(back.is_initiating());
    }

    #[test]
    fn uplink_nas_transport_roundtrips() {
        let pdu = uplink_nas_transport(1, 2, vec![0x7e, 0x00, 0x5c, 0x00]);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(pdu, back);
        assert_eq!(back.procedure_name(), "UplinkNASTransport");
    }
}

#[cfg(test)]
mod release_tests {
    use super::*;

    #[test]
    fn ue_context_release_command_roundtrips() {
        let pdu = ue_context_release_command(42, 7, CauseNas::NORMAL_RELEASE);
        let mut data = PerCodecData::new_aper();
        pdu.aper_encode(&mut data).expect("APER encode");
        let bytes = data.get_inner().expect("bytes");
        let back = NGAP_PDU::decode(&bytes).expect("APER decode");
        assert_eq!(
            parse_ue_context_release_command(&back),
            Some((42, 7, Some(CauseNas::NORMAL_RELEASE)))
        );

        // The radio-network-cause variant (successful handover toward the source gNB).
        let pdu = ue_context_release_command_radio(42, 7, CauseRadioNetwork::SUCCESSFUL_HANDOVER);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            parse_ue_context_release_command(&back),
            Some((42, 7, None)),
            "ids parse; the cause is not a NAS cause"
        );
        assert_eq!(
            release_command_radio_cause(&back),
            Some(CauseRadioNetwork::SUCCESSFUL_HANDOVER)
        );
        assert_eq!(release_command_radio_cause(&initial_ue_message_with_nas(1, vec![1])), None);
    }

    #[test]
    fn initial_ue_with_stmsi_roundtrips() {
        let pdu = initial_ue_message_with_stmsi(4, 0x00A1_B2C3, vec![0x7e, 0x00]);
        let mut data = PerCodecData::new_aper();
        pdu.aper_encode(&mut data).expect("APER encode");
        let bytes = data.get_inner().expect("bytes");
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) =
            NGAP_PDU::decode(&bytes).expect("APER decode")
        else {
            panic!("not an initiating message");
        };
        let InitiatingMessageValue::Id_InitialUEMessage(msg) = value else {
            panic!("not an InitialUEMessage");
        };
        assert_eq!(fiveg_s_tmsi_from_initial_ue(&msg), Some(0x00A1_B2C3));
        // An InitialUEMessage without the S-TMSI IE yields None.
        let InitiatingMessageValue::Id_InitialUEMessage(plain) =
            (match initial_ue_message_with_nas(4, vec![1]) {
                NGAP_PDU::InitiatingMessage(m) => m.value,
                _ => unreachable!(),
            })
        else {
            unreachable!()
        };
        assert_eq!(fiveg_s_tmsi_from_initial_ue(&plain), None);
    }

    #[test]
    fn paging_roundtrips() {
        // A multi-TAI registration area rides the TAI List for Paging.
        let area = [[0x00, 0x00, 0x01], [0x00, 0x00, 0x02]];
        let pdu = paging(0x00A1_B2C3, "999", "70", &area);
        let mut data = PerCodecData::new_aper();
        pdu.aper_encode(&mut data).expect("APER encode");
        let bytes = data.get_inner().expect("bytes");
        let back = NGAP_PDU::decode(&bytes).expect("APER decode");
        assert_eq!(tmsi_from_paging(&back), Some(0x00A1_B2C3));
        assert_eq!(tacs_from_paging(&back), Some(area.to_vec()));
        // A non-Paging message has no paged TMSI.
        assert_eq!(tmsi_from_paging(&initial_ue_message_with_nas(1, vec![1])), None);
        assert_eq!(tacs_from_paging(&initial_ue_message_with_nas(1, vec![1])), None);
    }

    #[test]
    fn ue_context_release_request_roundtrips() {
        // Cause radioNetwork #20 = user-inactivity.
        let pdu = ue_context_release_request(99, 3, 20);
        let mut data = PerCodecData::new_aper();
        pdu.aper_encode(&mut data).expect("APER encode");
        let bytes = data.get_inner().expect("bytes");
        let back = NGAP_PDU::decode(&bytes).expect("APER decode");
        assert_eq!(parse_ue_context_release_request(&back), Some((99, 3)));
        // A different message type isn't misread as a release request.
        assert_eq!(parse_ue_context_release_request(&initial_ue_message_with_nas(1, vec![1])), None);
    }

    #[test]
    fn user_location_and_supported_tas_roundtrip() {
        // The UE's TAI rides the InitialUEMessage (registration and resume forms).
        let pdu = initial_ue_message_with_nas_at(1, vec![0x7e], "999", "70", &[0, 0, 2]);
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) =
            NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode")
        else {
            panic!("not an initiating message");
        };
        let InitiatingMessageValue::Id_InitialUEMessage(msg) = &value else {
            panic!("not an InitialUEMessage");
        };
        assert_eq!(tac_from_initial_ue(msg), Some([0, 0, 2]));

        let pdu = initial_ue_message_with_stmsi_at(1, 0xbeef, vec![0x7e], "999", "70", &[0, 0, 3]);
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) =
            NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode")
        else {
            panic!("not an initiating message");
        };
        let InitiatingMessageValue::Id_InitialUEMessage(msg) = &value else {
            panic!("not an InitialUEMessage");
        };
        assert_eq!(tac_from_initial_ue(msg), Some([0, 0, 3]));
        assert_eq!(fiveg_s_tmsi_from_initial_ue(msg), Some(0xbeef), "5G-S-TMSI still present");

        // A ULI-less InitialUEMessage yields no TAC (the old builders).
        let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) =
            initial_ue_message_with_nas(1, vec![0x7e])
        else {
            panic!();
        };
        let InitiatingMessageValue::Id_InitialUEMessage(msg) = &value else { panic!() };
        assert_eq!(tac_from_initial_ue(msg), None);

        // The gNB's supported TAs ride the NGSetupRequest.
        let pdu = ng_setup_request(7, "999", "70", &[[0, 0, 1], [0, 0, 2]]);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(supported_tacs_from_ng_setup(&back), Some(vec![[0, 0, 1], [0, 0, 2]]));
        assert_eq!(gnb_id_from_ng_setup(&back), Some(7), "the gNB id parses back");
        assert_eq!(gnb_id_from_ng_setup(&initial_ue_message_with_nas(1, vec![1])), None);
        assert_eq!(supported_tacs_from_ng_setup(&initial_ue_message_with_nas(1, vec![1])), None);
    }

    #[test]
    fn downlink_nas_with_area_restriction_roundtrips() {
        // Allowed TAC 000001, non-allowed TAC 00000a, riding on a NAS PDU.
        let pdu = downlink_nas_transport_with_area_restriction(
            7,
            3,
            vec![0xde, 0xad],
            "999",
            "70",
            &[[0, 0, 1]],
            &[[0, 0, 0x0a]],
        );
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            area_restriction_from_downlink_nas(&back),
            Some((vec![[0, 0, 1]], vec![[0, 0, 0x0a]]))
        );
        // A plain DownlinkNASTransport has no restriction.
        assert_eq!(area_restriction_from_downlink_nas(&downlink_nas_transport(7, 3, vec![1])), None);
    }

    #[test]
    fn n2_handover_messages_roundtrip() {
        let addr = Ipv4Addr::new(10, 0, 8, 1);

        // Handover Required: source → AMF (target gNB id + sessions + direct
        // forwarding availability + container).
        let pdu = handover_required(7, 4, 9, "999", "70", &[0, 0, 2], &[5], true, b"s2t".to_vec());
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            handover_required_params(&back),
            Some((7, 4, 9, vec![5], true, b"s2t".to_vec()))
        );
        // Without direct forwarding the flag reads back false.
        let plain = handover_required(7, 4, 9, "999", "70", &[0, 0, 2], &[5], false, b"s2t".to_vec());
        let back = NGAP_PDU::decode(&plain.encode().expect("encode")).expect("decode");
        assert!(matches!(handover_required_params(&back), Some((_, _, _, _, false, _))));

        // Handover Request: AMF → target ({NCC, NH} + UL F-TEID per session).
        let nh = [0x6bu8; 32];
        let pdu = handover_request(
            7,
            "999",
            "70",
            (1_000_000_000, 500_000_000),
            &[0x20, 0x20],
            1,
            &nh,
            &[(1, Some([1, 2, 3]))],
            &[(5, vec![QosFlow::default_non_gbr()], 0x33, addr)],
            b"s2t".to_vec(),
        );
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            handover_request_params(&back),
            Some((7, 1, nh, vec![(5, 0x33, addr)], b"s2t".to_vec()))
        );

        // Handover Request Acknowledge: target → AMF (its DL F-TEIDs, a DL
        // forwarding F-TEID for the in-flight data, and the container).
        let fwd = Ipv4Addr::new(10, 0, 9, 6);
        let pdu =
            handover_request_acknowledge(7, 9, &[(5, 0xAA, addr, Some((0xBB, fwd)))], b"t2s".to_vec());
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            handover_request_ack_params(&back),
            Some((7, 9, vec![(5, 0xAA, addr, Some((0xBB, fwd)))], b"t2s".to_vec()))
        );

        // Handover Command: AMF → source (the target's forwarding F-TEID + container).
        let pdu = handover_command(7, 4, &[(5, 0xBB, fwd)], b"t2s".to_vec());
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            handover_command_params(&back),
            Some((7, 4, vec![(5, 0xBB, fwd)], b"t2s".to_vec()))
        );
        // No forwarding → the list IE is omitted and reads back empty.
        let pdu = handover_command(7, 4, &[], b"t2s".to_vec());
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(handover_command_params(&back), Some((7, 4, Vec::new(), b"t2s".to_vec())));

        // Handover Notify: target → AMF (the UE arrived, with its location).
        let pdu = handover_notify(7, 9, "999", "70", &[0, 0, 2]);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(handover_notify_params(&back), Some((7, 9, Some([0, 0, 2]))));

        // Cross-parses fail cleanly.
        assert_eq!(handover_required_params(&handover_notify(1, 2, "999", "70", &[0, 0, 1])), None);
        assert_eq!(handover_notify_params(&initial_ue_message_with_nas(1, vec![1])), None);
    }

    #[test]
    fn handover_failure_messages_roundtrip() {
        // Preparation failure: AMF → source, radio cause.
        let pdu = handover_preparation_failure(7, 4, CauseRadioNetwork::TNGRELOCPREP_EXPIRY);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            handover_preparation_failure_params(&back),
            Some((7, 4, Some(CauseRadioNetwork::TNGRELOCPREP_EXPIRY)))
        );

        // Handover failure: target → AMF.
        let pdu = handover_failure(7, CauseRadioNetwork::HO_TARGET_NOT_ALLOWED);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            handover_failure_params(&back),
            Some((7, Some(CauseRadioNetwork::HO_TARGET_NOT_ALLOWED)))
        );

        // Cancel + acknowledge.
        let pdu = handover_cancel(7, 4, CauseRadioNetwork::HANDOVER_CANCELLED);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(handover_cancel_params(&back), Some((7, 4)));
        let pdu = handover_cancel_acknowledge(7, 4);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(handover_cancel_ack_params(&back), Some((7, 4)));

        // Path switch failure: the requested sessions reported released.
        let pdu = path_switch_request_failure(7, 9, &[5], CauseRadioNetwork::UNKNOWN_LOCAL_UE_NGAP_ID);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(path_switch_failure_params(&back), Some((7, 9, vec![5])));

        // Cross-parses fail cleanly.
        assert_eq!(handover_failure_params(&handover_cancel_acknowledge(1, 2)), None);
        assert_eq!(handover_cancel_params(&initial_ue_message_with_nas(1, vec![1])), None);
    }

    #[test]
    fn path_switch_roundtrips() {
        // The target gNB's request: new location + the new DL F-TEIDs.
        let addr = Ipv4Addr::new(10, 0, 9, 2);
        let pdu = path_switch_request(7, 9, "999", "70", &[0, 0, 2], &[0x20, 0x20], &[(5, 0x77, addr)]);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            path_switch_params(&back),
            Some((7, 9, Some([0, 0, 2]), vec![(5, 0x77, addr)]))
        );
        assert_eq!(path_switch_params(&initial_ue_message_with_nas(1, vec![1])), None);

        // The AMF's acknowledge: the fresh {NCC, NH} pair + the switched sessions.
        let nh = [0x5au8; 32];
        let ack = path_switch_request_acknowledge(7, 9, 1, &nh, &[5]);
        let back = NGAP_PDU::decode(&ack.encode().expect("encode")).expect("decode");
        assert_eq!(path_switch_ack_security(&back), Some((1, nh, vec![5])));
        // A request isn't misread as an acknowledge, and vice versa.
        assert_eq!(path_switch_ack_security(&pdu), None);
        assert_eq!(path_switch_params(&ack), None);
    }

    #[test]
    fn initial_context_setup_roundtrips() {
        let ic = InitialContext {
            allowed_nssai: vec![(1, Some([1, 2, 3])), (2, None)],
            ue_sec_cap: [0x20, 0x20], // NEA2 / NIA2 only
            security_key: [0xabu8; 32],
            ue_ambr: Some((1_000_000_000, 500_000_000)),
            rfsp: Some(5),
            area_restriction: Some((vec![[0, 0, 1]], Vec::new())),
            pdu_sessions: Vec::new(),
            nas: vec![0x7e, 0x02, 0x42],
        };
        let pdu = initial_context_setup_request(7, 3, "999", "70", &ic);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        // The parser reports the base context; PDU sessions parse via a dedicated
        // helper (they set up inline, below).
        assert_eq!(initial_context_setup_params(&back), Some((7, 3, ic)));
        assert!(initial_context_setup_session_ids(&back).is_empty());

        // A resume ICS carrying an inline PDU session; the gNB answers with its DL
        // F-TEID in the Cxt Res list.
        let addr = Ipv4Addr::new(10, 0, 1, 2);
        let with_session = InitialContext {
            allowed_nssai: vec![(1, None)],
            ue_sec_cap: [0x20, 0x20],
            security_key: [0x22u8; 32],
            pdu_sessions: vec![IcsPduSession {
                psi: 5,
                flows: vec![QosFlow::default_non_gbr()],
                upf_teid: 0x11,
                upf_addr: addr,
            }],
            nas: vec![0x7e],
            ..Default::default()
        };
        let pdu = initial_context_setup_request(8, 4, "999", "70", &with_session);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        // The base fields still parse (sessions aren't reflected into the struct).
        let (a, r, _) = initial_context_setup_params(&back).expect("ICS parses");
        assert_eq!((a, r), (8, 4));
        // The gNB's response carries its DL F-TEID for the inline session.
        let resp = initial_context_setup_response_with_sessions(8, 4, &[(5, 0x99, addr)]);
        let back = NGAP_PDU::decode(&resp.encode().expect("encode")).expect("decode");
        assert_eq!(initial_context_setup_session_ids(&back), vec![(5, 0x99, addr)]);
        assert_eq!(initial_context_setup_response_ids(&back), Some((8, 4)));
        assert!(initial_context_setup_failed_session_ids(&back).is_empty());

        // A response admitting one session (5) and rejecting another (6): each list
        // round-trips independently, and the rejected session's cause is read back.
        let resp = initial_context_setup_response_with_results(
            8,
            4,
            &[(5, 0x99, addr)],
            &[(6, CauseRadioNetwork::MULTIPLE_PDU_SESSION_ID_INSTANCES)],
        );
        let back = NGAP_PDU::decode(&resp.encode().expect("encode")).expect("decode");
        assert_eq!(initial_context_setup_session_ids(&back), vec![(5, 0x99, addr)]);
        assert_eq!(
            initial_context_setup_failed_session_ids(&back),
            vec![(6, CauseRadioNetwork::MULTIPLE_PDU_SESSION_ID_INSTANCES)]
        );

        // The optional IEs are genuinely optional.
        let bare = InitialContext {
            allowed_nssai: vec![(1, None)],
            ue_sec_cap: [0x20, 0x20],
            security_key: [0x11u8; 32],
            nas: vec![0x7e],
            ..Default::default()
        };
        let pdu = initial_context_setup_request(1, 2, "999", "70", &bare);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(initial_context_setup_params(&back), Some((1, 2, bare)));

        // The gNB's response round-trips; a request isn't misread as one.
        let resp = initial_context_setup_response(7, 3);
        let back = NGAP_PDU::decode(&resp.encode().expect("encode")).expect("decode");
        assert_eq!(initial_context_setup_response_ids(&back), Some((7, 3)));
        assert_eq!(initial_context_setup_response_ids(&pdu), None);
        assert_eq!(initial_context_setup_params(&resp), None);
    }

    #[test]
    fn ue_context_modification_roundtrips() {
        // RFSP index 7 + UE-AMBR 300/600 Mbps (dl/ul) reach the RAN intact.
        let pdu = ue_context_modification_request(42, 5, Some(7), Some((600_000_000, 300_000_000)));
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(
            ue_context_modification_params(&back),
            Some((42, 5, Some(7), Some((600_000_000, 300_000_000))))
        );

        // The optional IEs are genuinely optional: a request with neither still
        // carries just the two UE-NGAP-IDs.
        let bare = ue_context_modification_request(1, 2, None, None);
        let back = NGAP_PDU::decode(&bare.encode().expect("encode")).expect("decode");
        assert_eq!(ue_context_modification_params(&back), Some((1, 2, None, None)));

        // The gNB's acknowledgement round-trips to the same IDs.
        let resp = ue_context_modification_response(42, 5);
        let back = NGAP_PDU::decode(&resp.encode().expect("encode")).expect("decode");
        assert_eq!(ue_context_modification_response_ids(&back), Some((42, 5)));
        // A request isn't misread as a response, and vice versa.
        assert_eq!(ue_context_modification_response_ids(&pdu), None);
        assert_eq!(ue_context_modification_params(&resp), None);
    }
}

// ── gNB-side helpers (the standalone RAN element — design/128 Phase 0) ─────────────────

/// gNB side: `(AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, NAS-PDU)` from a
/// `DownlinkNASTransport`. Unlike the single-UE scripted tier, a standalone gNB
/// needs the RAN-UE-NGAP-ID to route the NAS to the right UE context.
pub fn downlink_nas_transport_params(pdu: &NGAP_PDU) -> Option<(u64, u32, Vec<u8>)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return None;
    };
    let InitiatingMessageValue::Id_DownlinkNASTransport(msg) = value else {
        return None;
    };
    let (mut amf_ue_id, mut ran_ue_id, mut nas) = (None, None, None);
    for ie in &msg.protocol_i_es.0 {
        match &ie.value {
            DownlinkNASTransportProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            DownlinkNASTransportProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(v) => {
                ran_ue_id = Some(v.0)
            }
            DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(v) => nas = Some(v.0.clone()),
            _ => {}
        }
    }
    Some((amf_ue_id?, ran_ue_id?, nas?))
}

/// Build a `UEContextReleaseComplete` (TS 38.413 §9.2.2.5) — the gNB's
/// confirmation that it released the context a UEContextReleaseCommand named.
pub fn ue_context_release_complete(amf_ue_id: u64, ran_ue_id: u32) -> NGAP_PDU {
    build_ngap!(SuccessfulOutcome, UEContextRelease,
        REJECT, UEContextReleaseComplete,
        IGNORE AMF_UE_NGAP_ID(amf_ue_id),
        IGNORE RAN_UE_NGAP_ID(ran_ue_id),
    )
}

/// The first QoS flow's QFI in an encoded `PDUSessionResourceSetupRequestTransfer`.
fn first_qfi_from_setup_transfer(bytes: &[u8]) -> Option<u8> {
    let mut codec = PerCodecData::from_slice_aper(bytes);
    let transfer = PDUSessionResourceSetupRequestTransfer::aper_decode(&mut codec).ok()?;
    transfer.protocol_i_es.0.iter().find_map(|e| match &e.value {
        PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue::Id_QosFlowSetupRequestList(l) => {
            l.0.first().map(|f| f.qos_flow_identifier.0)
        }
        _ => None,
    })
}

/// gNB side: `(psi, QFI)` per PDU session of a `PDUSessionResourceSetupRequest` —
/// the QFI of each session's **first** QoS flow, aligned with
/// [`pdu_session_resource_setup_request_params`]. The gNB marks uplink N3 G-PDUs
/// with this QFI (TS 38.415 UL PDU SESSION INFORMATION).
pub fn pdu_session_setup_request_qfis(pdu: &NGAP_PDU) -> Vec<(u8, u8)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return Vec::new();
    };
    let InitiatingMessageValue::Id_PDUSessionResourceSetup(req) = value else {
        return Vec::new();
    };
    let Some(list) = req.protocol_i_es.0.iter().find_map(|e| match &e.value {
        PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListSUReq(l) => Some(l),
        _ => None,
    }) else {
        return Vec::new();
    };
    list.0
        .iter()
        .filter_map(|item| {
            let qfi = first_qfi_from_setup_transfer(&item.pdu_session_resource_setup_request_transfer.0)?;
            Some((item.pdu_session_id.0, qfi))
        })
        .collect()
}

/// gNB side: `(psi, QFI)` per PDU session an `InitialContextSetupRequest` sets up
/// inline (the Service Request resume path) — aligned with
/// [`initial_context_setup_request_session_ids`].
pub fn initial_context_setup_request_qfis(pdu: &NGAP_PDU) -> Vec<(u8, u8)> {
    let NGAP_PDU::InitiatingMessage(InitiatingMessage { value, .. }) = pdu else {
        return Vec::new();
    };
    let InitiatingMessageValue::Id_InitialContextSetup(req) = value else {
        return Vec::new();
    };
    let Some(list) = req.protocol_i_es.0.iter().find_map(|e| match &e.value {
        InitialContextSetupRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListCxtReq(l) => Some(l),
        _ => None,
    }) else {
        return Vec::new();
    };
    list.0
        .iter()
        .filter_map(|item| {
            let qfi = first_qfi_from_setup_transfer(&item.pdu_session_resource_setup_request_transfer.0)?;
            Some((item.pdu_session_id.0, qfi))
        })
        .collect()
}

#[cfg(test)]
mod gnb_side_tests {
    use super::*;

    #[test]
    fn downlink_nas_transport_params_roundtrips() {
        let nas = vec![0x7e, 0x00, 0x56, 0x01];
        let pdu = downlink_nas_transport(9, 4, nas.clone());
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(downlink_nas_transport_params(&back), Some((9, 4, nas)));
        // An uplink transport is not misread as a downlink one.
        assert_eq!(downlink_nas_transport_params(&uplink_nas_transport(9, 4, vec![0x7e])), None);
    }

    #[test]
    fn ue_context_release_complete_roundtrips() {
        let pdu = ue_context_release_complete(42, 7);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        // The AMF dispatches on the successful outcome of the UEContextRelease
        // procedure — that is what the gNB's complete must decode to.
        assert!(matches!(
            &back,
            NGAP_PDU::SuccessfulOutcome(SuccessfulOutcome {
                value: SuccessfulOutcomeValue::Id_UEContextRelease(_),
                ..
            })
        ));
        assert_eq!(back.procedure_name(), "UEContextRelease");
    }

    #[test]
    fn setup_request_qfis_extract_the_first_flow() {
        let flows = [QosFlow { qfi: 5, ..QosFlow::default_non_gbr() }];
        let pdu = pdu_session_resource_setup_request(
            1, 2, 6, &flows, 0x1111, Ipv4Addr::LOCALHOST, 1_000_000, 1_000_000, PduSessionType::Ipv4,
            vec![0x7e],
        );
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(pdu_session_setup_request_qfis(&back), vec![(6, 5)]);
        assert!(initial_context_setup_request_qfis(&back).is_empty(), "wrong PDU type");
    }

    #[test]
    fn ics_inline_session_qfis_extract() {
        let ic = InitialContext {
            allowed_nssai: vec![(1, None)],
            ue_sec_cap: [0xa0, 0x20],
            security_key: [0x22u8; 32],
            pdu_sessions: vec![IcsPduSession {
                psi: 1,
                flows: vec![QosFlow { qfi: 3, ..QosFlow::default_non_gbr() }],
                upf_teid: 0x9,
                upf_addr: Ipv4Addr::LOCALHOST,
            }],
            nas: vec![0x7e],
            ..Default::default()
        };
        let pdu = initial_context_setup_request(1, 2, "999", "70", &ic);
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(initial_context_setup_request_qfis(&back), vec![(1, 3)]);
        assert!(pdu_session_setup_request_qfis(&back).is_empty(), "wrong PDU type");
    }
}
