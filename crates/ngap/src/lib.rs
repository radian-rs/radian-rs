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
    let to_tacs = |ts: &[[u8; 3]]| ts.iter().map(|t| TAC(t.to_vec())).collect::<Vec<_>>();
    let area = ServiceAreaInformation_Item {
        plmn_identity: helpers::plmn(mcc, mnc),
        allowed_ta_cs: (!allowed_tacs.is_empty()).then(|| AllowedTACs(to_tacs(allowed_tacs))),
        not_allowed_ta_cs: (!not_allowed_tacs.is_empty())
            .then(|| NotAllowedTACs(to_tacs(not_allowed_tacs))),
        ie_extensions: None,
    };
    let mrl = MobilityRestrictionList {
        serving_plmn: helpers::plmn(mcc, mnc),
        equivalent_plm_ns: None,
        rat_restrictions: None,
        forbidden_area_information: None,
        service_area_information: Some(ServiceAreaInformation(vec![area])),
        ie_extensions: None,
    };
    build_ngap!(InitiatingMessage, DownlinkNASTransport,
        IGNORE, DownlinkNASTransport,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
        REJECT NAS_PDU(nas),
        IGNORE MobilityRestrictionList(mrl),
    )
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
pub fn paging(tmsi: u32, mcc: &str, mnc: &str, tac: &[u8]) -> NGAP_PDU {
    let tai_list = TAIListForPaging(vec![TAIListForPagingItem {
        tai: helpers::tai(plmn(mcc, mnc), tac),
        ie_extensions: None,
    }]);
    build_ngap!(InitiatingMessage, Paging,
        IGNORE, Paging,
        IGNORE UEPagingIdentity(UEPagingIdentity::FiveG_S_TMSI(fiveg_s_tmsi(tmsi))),
        IGNORE TAIListForPaging(tai_list),
    )
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
#[derive(Debug, Clone, Copy)]
pub struct Gbr {
    pub gfbr_dl_bps: u64,
    pub gfbr_ul_bps: u64,
    pub mfbr_dl_bps: u64,
    pub mfbr_ul_bps: u64,
}

/// One authorized QoS flow (TS 23.501 §5.7) — QFI, 5QI, ARP, and GBR rates when
/// the flow is guaranteed-bit-rate.
#[derive(Debug, Clone, Copy)]
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

/// The N2 SM info the SMF gives the gNB: the UPF's UL N3 F-TEID + PDU type + QoS.
fn setup_request_transfer(flows: &[QosFlow], upf_teid: u32, upf_addr: Ipv4Addr) -> PDUSessionResourceSetupRequestTransfer {
    PDUSessionResourceSetupRequestTransfer {
        protocol_i_es: PDUSessionResourceSetupRequestTransferProtocolIEs(vec![
            build_ngap_ie!(PDUSessionResourceSetupRequestTransfer, REJECT UL_NGU_UP_TNLInformation(gtp_tunnel(upf_teid, upf_addr))),
            build_ngap_ie!(PDUSessionResourceSetupRequestTransfer, REJECT PDUSessionType(PDUSessionType(PDUSessionType::IPV4))),
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
    nas: Vec<u8>,
) -> NGAP_PDU {
    let transfer = encode_aper(&setup_request_transfer(flows, upf_teid, upf_addr));
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let pdu = paging(0x00A1_B2C3, "999", "70", &[0x00, 0x00, 0x01]);
        let mut data = PerCodecData::new_aper();
        pdu.aper_encode(&mut data).expect("APER encode");
        let bytes = data.get_inner().expect("bytes");
        let back = NGAP_PDU::decode(&bytes).expect("APER decode");
        assert_eq!(tmsi_from_paging(&back), Some(0x00A1_B2C3));
        // A non-Paging message has no paged TMSI.
        assert_eq!(tmsi_from_paging(&initial_ue_message_with_nas(1, vec![1])), None);
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
