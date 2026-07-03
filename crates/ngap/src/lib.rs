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

/// One non-GBR QoS flow (5QI 9, default ARP) for `qfi`.
fn qos_flow_setup_list(qfi: u8) -> QosFlowSetupRequestList {
    QosFlowSetupRequestList(vec![QosFlowSetupRequestItem {
        qos_flow_identifier: QosFlowIdentifier(qfi),
        qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
            qos_characteristics: QosCharacteristics::NonDynamic5QI(NonDynamic5QIDescriptor {
                five_qi: FiveQI(9),
                priority_level_qos: None,
                averaging_window: None,
                maximum_data_burst_volume: None,
                ie_extensions: None,
            }),
            allocation_and_retention_priority: AllocationAndRetentionPriority {
                priority_level_arp: PriorityLevelARP(8),
                pre_emption_capability: Pre_emptionCapability(
                    Pre_emptionCapability::SHALL_NOT_TRIGGER_PRE_EMPTION,
                ),
                pre_emption_vulnerability: Pre_emptionVulnerability(
                    Pre_emptionVulnerability::NOT_PRE_EMPTABLE,
                ),
                ie_extensions: None,
            },
            gbr_qos_information: None,
            reflective_qos_attribute: None,
            additional_qos_flow_information: None,
            ie_extensions: None,
        },
        e_rab_id: None,
        ie_extensions: None,
    }])
}

/// APER-encode a standalone N2 SM-info `*Transfer` sub-PDU to octets.
fn encode_aper<T: AperCodec>(pdu: &T) -> Vec<u8> {
    let mut codec = PerCodecData::new_aper();
    pdu.aper_encode(&mut codec).expect("APER-encode SM-info transfer");
    codec.into_bytes()
}

/// The N2 SM info the SMF gives the gNB: the UPF's UL N3 F-TEID + PDU type + QoS.
fn setup_request_transfer(qfi: u8, upf_teid: u32, upf_addr: Ipv4Addr) -> PDUSessionResourceSetupRequestTransfer {
    PDUSessionResourceSetupRequestTransfer {
        protocol_i_es: PDUSessionResourceSetupRequestTransferProtocolIEs(vec![
            build_ngap_ie!(PDUSessionResourceSetupRequestTransfer, REJECT UL_NGU_UP_TNLInformation(gtp_tunnel(upf_teid, upf_addr))),
            build_ngap_ie!(PDUSessionResourceSetupRequestTransfer, REJECT PDUSessionType(PDUSessionType(PDUSessionType::IPV4))),
            build_ngap_ie!(PDUSessionResourceSetupRequestTransfer, REJECT QosFlowSetupRequestList(qos_flow_setup_list(qfi))),
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
    qfi: u8,
    upf_teid: u32,
    upf_addr: Ipv4Addr,
    nas: Vec<u8>,
) -> NGAP_PDU {
    let transfer = encode_aper(&setup_request_transfer(qfi, upf_teid, upf_addr));
    build_ngap!(InitiatingMessage, PDUSessionResourceSetup,
        REJECT, PDUSessionResourceSetupRequest,
        REJECT AMF_UE_NGAP_ID(amf_ue_id),
        REJECT RAN_UE_NGAP_ID(ran_ue_id),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdu_session_resource_setup_request_roundtrips() {
        let pdu = pdu_session_resource_setup_request(
            1, 2, 5, 1, 0x1111, Ipv4Addr::new(127, 0, 0, 1), vec![0x2e, 0x05, 0x01, 0xc2],
        );
        let back = NGAP_PDU::decode(&pdu.encode().expect("encode")).expect("decode");
        assert_eq!(pdu, back);
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
}
