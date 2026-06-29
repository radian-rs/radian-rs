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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ng_setup_response_roundtrips() {
        let pdu = ng_setup_response("radiant-amf", "999", "70");
        let bytes = pdu.encode().expect("APER encode");
        let back = NGAP_PDU::decode(&bytes).expect("APER decode");
        assert_eq!(pdu, back);
        assert_eq!(back.procedure_name(), "NGSetup");
        assert!(matches!(back, NGAP_PDU::SuccessfulOutcome(_)));
    }
}
