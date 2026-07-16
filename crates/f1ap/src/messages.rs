//! F1AP message builders and parsers (design/128 Phase 3), over the generated TS 38.473
//! codec. This first slice covers **F1 Setup** (the DU↔CU association) and the three
//! **RRC-transfer** messages that carry RRC across the F1 split — the heart of a CU/DU
//! deployment: the DU relays a UE's RRC up to the CU (where RRC/PDCP live), and the CU
//! sends RRC down. RRC rides opaque (`RRCContainer = OCTET STRING`), exactly as NAS rides
//! opaque inside NGAP. UE Context management + Paging are a follow-up slice.
//!
//! Encoding is APER; builders return the wire PDU bytes and parsers take them back to the
//! fields (the F1AP UE IDs, the SRB id, the RRC container), mirroring `crates/ngap`.

use asn1_codecs::PerCodecData;
use asn1_codecs::aper::AperCodec;
use bitvec::order::Msb0;
use bitvec::vec::BitVec;

use crate::generated::*;

// ── procedure codes (TS 38.473 §9.2) ──────────────────────────────────────────────────────
const PC_F1_SETUP: u8 = 1;
const PC_INITIAL_UL_RRC: u8 = 11;
const PC_DL_RRC: u8 = 12;
const PC_UL_RRC: u8 = 13;

// ── protocol IE ids (TS 38.473 §9.3.1) ────────────────────────────────────────────────────
const IE_GNB_CU_UE_ID: u16 = 40;
const IE_GNB_DU_UE_ID: u16 = 41;
const IE_GNB_DU_ID: u16 = 42;
const IE_RRC_CONTAINER: u16 = 50;
const IE_SRB_ID: u16 = 64;
const IE_TRANSACTION_ID: u16 = 78;
const IE_C_RNTI: u16 = 95;
const IE_NRCGI: u16 = 111;
const IE_GNB_CU_RRC_VERSION: u16 = 170;
const IE_GNB_DU_RRC_VERSION: u16 = 171;

const REJECT: u8 = Criticality::REJECT;
const IGNORE: u8 = Criticality::IGNORE;

// ── codec helpers ─────────────────────────────────────────────────────────────────────────

/// APER-encode an F1AP PDU to wire bytes.
fn encode(pdu: &F1AP_PDU) -> Vec<u8> {
    let mut data = PerCodecData::new_aper();
    pdu.aper_encode(&mut data).expect("F1AP APER encode");
    data.into_bytes()
}

/// APER-decode an F1AP PDU from wire bytes; `None` on a malformed PDU.
pub fn decode(bytes: &[u8]) -> Option<F1AP_PDU> {
    let mut data = PerCodecData::from_slice_aper(bytes);
    F1AP_PDU::aper_decode(&mut data).ok()
}

fn ie_id(id: u16) -> ProtocolIE_ID {
    ProtocolIE_ID(id)
}

/// The 3-octet BCD PLMN (TS 23.003 §2.2): MCC/MNC nibble-packed, `0xF` filling a 2-digit
/// MNC's third nibble.
fn plmn(mcc: &str, mnc: &str) -> PLMN_Identity {
    let d: Vec<u8> = mcc.bytes().chain(mnc.bytes()).map(|b| b - b'0').collect();
    let (mcc, mnc) = (&d[..3], &d[3..]);
    let (mnc3, mnc2, mnc1) = if mnc.len() == 2 {
        (0x0F, mnc[1], mnc[0])
    } else {
        (mnc[2], mnc[1], mnc[0])
    };
    PLMN_Identity(vec![
        (mcc[1] << 4) | mcc[0],
        (mnc3 << 4) | mcc[2],
        (mnc2 << 4) | mnc1,
    ])
}

/// The low `n` bits of `value` as an MSB-first `BIT STRING` of length `n`.
fn bits(value: u64, n: usize) -> BitVec<u8, Msb0> {
    let mut bv = BitVec::<u8, Msb0>::with_capacity(n);
    for i in (0..n).rev() {
        bv.push((value >> i) & 1 == 1);
    }
    bv
}

/// A minimal `RRC-Version` IE (latest-RRC-Version 3-bit field = 0). The peers exchange it
/// at F1 Setup; the value is informational for our purposes.
fn rrc_version() -> RRC_Version {
    RRC_Version {
        latest_rrc_version: RRC_VersionLatest_RRC_Version(bits(0, 3)),
        ie_extensions: None,
    }
}

// ── F1 Setup (DU ↔ CU association) ────────────────────────────────────────────────────────

/// `F1SetupRequest` (DU → CU): the DU registers with the CU (transaction id, gNB-DU-ID,
/// RRC version). Served-cell configuration is omitted (a later slice / real-radio concern).
pub fn f1_setup_request(transaction_id: u8, gnb_du_id: u64) -> Vec<u8> {
    let ies = vec![
        F1SetupRequestProtocolIEs_Entry {
            id: ie_id(IE_TRANSACTION_ID),
            criticality: Criticality(REJECT),
            value: F1SetupRequestProtocolIEs_EntryValue::Id_TransactionID(TransactionID(
                transaction_id,
            )),
        },
        F1SetupRequestProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_ID),
            criticality: Criticality(REJECT),
            value: F1SetupRequestProtocolIEs_EntryValue::Id_gNB_DU_ID(GNB_DU_ID(gnb_du_id)),
        },
        F1SetupRequestProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_RRC_VERSION),
            criticality: Criticality(REJECT),
            value: F1SetupRequestProtocolIEs_EntryValue::Id_GNB_DU_RRC_Version(rrc_version()),
        },
    ];
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_F1_SETUP),
        criticality: Criticality(REJECT),
        value: InitiatingMessageValue::Id_F1Setup(F1SetupRequest {
            protocol_i_es: F1SetupRequestProtocolIEs(ies),
        }),
    }))
}

/// `F1SetupResponse` (CU → DU): the CU accepts the association.
pub fn f1_setup_response(transaction_id: u8) -> Vec<u8> {
    let ies = vec![
        F1SetupResponseProtocolIEs_Entry {
            id: ie_id(IE_TRANSACTION_ID),
            criticality: Criticality(REJECT),
            value: F1SetupResponseProtocolIEs_EntryValue::Id_TransactionID(TransactionID(
                transaction_id,
            )),
        },
        F1SetupResponseProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_RRC_VERSION),
            criticality: Criticality(REJECT),
            value: F1SetupResponseProtocolIEs_EntryValue::Id_GNB_CU_RRC_Version(rrc_version()),
        },
    ];
    encode(&F1AP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode(PC_F1_SETUP),
        criticality: Criticality(REJECT),
        value: SuccessfulOutcomeValue::Id_F1Setup(F1SetupResponse {
            protocol_i_es: F1SetupResponseProtocolIEs(ies),
        }),
    }))
}

/// The transaction id of an `F1SetupRequest`/`Response`, and whether it is the response.
pub fn parse_f1_setup(pdu: &F1AP_PDU) -> Option<(u8, bool)> {
    match pdu {
        F1AP_PDU::InitiatingMessage(InitiatingMessage {
            value: InitiatingMessageValue::Id_F1Setup(req),
            ..
        }) => {
            let txn = req.protocol_i_es.0.iter().find_map(|e| match &e.value {
                F1SetupRequestProtocolIEs_EntryValue::Id_TransactionID(t) => Some(t.0),
                _ => None,
            })?;
            Some((txn, false))
        }
        F1AP_PDU::SuccessfulOutcome(SuccessfulOutcome {
            value: SuccessfulOutcomeValue::Id_F1Setup(resp),
            ..
        }) => {
            let txn = resp.protocol_i_es.0.iter().find_map(|e| match &e.value {
                F1SetupResponseProtocolIEs_EntryValue::Id_TransactionID(t) => Some(t.0),
                _ => None,
            })?;
            Some((txn, true))
        }
        _ => None,
    }
}

// ── RRC transfer (the RRC-over-F1 relay) ──────────────────────────────────────────────────

/// `InitialULRRCMessageTransfer` (DU → CU): a UE appeared on the cell — its first RRC
/// (RRCSetupRequest) with the DU-allocated gNB-DU-UE-F1AP-ID, the serving cell (NR-CGI),
/// and the C-RNTI. The CU allocates a gNB-CU-UE-F1AP-ID and replies with DL RRC.
pub fn initial_ul_rrc_message_transfer(
    gnb_du_ue_id: u32,
    mcc: &str,
    mnc: &str,
    nr_cell_identity: u64,
    c_rnti: u16,
    rrc: Vec<u8>,
) -> Vec<u8> {
    let nrcgi = NRCGI {
        plmn_identity: plmn(mcc, mnc),
        nr_cell_identity: NRCellIdentity(bits(nr_cell_identity, 36)),
        ie_extensions: None,
    };
    let ies = vec![
        InitialULRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: InitialULRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
        InitialULRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_NRCGI),
            criticality: Criticality(REJECT),
            value: InitialULRRCMessageTransferProtocolIEs_EntryValue::Id_NRCGI(nrcgi),
        },
        InitialULRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_C_RNTI),
            criticality: Criticality(REJECT),
            value: InitialULRRCMessageTransferProtocolIEs_EntryValue::Id_C_RNTI(C_RNTI(c_rnti)),
        },
        InitialULRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_RRC_CONTAINER),
            criticality: Criticality(REJECT),
            value: InitialULRRCMessageTransferProtocolIEs_EntryValue::Id_RRCContainer(
                RRCContainer(rrc),
            ),
        },
    ];
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_INITIAL_UL_RRC),
        criticality: Criticality(IGNORE),
        value: InitiatingMessageValue::Id_InitialULRRCMessageTransfer(
            InitialULRRCMessageTransfer {
                protocol_i_es: InitialULRRCMessageTransferProtocolIEs(ies),
            },
        ),
    }))
}

/// `(gNB-DU-UE-F1AP-ID, C-RNTI, RRC container)` from an `InitialULRRCMessageTransfer`.
pub fn parse_initial_ul_rrc(pdu: &F1AP_PDU) -> Option<(u32, u16, Vec<u8>)> {
    let F1AP_PDU::InitiatingMessage(InitiatingMessage {
        value: InitiatingMessageValue::Id_InitialULRRCMessageTransfer(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut du_id, mut c_rnti, mut rrc) = (None, None, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            InitialULRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => {
                du_id = Some(v.0)
            }
            InitialULRRCMessageTransferProtocolIEs_EntryValue::Id_C_RNTI(v) => c_rnti = Some(v.0),
            InitialULRRCMessageTransferProtocolIEs_EntryValue::Id_RRCContainer(v) => {
                rrc = Some(v.0.clone())
            }
            _ => {}
        }
    }
    Some((du_id?, c_rnti?, rrc?))
}

/// `DLRRCMessageTransfer` (CU → DU): carry an RRC PDU down to a UE on `srb_id`.
pub fn dl_rrc_message_transfer(
    gnb_cu_ue_id: u32,
    gnb_du_ue_id: u32,
    srb_id: u8,
    rrc: Vec<u8>,
) -> Vec<u8> {
    let ies = vec![
        DLRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: DLRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        DLRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: DLRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
        DLRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_SRB_ID),
            criticality: Criticality(REJECT),
            value: DLRRCMessageTransferProtocolIEs_EntryValue::Id_SRBID(SRBID(srb_id)),
        },
        DLRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_RRC_CONTAINER),
            criticality: Criticality(REJECT),
            value: DLRRCMessageTransferProtocolIEs_EntryValue::Id_RRCContainer(RRCContainer(rrc)),
        },
    ];
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_DL_RRC),
        criticality: Criticality(IGNORE),
        value: InitiatingMessageValue::Id_DLRRCMessageTransfer(DLRRCMessageTransfer {
            protocol_i_es: DLRRCMessageTransferProtocolIEs(ies),
        }),
    }))
}

/// `ULRRCMessageTransfer` (DU → CU): carry an RRC PDU up from a UE on `srb_id`.
pub fn ul_rrc_message_transfer(
    gnb_cu_ue_id: u32,
    gnb_du_ue_id: u32,
    srb_id: u8,
    rrc: Vec<u8>,
) -> Vec<u8> {
    let ies = vec![
        ULRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: ULRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        ULRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: ULRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
        ULRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_SRB_ID),
            criticality: Criticality(REJECT),
            value: ULRRCMessageTransferProtocolIEs_EntryValue::Id_SRBID(SRBID(srb_id)),
        },
        ULRRCMessageTransferProtocolIEs_Entry {
            id: ie_id(IE_RRC_CONTAINER),
            criticality: Criticality(REJECT),
            value: ULRRCMessageTransferProtocolIEs_EntryValue::Id_RRCContainer(RRCContainer(rrc)),
        },
    ];
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_UL_RRC),
        criticality: Criticality(IGNORE),
        value: InitiatingMessageValue::Id_ULRRCMessageTransfer(ULRRCMessageTransfer {
            protocol_i_es: ULRRCMessageTransferProtocolIEs(ies),
        }),
    }))
}

/// A parsed RRC-transfer message: the F1AP UE IDs, the SRB id, and the RRC container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcTransfer {
    pub gnb_cu_ue_id: u32,
    pub gnb_du_ue_id: u32,
    pub srb_id: u8,
    pub rrc: Vec<u8>,
}

/// Parse a `DLRRCMessageTransfer` into its IDs, SRB id, and RRC container.
pub fn parse_dl_rrc(pdu: &F1AP_PDU) -> Option<RrcTransfer> {
    let F1AP_PDU::InitiatingMessage(InitiatingMessage {
        value: InitiatingMessageValue::Id_DLRRCMessageTransfer(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut du, mut srb, mut rrc) = (None, None, None, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            DLRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => cu = Some(v.0),
            DLRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => du = Some(v.0),
            DLRRCMessageTransferProtocolIEs_EntryValue::Id_SRBID(v) => srb = Some(v.0),
            DLRRCMessageTransferProtocolIEs_EntryValue::Id_RRCContainer(v) => {
                rrc = Some(v.0.clone())
            }
            _ => {}
        }
    }
    Some(RrcTransfer {
        gnb_cu_ue_id: cu?,
        gnb_du_ue_id: du?,
        srb_id: srb?,
        rrc: rrc?,
    })
}

/// Parse a `ULRRCMessageTransfer` into its IDs, SRB id, and RRC container.
pub fn parse_ul_rrc(pdu: &F1AP_PDU) -> Option<RrcTransfer> {
    let F1AP_PDU::InitiatingMessage(InitiatingMessage {
        value: InitiatingMessageValue::Id_ULRRCMessageTransfer(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut du, mut srb, mut rrc) = (None, None, None, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            ULRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => cu = Some(v.0),
            ULRRCMessageTransferProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => du = Some(v.0),
            ULRRCMessageTransferProtocolIEs_EntryValue::Id_SRBID(v) => srb = Some(v.0),
            ULRRCMessageTransferProtocolIEs_EntryValue::Id_RRCContainer(v) => {
                rrc = Some(v.0.clone())
            }
            _ => {}
        }
    }
    Some(RrcTransfer {
        gnb_cu_ue_id: cu?,
        gnb_du_ue_id: du?,
        srb_id: srb?,
        rrc: rrc?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plmn_bcd_encoding() {
        // MCC 999 / MNC 70 (the test PLMN): [0x99, 0xF9, 0x07].
        assert_eq!(plmn("999", "70").0, vec![0x99, 0xF9, 0x07]);
        // A 3-digit MNC fills the third nibble.
        assert_eq!(plmn("310", "260").0, vec![0x13, 0x00, 0x62]);
    }

    #[test]
    fn f1_setup_roundtrips() {
        let req = f1_setup_request(1, 0xABCD);
        let back = decode(&req).expect("decode F1SetupRequest");
        assert_eq!(parse_f1_setup(&back), Some((1, false)));

        let resp = f1_setup_response(1);
        let back = decode(&resp).expect("decode F1SetupResponse");
        assert_eq!(parse_f1_setup(&back), Some((1, true)));
    }

    #[test]
    fn initial_ul_rrc_roundtrips_and_carries_rrc() {
        let rrc = vec![0x10, 0x20, 0x30]; // an opaque RRCSetupRequest
        let pdu = initial_ul_rrc_message_transfer(7, "999", "70", 0x12, 0x4601, rrc.clone());
        let back = decode(&pdu).expect("decode InitialULRRCMessageTransfer");
        assert_eq!(parse_initial_ul_rrc(&back), Some((7, 0x4601, rrc)));
    }

    #[test]
    fn dl_and_ul_rrc_transfer_roundtrip() {
        let rrc = vec![0x2e, 0x00, 0x56]; // opaque RRC (a DL DCCH message)
        let dl = dl_rrc_message_transfer(3, 7, 1, rrc.clone());
        let back = decode(&dl).expect("decode DLRRCMessageTransfer");
        assert_eq!(
            parse_dl_rrc(&back),
            Some(RrcTransfer {
                gnb_cu_ue_id: 3,
                gnb_du_ue_id: 7,
                srb_id: 1,
                rrc: rrc.clone()
            })
        );
        // A DL transfer is not misread as a UL transfer.
        assert_eq!(parse_ul_rrc(&back), None);

        let ul = ul_rrc_message_transfer(3, 7, 1, rrc.clone());
        let back = decode(&ul).expect("decode ULRRCMessageTransfer");
        assert_eq!(
            parse_ul_rrc(&back),
            Some(RrcTransfer {
                gnb_cu_ue_id: 3,
                gnb_du_ue_id: 7,
                srb_id: 1,
                rrc
            })
        );
    }

    #[test]
    fn malformed_input_is_none() {
        assert!(decode(&[]).is_none());
        assert!(parse_dl_rrc(&decode(&f1_setup_request(1, 1)).unwrap()).is_none());
    }
}
