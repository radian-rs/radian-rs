//! F1AP message builders and parsers (design/128 Phase 3), over the generated TS 38.473
//! codec. Covers the CU/DU message subset a UE attach exercises:
//! - **F1 Setup** (the DU↔CU association),
//! - the three **RRC-transfer** messages that carry RRC across the F1 split (the heart of
//!   a CU/DU deployment — the DU relays a UE's RRC up to the CU, where RRC/PDCP live, and
//!   the CU sends RRC down),
//! - **UE Context** Setup / Modification / Release (the CU manages a UE's context at the
//!   DU — SpCell, SRB1, the cell-group config, RRC reconfiguration),
//! - **Paging** (the CU pages a CM-IDLE UE by 5G-S-TMSI in a cell).
//!
//! RRC rides opaque (`RRCContainer = OCTET STRING`), exactly as NAS rides opaque inside
//! NGAP. Encoding is APER; builders return the wire PDU bytes and parsers take them back
//! to the fields (the F1AP UE IDs, the SRB id, the RRC container), mirroring `crates/ngap`.

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

/// A fixed-length `BIT STRING` read back as an integer.
fn bits_to_u64(bv: &bitvec::slice::BitSlice<u8, Msb0>) -> u64 {
    bv.iter().fold(0u64, |acc, b| (acc << 1) | (*b as u64))
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

// ── UE Context management (CU drives the DU) ──────────────────────────────────────────────

const PC_UE_CONTEXT_SETUP: u8 = 5;
const PC_UE_CONTEXT_RELEASE: u8 = 6;
const PC_UE_CONTEXT_MODIFICATION: u8 = 7;
const PC_UE_CONTEXT_RELEASE_REQUEST: u8 = 10;
const PC_PAGING: u8 = 18;

const IE_CAUSE: u16 = 0;
const IE_CU_TO_DU_RRC_INFO: u16 = 9;
const IE_DU_TO_CU_RRC_INFO: u16 = 39;
const IE_SPCELL_ID: u16 = 63;
const IE_SRBS_TO_BE_SETUP_ITEM: u16 = 73;
const IE_SRBS_TO_BE_SETUP_LIST: u16 = 74;
const IE_SERV_CELL_INDEX: u16 = 107;

/// `UEContextSetupRequest` (CU → DU): the CU sets up a UE context at the DU — the serving
/// cell (SpCell = NR-CGI), SRB1, and the RRC message to deliver to the UE (e.g. RRCSetup).
/// The DU answers with the cell-group config it chose. A minimal single-SRB context, no
/// DRBs (those ride a later modification / the full CU restructure).
pub fn ue_context_setup_request(
    gnb_cu_ue_id: u32,
    mcc: &str,
    mnc: &str,
    nr_cell_identity: u64,
    rrc: Vec<u8>,
) -> Vec<u8> {
    let spcell = NRCGI {
        plmn_identity: plmn(mcc, mnc),
        nr_cell_identity: NRCellIdentity(bits(nr_cell_identity, 36)),
        ie_extensions: None,
    };
    let srb1 = SRBs_ToBeSetup_List(vec![SRBs_ToBeSetup_List_Entry {
        id: ie_id(IE_SRBS_TO_BE_SETUP_ITEM),
        criticality: Criticality(REJECT),
        value: SRBs_ToBeSetup_List_EntryValue::Id_SRBs_ToBeSetup_Item(SRBs_ToBeSetup_Item {
            srbid: SRBID(1),
            duplication_indication: None,
            ie_extensions: None,
        }),
    }]);
    let cu_to_du = CUtoDURRCInformation {
        cg_config_info: None,
        ue_capability_rat_container_list: None,
        meas_config: None,
        ie_extensions: None,
    };
    let ies = vec![
        UEContextSetupRequestProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextSetupRequestProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        UEContextSetupRequestProtocolIEs_Entry {
            id: ie_id(IE_SPCELL_ID),
            criticality: Criticality(REJECT),
            value: UEContextSetupRequestProtocolIEs_EntryValue::Id_SpCell_ID(spcell),
        },
        UEContextSetupRequestProtocolIEs_Entry {
            id: ie_id(IE_SERV_CELL_INDEX),
            criticality: Criticality(REJECT),
            value: UEContextSetupRequestProtocolIEs_EntryValue::Id_ServCellIndex(ServCellIndex(0)),
        },
        UEContextSetupRequestProtocolIEs_Entry {
            id: ie_id(IE_CU_TO_DU_RRC_INFO),
            criticality: Criticality(REJECT),
            value: UEContextSetupRequestProtocolIEs_EntryValue::Id_CUtoDURRCInformation(cu_to_du),
        },
        UEContextSetupRequestProtocolIEs_Entry {
            id: ie_id(IE_SRBS_TO_BE_SETUP_LIST),
            criticality: Criticality(REJECT),
            value: UEContextSetupRequestProtocolIEs_EntryValue::Id_SRBs_ToBeSetup_List(srb1),
        },
        UEContextSetupRequestProtocolIEs_Entry {
            id: ie_id(IE_RRC_CONTAINER),
            criticality: Criticality(REJECT),
            value: UEContextSetupRequestProtocolIEs_EntryValue::Id_RRCContainer(RRCContainer(rrc)),
        },
    ];
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_UE_CONTEXT_SETUP),
        criticality: Criticality(REJECT),
        value: InitiatingMessageValue::Id_UEContextSetup(UEContextSetupRequest {
            protocol_i_es: UEContextSetupRequestProtocolIEs(ies),
        }),
    }))
}

/// `UEContextSetupResponse` (DU → CU): the DU confirms the context and returns the
/// **cell-group config** it built (which the CU embeds in the RRCSetup's masterCellGroup).
pub fn ue_context_setup_response(
    gnb_cu_ue_id: u32,
    gnb_du_ue_id: u32,
    cell_group_config: Vec<u8>,
) -> Vec<u8> {
    let du_to_cu = DUtoCURRCInformation {
        cell_group_config: CellGroupConfig(cell_group_config),
        meas_gap_config: None,
        requested_p_max_fr1: None,
        ie_extensions: None,
    };
    let ies = vec![
        UEContextSetupResponseProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextSetupResponseProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        UEContextSetupResponseProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextSetupResponseProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
        UEContextSetupResponseProtocolIEs_Entry {
            id: ie_id(IE_DU_TO_CU_RRC_INFO),
            criticality: Criticality(REJECT),
            value: UEContextSetupResponseProtocolIEs_EntryValue::Id_DUtoCURRCInformation(du_to_cu),
        },
    ];
    encode(&F1AP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode(PC_UE_CONTEXT_SETUP),
        criticality: Criticality(REJECT),
        value: SuccessfulOutcomeValue::Id_UEContextSetup(UEContextSetupResponse {
            protocol_i_es: UEContextSetupResponseProtocolIEs(ies),
        }),
    }))
}

/// `UEContextReleaseCommand` (CU → DU): release a UE context, with a radio-network cause
/// and optionally an RRC message (an RRCRelease) for the DU to deliver first.
pub fn ue_context_release_command(
    gnb_cu_ue_id: u32,
    gnb_du_ue_id: u32,
    cause_radio: u8,
    rrc: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut ies = vec![
        UEContextReleaseCommandProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextReleaseCommandProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        UEContextReleaseCommandProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextReleaseCommandProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
        UEContextReleaseCommandProtocolIEs_Entry {
            id: ie_id(IE_CAUSE),
            criticality: Criticality(IGNORE),
            value: UEContextReleaseCommandProtocolIEs_EntryValue::Id_Cause(Cause::RadioNetwork(
                CauseRadioNetwork(cause_radio),
            )),
        },
    ];
    if let Some(rrc) = rrc {
        ies.push(UEContextReleaseCommandProtocolIEs_Entry {
            id: ie_id(IE_RRC_CONTAINER),
            criticality: Criticality(IGNORE),
            value: UEContextReleaseCommandProtocolIEs_EntryValue::Id_RRCContainer(RRCContainer(
                rrc,
            )),
        });
    }
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_UE_CONTEXT_RELEASE),
        criticality: Criticality(REJECT),
        value: InitiatingMessageValue::Id_UEContextRelease(UEContextReleaseCommand {
            protocol_i_es: UEContextReleaseCommandProtocolIEs(ies),
        }),
    }))
}

/// `UEContextReleaseComplete` (DU → CU): the DU confirms the release.
pub fn ue_context_release_complete(gnb_cu_ue_id: u32, gnb_du_ue_id: u32) -> Vec<u8> {
    let ies = vec![
        UEContextReleaseCompleteProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextReleaseCompleteProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        UEContextReleaseCompleteProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextReleaseCompleteProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
    ];
    encode(&F1AP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode(PC_UE_CONTEXT_RELEASE),
        criticality: Criticality(REJECT),
        value: SuccessfulOutcomeValue::Id_UEContextRelease(UEContextReleaseComplete {
            protocol_i_es: UEContextReleaseCompleteProtocolIEs(ies),
        }),
    }))
}

/// `(gNB-CU-UE-F1AP-ID, RRC container)` from a `UEContextSetupRequest` — the DU side.
pub fn parse_ue_context_setup_request(pdu: &F1AP_PDU) -> Option<(u32, Vec<u8>)> {
    let F1AP_PDU::InitiatingMessage(InitiatingMessage {
        value: InitiatingMessageValue::Id_UEContextSetup(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut rrc) = (None, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            UEContextSetupRequestProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => cu = Some(v.0),
            UEContextSetupRequestProtocolIEs_EntryValue::Id_RRCContainer(v) => {
                rrc = Some(v.0.clone())
            }
            _ => {}
        }
    }
    Some((cu?, rrc?))
}

/// `(gNB-CU-UE-F1AP-ID, gNB-DU-UE-F1AP-ID, cell-group config)` from a
/// `UEContextSetupResponse` — the CU side.
pub fn parse_ue_context_setup_response(pdu: &F1AP_PDU) -> Option<(u32, u32, Vec<u8>)> {
    let F1AP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        value: SuccessfulOutcomeValue::Id_UEContextSetup(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut du, mut cg) = (None, None, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            UEContextSetupResponseProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => cu = Some(v.0),
            UEContextSetupResponseProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => du = Some(v.0),
            UEContextSetupResponseProtocolIEs_EntryValue::Id_DUtoCURRCInformation(v) => {
                cg = Some(v.cell_group_config.0.clone())
            }
            _ => {}
        }
    }
    Some((cu?, du?, cg?))
}

/// `(gNB-CU-UE-F1AP-ID, gNB-DU-UE-F1AP-ID, radio cause, optional RRC container)` from a
/// `UEContextReleaseCommand` — the DU side.
pub fn parse_ue_context_release_command(pdu: &F1AP_PDU) -> Option<(u32, u32, u8, Option<Vec<u8>>)> {
    let F1AP_PDU::InitiatingMessage(InitiatingMessage {
        value: InitiatingMessageValue::Id_UEContextRelease(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut du, mut cause, mut rrc) = (None, None, 0, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            UEContextReleaseCommandProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => {
                cu = Some(v.0)
            }
            UEContextReleaseCommandProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => {
                du = Some(v.0)
            }
            UEContextReleaseCommandProtocolIEs_EntryValue::Id_Cause(Cause::RadioNetwork(c)) => {
                cause = c.0
            }
            UEContextReleaseCommandProtocolIEs_EntryValue::Id_RRCContainer(v) => {
                rrc = Some(v.0.clone())
            }
            _ => {}
        }
    }
    Some((cu?, du?, cause, rrc))
}

/// `(gNB-CU-UE-F1AP-ID, gNB-DU-UE-F1AP-ID)` from a `UEContextReleaseComplete`.
pub fn parse_ue_context_release_complete(pdu: &F1AP_PDU) -> Option<(u32, u32)> {
    let F1AP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        value: SuccessfulOutcomeValue::Id_UEContextRelease(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut du) = (None, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            UEContextReleaseCompleteProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => {
                cu = Some(v.0)
            }
            UEContextReleaseCompleteProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => {
                du = Some(v.0)
            }
            _ => {}
        }
    }
    Some((cu?, du?))
}

/// `UEContextReleaseRequest` (DU → CU): the DU asks the CU to release a UE context — the
/// gNB-DU-initiated release, e.g. on detected radio inactivity (TS 38.473 §8.3.2). The CU
/// answers by driving the NG release and then a `UEContextReleaseCommand`.
pub fn ue_context_release_request(gnb_cu_ue_id: u32, gnb_du_ue_id: u32, cause_radio: u8) -> Vec<u8> {
    let ies = vec![
        UEContextReleaseRequestProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextReleaseRequestProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        UEContextReleaseRequestProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextReleaseRequestProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
        UEContextReleaseRequestProtocolIEs_Entry {
            id: ie_id(IE_CAUSE),
            criticality: Criticality(IGNORE),
            value: UEContextReleaseRequestProtocolIEs_EntryValue::Id_Cause(Cause::RadioNetwork(
                CauseRadioNetwork(cause_radio),
            )),
        },
    ];
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_UE_CONTEXT_RELEASE_REQUEST),
        criticality: Criticality(IGNORE),
        value: InitiatingMessageValue::Id_UEContextReleaseRequest(UEContextReleaseRequest {
            protocol_i_es: UEContextReleaseRequestProtocolIEs(ies),
        }),
    }))
}

/// `(gNB-CU-UE-F1AP-ID, gNB-DU-UE-F1AP-ID, radio cause)` from a `UEContextReleaseRequest`.
pub fn parse_ue_context_release_request(pdu: &F1AP_PDU) -> Option<(u32, u32, u8)> {
    let F1AP_PDU::InitiatingMessage(InitiatingMessage {
        value: InitiatingMessageValue::Id_UEContextReleaseRequest(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut du, mut cause) = (None, None, 0);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            UEContextReleaseRequestProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => cu = Some(v.0),
            UEContextReleaseRequestProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => du = Some(v.0),
            UEContextReleaseRequestProtocolIEs_EntryValue::Id_Cause(Cause::RadioNetwork(c)) => {
                cause = c.0
            }
            _ => {}
        }
    }
    Some((cu?, du?, cause))
}

// ── UE Context Modification (CU reconfigures the DU-side context) ──────────────────────────

const IE_PAGING_CELL_ITEM: u16 = 112;
const IE_PAGING_CELL_LIST: u16 = 113;
const IE_UE_IDENTITY_INDEX_VALUE: u16 = 117;
const IE_PAGING_IDENTITY: u16 = 127;

/// `UEContextModificationRequest` (CU → DU): reconfigure a UE's context — here, deliver an
/// RRC message (an RRCReconfiguration). Adding/releasing DRBs is a later refinement.
pub fn ue_context_modification_request(
    gnb_cu_ue_id: u32,
    gnb_du_ue_id: u32,
    rrc: Vec<u8>,
) -> Vec<u8> {
    let ies = vec![
        UEContextModificationRequestProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextModificationRequestProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        UEContextModificationRequestProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextModificationRequestProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
        UEContextModificationRequestProtocolIEs_Entry {
            id: ie_id(IE_RRC_CONTAINER),
            criticality: Criticality(REJECT),
            value: UEContextModificationRequestProtocolIEs_EntryValue::Id_RRCContainer(
                RRCContainer(rrc),
            ),
        },
    ];
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_UE_CONTEXT_MODIFICATION),
        criticality: Criticality(REJECT),
        value: InitiatingMessageValue::Id_UEContextModification(UEContextModificationRequest {
            protocol_i_es: UEContextModificationRequestProtocolIEs(ies),
        }),
    }))
}

/// `UEContextModificationResponse` (DU → CU): the DU confirms the modification.
pub fn ue_context_modification_response(gnb_cu_ue_id: u32, gnb_du_ue_id: u32) -> Vec<u8> {
    let ies = vec![
        UEContextModificationResponseProtocolIEs_Entry {
            id: ie_id(IE_GNB_CU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextModificationResponseProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(
                GNB_CU_UE_F1AP_ID(gnb_cu_ue_id),
            ),
        },
        UEContextModificationResponseProtocolIEs_Entry {
            id: ie_id(IE_GNB_DU_UE_ID),
            criticality: Criticality(REJECT),
            value: UEContextModificationResponseProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(
                GNB_DU_UE_F1AP_ID(gnb_du_ue_id),
            ),
        },
    ];
    encode(&F1AP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode(PC_UE_CONTEXT_MODIFICATION),
        criticality: Criticality(REJECT),
        value: SuccessfulOutcomeValue::Id_UEContextModification(UEContextModificationResponse {
            protocol_i_es: UEContextModificationResponseProtocolIEs(ies),
        }),
    }))
}

/// `(gNB-CU-UE-F1AP-ID, gNB-DU-UE-F1AP-ID, RRC container)` from a
/// `UEContextModificationRequest` — the DU side.
pub fn parse_ue_context_modification_request(pdu: &F1AP_PDU) -> Option<(u32, u32, Vec<u8>)> {
    let F1AP_PDU::InitiatingMessage(InitiatingMessage {
        value: InitiatingMessageValue::Id_UEContextModification(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut du, mut rrc) = (None, None, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            UEContextModificationRequestProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => {
                cu = Some(v.0)
            }
            UEContextModificationRequestProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => {
                du = Some(v.0)
            }
            UEContextModificationRequestProtocolIEs_EntryValue::Id_RRCContainer(v) => {
                rrc = Some(v.0.clone())
            }
            _ => {}
        }
    }
    Some((cu?, du?, rrc?))
}

/// `(gNB-CU-UE-F1AP-ID, gNB-DU-UE-F1AP-ID)` from a `UEContextModificationResponse`.
pub fn parse_ue_context_modification_response(pdu: &F1AP_PDU) -> Option<(u32, u32)> {
    let F1AP_PDU::SuccessfulOutcome(SuccessfulOutcome {
        value: SuccessfulOutcomeValue::Id_UEContextModification(m),
        ..
    }) = pdu
    else {
        return None;
    };
    let (mut cu, mut du) = (None, None);
    for e in &m.protocol_i_es.0 {
        match &e.value {
            UEContextModificationResponseProtocolIEs_EntryValue::Id_gNB_CU_UE_F1AP_ID(v) => {
                cu = Some(v.0)
            }
            UEContextModificationResponseProtocolIEs_EntryValue::Id_gNB_DU_UE_F1AP_ID(v) => {
                du = Some(v.0)
            }
            _ => {}
        }
    }
    Some((cu?, du?))
}

// ── Paging (CU → DU, non-UE-associated) ───────────────────────────────────────────────────

/// `Paging` (CU → DU): page a CM-IDLE UE by its **5G-S-TMSI** in a cell (NR-CGI). Carries
/// the UE Identity Index Value (which paging occasion), the CN paging identity (5G-S-TMSI,
/// 48 bits), and the target cell.
pub fn paging(
    mcc: &str,
    mnc: &str,
    nr_cell_identity: u64,
    five_g_s_tmsi: u64,
    ue_identity_index: u16,
) -> Vec<u8> {
    let paging_cell = PagingCell_list(vec![PagingCell_list_Entry {
        id: ie_id(IE_PAGING_CELL_ITEM),
        criticality: Criticality(IGNORE),
        value: PagingCell_list_EntryValue::Id_PagingCell_Item(PagingCell_Item {
            nrcgi: NRCGI {
                plmn_identity: plmn(mcc, mnc),
                nr_cell_identity: NRCellIdentity(bits(nr_cell_identity, 36)),
                ie_extensions: None,
            },
            ie_extensions: None,
        }),
    }]);
    let ies = vec![
        PagingProtocolIEs_Entry {
            id: ie_id(IE_UE_IDENTITY_INDEX_VALUE),
            criticality: Criticality(REJECT),
            value: PagingProtocolIEs_EntryValue::Id_UEIdentityIndexValue(
                UEIdentityIndexValue::IndexLength10(UEIdentityIndexValue_indexLength10(bits(
                    ue_identity_index as u64,
                    10,
                ))),
            ),
        },
        PagingProtocolIEs_Entry {
            id: ie_id(IE_PAGING_IDENTITY),
            criticality: Criticality(REJECT),
            value: PagingProtocolIEs_EntryValue::Id_PagingIdentity(
                PagingIdentity::CNUEPagingIdentity(CNUEPagingIdentity::FiveG_S_TMSI(
                    CNUEPagingIdentity_fiveG_S_TMSI(bits(five_g_s_tmsi, 48)),
                )),
            ),
        },
        PagingProtocolIEs_Entry {
            id: ie_id(IE_PAGING_CELL_LIST),
            criticality: Criticality(REJECT),
            value: PagingProtocolIEs_EntryValue::Id_PagingCell_List(paging_cell),
        },
    ];
    encode(&F1AP_PDU::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode(PC_PAGING),
        criticality: Criticality(IGNORE),
        value: InitiatingMessageValue::Id_Paging(Paging {
            protocol_i_es: PagingProtocolIEs(ies),
        }),
    }))
}

/// The **5G-S-TMSI** (48 bits) a `Paging` targets, if it pages by CN identity — the DU
/// side / tests.
pub fn parse_paging_5g_s_tmsi(pdu: &F1AP_PDU) -> Option<u64> {
    let F1AP_PDU::InitiatingMessage(InitiatingMessage {
        value: InitiatingMessageValue::Id_Paging(m),
        ..
    }) = pdu
    else {
        return None;
    };
    m.protocol_i_es.0.iter().find_map(|e| match &e.value {
        PagingProtocolIEs_EntryValue::Id_PagingIdentity(PagingIdentity::CNUEPagingIdentity(
            CNUEPagingIdentity::FiveG_S_TMSI(t),
        )) => Some(bits_to_u64(&t.0)),
        _ => None,
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

    #[test]
    fn ue_context_setup_roundtrips() {
        let rrc = vec![0x20, 0x40, 0x60]; // an opaque RRCSetup
        let req = ue_context_setup_request(3, "999", "70", 0x12, rrc.clone());
        let back = decode(&req).expect("decode UEContextSetupRequest");
        assert_eq!(parse_ue_context_setup_request(&back), Some((3, rrc)));

        // The DU replies with the cell-group config it built.
        let cg = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let resp = ue_context_setup_response(3, 7, cg.clone());
        let back = decode(&resp).expect("decode UEContextSetupResponse");
        assert_eq!(parse_ue_context_setup_response(&back), Some((3, 7, cg)));
    }

    #[test]
    fn ue_context_release_roundtrips_with_and_without_rrc() {
        // With an RRCRelease to deliver.
        let rrc = vec![0x2e, 0x02, 0x01]; // opaque RRCRelease
        let cmd =
            ue_context_release_command(3, 7, CauseRadioNetwork::UNSPECIFIED, Some(rrc.clone()));
        let back = decode(&cmd).expect("decode UEContextReleaseCommand");
        assert_eq!(
            parse_ue_context_release_command(&back),
            Some((3, 7, 0, Some(rrc)))
        );

        // Without.
        let cmd = ue_context_release_command(3, 7, CauseRadioNetwork::UNSPECIFIED, None);
        let back = decode(&cmd).expect("decode UEContextReleaseCommand");
        assert_eq!(
            parse_ue_context_release_command(&back),
            Some((3, 7, 0, None))
        );

        let done = ue_context_release_complete(3, 7);
        let back = decode(&done).expect("decode UEContextReleaseComplete");
        assert_eq!(parse_ue_context_release_complete(&back), Some((3, 7)));
    }

    #[test]
    fn ue_context_messages_are_not_cross_parsed() {
        // A setup request is not misread as a release command, or as an RRC transfer.
        let req = decode(&ue_context_setup_request(3, "999", "70", 1, vec![1])).unwrap();
        assert!(parse_ue_context_release_command(&req).is_none());
        assert!(parse_dl_rrc(&req).is_none());
    }

    #[test]
    fn ue_context_release_request_roundtrips() {
        // DU → CU: the gNB-DU asks for a release (radio inactivity).
        let req = ue_context_release_request(4, 9, CauseRadioNetwork::NORMAL_RELEASE);
        let back = decode(&req).expect("decode UEContextReleaseRequest");
        assert_eq!(
            parse_ue_context_release_request(&back),
            Some((4, 9, CauseRadioNetwork::NORMAL_RELEASE))
        );
        // Not misread as the CU-initiated release command.
        assert!(parse_ue_context_release_command(&back).is_none());
    }

    #[test]
    fn ue_context_modification_roundtrips() {
        let rrc = vec![0x2e, 0x01, 0x0c]; // opaque RRCReconfiguration
        let req = ue_context_modification_request(3, 7, rrc.clone());
        let back = decode(&req).expect("decode UEContextModificationRequest");
        assert_eq!(
            parse_ue_context_modification_request(&back),
            Some((3, 7, rrc))
        );
        // Not misread as a setup request.
        assert!(parse_ue_context_setup_request(&back).is_none());

        let resp = ue_context_modification_response(3, 7);
        let back = decode(&resp).expect("decode UEContextModificationResponse");
        assert_eq!(parse_ue_context_modification_response(&back), Some((3, 7)));
    }

    #[test]
    fn paging_carries_the_5g_s_tmsi() {
        let tmsi = 0x0001_2345_6789 & ((1 << 48) - 1);
        let pdu = paging("999", "70", 0x12, tmsi, 0x2AB);
        let back = decode(&pdu).expect("decode Paging");
        assert_eq!(parse_paging_5g_s_tmsi(&back), Some(tmsi));
        // A paging is not misread as a UE-associated message.
        assert!(parse_dl_rrc(&back).is_none());
    }
}
