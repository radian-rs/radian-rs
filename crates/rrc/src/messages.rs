//! RRC message builders and parsers (design/128 Phase 1b), over the generated
//! TS 38.331 codec. Builders return a **wire PDU** — the CCCH/DCCH message envelope,
//! UPER-encoded, ready for the SRB — and parsers take those bytes back to the fields
//! the gNB and the co-located test UE act on.
//!
//! Scope is the Phase-1 fake-Uu message set: connection setup (RRCSetupRequest/Setup/
//! Complete), NAS transport (UL/DL-InformationTransfer, and the initial NAS in
//! RRCSetupComplete), the security-mode procedure, RRCReconfiguration(Complete), and
//! RRCRelease. NAS rides as an opaque octet string throughout. Heavy radio config
//! (`masterCellGroup`) is an OCTET STRING at this layer — the caller supplies its bytes;
//! the RRC codec never looks inside (which also keeps this crate off the CellGroupConfig
//! subtree).

use asn1_codecs::PerCodecData;
use asn1_codecs::uper::UperCodec;
use bitvec::order::Msb0;
use bitvec::slice::BitSlice;
use bitvec::vec::BitVec;

use crate::generated::*;

// ── constants (TS 38.331 ENUMERATED indices) ──────────────────────────────────────────────

/// `EstablishmentCause` values used at connection setup (TS 38.331 §6.2.2).
pub mod establishment_cause {
    pub const EMERGENCY: u8 = 0;
    pub const HIGH_PRIORITY_ACCESS: u8 = 1;
    pub const MT_ACCESS: u8 = 2;
    /// Mobile-originated signalling — what a registering UE uses.
    pub const MO_SIGNALLING: u8 = 3;
    pub const MO_DATA: u8 = 4;
}

/// `CipheringAlgorithm` / `IntegrityProtAlgorithm` indices (TS 38.331 §6.3.2) — the
/// same NEA/NIA numbering the core negotiates (nea0/nia0 = 0, …, nea3/nia3 = 3).
pub mod algo {
    pub const NEA0: u8 = 0;
    pub const NEA1: u8 = 1;
    pub const NEA2: u8 = 2;
    pub const NEA3: u8 = 3;
    pub const NIA0: u8 = 0;
    pub const NIA1: u8 = 1;
    pub const NIA2: u8 = 2;
    pub const NIA3: u8 = 3;
}

// ── codec helpers ─────────────────────────────────────────────────────────────────────────

/// UPER-encode a message to wire bytes. Builders construct well-formed values, so an
/// encode failure is a bug here, not bad input — hence `expect` (mirrors `crates/ngap`).
fn encode<T: UperCodec>(pdu: &T) -> Vec<u8> {
    let mut data = PerCodecData::new_uper();
    pdu.uper_encode(&mut data).expect("RRC UPER encode");
    data.into_bytes()
}

/// UPER-decode a message from wire bytes; `None` on a malformed PDU.
fn decode<T: UperCodec<Output = T>>(bytes: &[u8]) -> Option<T> {
    let mut data = PerCodecData::from_slice_uper(bytes);
    T::uper_decode(&mut data).ok()
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
fn bits_to_u64(bv: &BitSlice<u8, Msb0>) -> u64 {
    bv.iter().fold(0u64, |acc, b| (acc << 1) | (*b as u64))
}

/// The 2-bit RRC transaction identifier (TS 38.331: `INTEGER (0..3)`). Higher bits are
/// masked off so a caller can never push the codec past the field's upper bound.
fn txn(id: u8) -> RRC_TransactionIdentifier {
    RRC_TransactionIdentifier(id & 0x3)
}

// ── UL-CCCH (UE → gNB, SRB0) ──────────────────────────────────────────────────────────────

/// `RRCSetupRequest` on UL-CCCH: the UE opens an RRC connection, identifying itself by a
/// 39-bit `randomValue` and an establishment cause (see [`establishment_cause`]).
pub fn rrc_setup_request(random_value: u64, cause: u8) -> Vec<u8> {
    let ies = RRCSetupRequest_IEs {
        ue_identity: InitialUE_Identity::RandomValue(InitialUE_Identity_randomValue(bits(
            random_value,
            39,
        ))),
        establishment_cause: EstablishmentCause(cause),
        spare: RRCSetupRequest_IEsSpare(bits(0, 1)),
    };
    encode(&UL_CCCH_Message {
        message: UL_CCCH_MessageType::C1(UL_CCCH_MessageType_c1::RrcSetupRequest(
            RRCSetupRequest {
                rrc_setup_request: ies,
            },
        )),
    })
}

/// A decoded UL-CCCH message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UlCcch {
    /// `RRCSetupRequest` with the UE's 39-bit identity and establishment cause.
    RrcSetupRequest { ue_identity: u64, cause: u8 },
    /// A message this subset does not model.
    Other,
}

/// Parse a UL-CCCH wire PDU.
pub fn parse_ul_ccch(bytes: &[u8]) -> Option<UlCcch> {
    let UL_CCCH_Message {
        message: UL_CCCH_MessageType::C1(c1),
    } = decode::<UL_CCCH_Message>(bytes)?
    else {
        return Some(UlCcch::Other);
    };
    Some(match c1 {
        UL_CCCH_MessageType_c1::RrcSetupRequest(req) => {
            let id = match &req.rrc_setup_request.ue_identity {
                InitialUE_Identity::RandomValue(v) => bits_to_u64(&v.0),
                InitialUE_Identity::Ng_5G_S_TMSI_Part1(v) => bits_to_u64(&v.0),
            };
            UlCcch::RrcSetupRequest {
                ue_identity: id,
                cause: req.rrc_setup_request.establishment_cause.0,
            }
        }
        _ => UlCcch::Other,
    })
}

// ── DL-CCCH (gNB → UE, SRB0) ──────────────────────────────────────────────────────────────

/// `RRCSetup` on DL-CCCH: the gNB accepts the connection, configuring SRB1 and handing
/// the UE its `masterCellGroup` (an opaque `CellGroupConfig` octet string the caller
/// builds — placeholder bytes are fine over the fake Uu, where there is no real radio).
pub fn rrc_setup(transaction_id: u8, master_cell_group: &[u8]) -> Vec<u8> {
    let radio_bearer_config = RadioBearerConfig {
        srb_to_add_mod_list: Some(SRB_ToAddModList(vec![SRB_ToAddMod {
            srb_identity: SRB_Identity(1),
            reestablish_pdcp: None,
            discard_on_pdcp: None,
            pdcp_config: None,
        }])),
        srb3_to_release: None,
        drb_to_add_mod_list: None,
        drb_to_release_list: None,
        security_config: None,
    };
    let ies = RRCSetup_IEs {
        radio_bearer_config,
        master_cell_group: RRCSetup_IEsMasterCellGroup(master_cell_group.to_vec()),
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    encode(&DL_CCCH_Message {
        message: DL_CCCH_MessageType::C1(DL_CCCH_MessageType_c1::RrcSetup(RRCSetup {
            rrc_transaction_identifier: txn(transaction_id),
            critical_extensions: RRCSetupCriticalExtensions::RrcSetup(ies),
        })),
    })
}

/// A decoded DL-CCCH message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlCcch {
    /// `RRCSetup` with its transaction id and the `masterCellGroup` octets.
    RrcSetup {
        transaction_id: u8,
        master_cell_group: Vec<u8>,
    },
    Other,
}

/// Parse a DL-CCCH wire PDU.
pub fn parse_dl_ccch(bytes: &[u8]) -> Option<DlCcch> {
    let DL_CCCH_Message {
        message: DL_CCCH_MessageType::C1(c1),
    } = decode::<DL_CCCH_Message>(bytes)?
    else {
        return Some(DlCcch::Other);
    };
    Some(match c1 {
        DL_CCCH_MessageType_c1::RrcSetup(s) => {
            let RRCSetupCriticalExtensions::RrcSetup(ies) = s.critical_extensions else {
                return Some(DlCcch::Other);
            };
            DlCcch::RrcSetup {
                transaction_id: s.rrc_transaction_identifier.0,
                master_cell_group: ies.master_cell_group.0,
            }
        }
        _ => DlCcch::Other,
    })
}

// ── UL-DCCH (UE → gNB, SRB1) ──────────────────────────────────────────────────────────────

/// `RRCSetupComplete` on UL-DCCH: completes connection setup and carries the UE's initial
/// NAS message (the Registration/Service Request) to the gNB for relay to the AMF.
pub fn rrc_setup_complete(transaction_id: u8, selected_plmn: u8, nas: Vec<u8>) -> Vec<u8> {
    let ies = RRCSetupComplete_IEs {
        selected_plmn_identity: RRCSetupComplete_IEsSelectedPLMN_Identity(selected_plmn),
        registered_amf: None,
        guami_type: None,
        s_nssai_list: None,
        dedicated_nas_message: DedicatedNAS_Message(nas),
        ng_5g_s_tmsi_value: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    ul_dcch(UL_DCCH_MessageType_c1::RrcSetupComplete(RRCSetupComplete {
        rrc_transaction_identifier: txn(transaction_id),
        critical_extensions: RRCSetupCompleteCriticalExtensions::RrcSetupComplete(ies),
    }))
}

/// `ULInformationTransfer` on UL-DCCH: an uplink NAS message on the established connection.
pub fn ul_information_transfer(nas: Vec<u8>) -> Vec<u8> {
    let ies = ULInformationTransfer_IEs {
        dedicated_nas_message: Some(DedicatedNAS_Message(nas)),
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    ul_dcch(UL_DCCH_MessageType_c1::UlInformationTransfer(
        ULInformationTransfer {
            critical_extensions: ULInformationTransferCriticalExtensions::UlInformationTransfer(
                ies,
            ),
        },
    ))
}

/// `SecurityModeComplete` on UL-DCCH: the UE confirms the security-mode procedure.
pub fn security_mode_complete(transaction_id: u8) -> Vec<u8> {
    ul_dcch(UL_DCCH_MessageType_c1::SecurityModeComplete(
        SecurityModeComplete {
            rrc_transaction_identifier: txn(transaction_id),
            critical_extensions: SecurityModeCompleteCriticalExtensions::SecurityModeComplete(
                SecurityModeComplete_IEs {
                    late_non_critical_extension: None,
                    non_critical_extension: None,
                },
            ),
        },
    ))
}

/// `RRCReconfigurationComplete` on UL-DCCH: the UE confirms a reconfiguration.
pub fn rrc_reconfiguration_complete(transaction_id: u8) -> Vec<u8> {
    ul_dcch(UL_DCCH_MessageType_c1::RrcReconfigurationComplete(
        RRCReconfigurationComplete {
            rrc_transaction_identifier: txn(transaction_id),
            critical_extensions:
                RRCReconfigurationCompleteCriticalExtensions::RrcReconfigurationComplete(
                    RRCReconfigurationComplete_IEs {
                        late_non_critical_extension: None,
                        non_critical_extension: None,
                    },
                ),
        },
    ))
}

fn ul_dcch(c1: UL_DCCH_MessageType_c1) -> Vec<u8> {
    encode(&UL_DCCH_Message {
        message: UL_DCCH_MessageType::C1(c1),
    })
}

/// A decoded UL-DCCH message (the subset the gNB acts on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UlDcch {
    /// `RRCSetupComplete` carrying the UE's initial NAS message.
    RrcSetupComplete {
        transaction_id: u8,
        nas: Vec<u8>,
    },
    /// `ULInformationTransfer` carrying an uplink NAS message (absent → empty).
    UlInformationTransfer {
        nas: Vec<u8>,
    },
    SecurityModeComplete {
        transaction_id: u8,
    },
    RrcReconfigurationComplete {
        transaction_id: u8,
    },
    Other,
}

/// Parse a UL-DCCH wire PDU.
pub fn parse_ul_dcch(bytes: &[u8]) -> Option<UlDcch> {
    let UL_DCCH_Message {
        message: UL_DCCH_MessageType::C1(c1),
    } = decode::<UL_DCCH_Message>(bytes)?
    else {
        return Some(UlDcch::Other);
    };
    Some(match c1 {
        UL_DCCH_MessageType_c1::RrcSetupComplete(m) => {
            let RRCSetupCompleteCriticalExtensions::RrcSetupComplete(ies) = m.critical_extensions
            else {
                return Some(UlDcch::Other);
            };
            UlDcch::RrcSetupComplete {
                transaction_id: m.rrc_transaction_identifier.0,
                nas: ies.dedicated_nas_message.0,
            }
        }
        UL_DCCH_MessageType_c1::UlInformationTransfer(m) => {
            let ULInformationTransferCriticalExtensions::UlInformationTransfer(ies) =
                m.critical_extensions
            else {
                return Some(UlDcch::Other);
            };
            UlDcch::UlInformationTransfer {
                nas: ies.dedicated_nas_message.map(|n| n.0).unwrap_or_default(),
            }
        }
        UL_DCCH_MessageType_c1::SecurityModeComplete(m) => UlDcch::SecurityModeComplete {
            transaction_id: m.rrc_transaction_identifier.0,
        },
        UL_DCCH_MessageType_c1::RrcReconfigurationComplete(m) => {
            UlDcch::RrcReconfigurationComplete {
                transaction_id: m.rrc_transaction_identifier.0,
            }
        }
        _ => UlDcch::Other,
    })
}

// ── DL-DCCH (gNB → UE, SRB1) ──────────────────────────────────────────────────────────────

/// `DLInformationTransfer` on DL-DCCH: a downlink NAS message on the established connection.
pub fn dl_information_transfer(transaction_id: u8, nas: Vec<u8>) -> Vec<u8> {
    let ies = DLInformationTransfer_IEs {
        dedicated_nas_message: Some(DedicatedNAS_Message(nas)),
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    dl_dcch(DL_DCCH_MessageType_c1::DlInformationTransfer(
        DLInformationTransfer {
            rrc_transaction_identifier: txn(transaction_id),
            critical_extensions: DLInformationTransferCriticalExtensions::DlInformationTransfer(
                ies,
            ),
        },
    ))
}

/// `SecurityModeCommand` on DL-DCCH: the gNB commands AS security, selecting the
/// ciphering + integrity algorithms (see [`algo`]).
pub fn security_mode_command(transaction_id: u8, ciphering: u8, integrity: u8) -> Vec<u8> {
    let ies = SecurityModeCommand_IEs {
        security_config_smc: SecurityConfigSMC {
            security_algorithm_config: SecurityAlgorithmConfig {
                ciphering_algorithm: CipheringAlgorithm(ciphering),
                integrity_prot_algorithm: Some(IntegrityProtAlgorithm(integrity)),
            },
        },
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    dl_dcch(DL_DCCH_MessageType_c1::SecurityModeCommand(
        SecurityModeCommand {
            rrc_transaction_identifier: txn(transaction_id),
            critical_extensions: SecurityModeCommandCriticalExtensions::SecurityModeCommand(ies),
        },
    ))
}

/// A minimal `RRCReconfiguration` on DL-DCCH (no inline radio/measurement config) —
/// enough to drive the procedure over the fake Uu; radio bearers arrive in a later slice.
pub fn rrc_reconfiguration(transaction_id: u8) -> Vec<u8> {
    let ies = RRCReconfiguration_IEs {
        radio_bearer_config: None,
        secondary_cell_group: None,
        meas_config: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    dl_dcch(DL_DCCH_MessageType_c1::RrcReconfiguration(
        RRCReconfiguration {
            rrc_transaction_identifier: txn(transaction_id),
            critical_extensions: RRCReconfigurationCriticalExtensions::RrcReconfiguration(ies),
        },
    ))
}

/// `RRCRelease` on DL-DCCH: the gNB releases the RRC connection (AN release).
pub fn rrc_release(transaction_id: u8) -> Vec<u8> {
    let ies = RRCRelease_IEs {
        redirected_carrier_info: None,
        cell_reselection_priorities: None,
        suspend_config: None,
        deprioritisation_req: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    dl_dcch(DL_DCCH_MessageType_c1::RrcRelease(RRCRelease {
        rrc_transaction_identifier: txn(transaction_id),
        critical_extensions: RRCReleaseCriticalExtensions::RrcRelease(ies),
    }))
}

fn dl_dcch(c1: DL_DCCH_MessageType_c1) -> Vec<u8> {
    encode(&DL_DCCH_Message {
        message: DL_DCCH_MessageType::C1(c1),
    })
}

/// A decoded DL-DCCH message (the subset the UE acts on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlDcch {
    /// `DLInformationTransfer` carrying a downlink NAS message (absent → empty).
    DlInformationTransfer {
        transaction_id: u8,
        nas: Vec<u8>,
    },
    /// `SecurityModeCommand` with the selected ciphering/integrity algorithms.
    SecurityModeCommand {
        transaction_id: u8,
        ciphering: u8,
        integrity: u8,
    },
    RrcReconfiguration {
        transaction_id: u8,
    },
    RrcRelease {
        transaction_id: u8,
    },
    Other,
}

/// Parse a DL-DCCH wire PDU.
pub fn parse_dl_dcch(bytes: &[u8]) -> Option<DlDcch> {
    let DL_DCCH_Message {
        message: DL_DCCH_MessageType::C1(c1),
    } = decode::<DL_DCCH_Message>(bytes)?
    else {
        return Some(DlDcch::Other);
    };
    Some(match c1 {
        DL_DCCH_MessageType_c1::DlInformationTransfer(m) => {
            let DLInformationTransferCriticalExtensions::DlInformationTransfer(ies) =
                m.critical_extensions
            else {
                return Some(DlDcch::Other);
            };
            DlDcch::DlInformationTransfer {
                transaction_id: m.rrc_transaction_identifier.0,
                nas: ies.dedicated_nas_message.map(|n| n.0).unwrap_or_default(),
            }
        }
        DL_DCCH_MessageType_c1::SecurityModeCommand(m) => {
            let SecurityModeCommandCriticalExtensions::SecurityModeCommand(ies) =
                m.critical_extensions
            else {
                return Some(DlDcch::Other);
            };
            let alg = ies.security_config_smc.security_algorithm_config;
            DlDcch::SecurityModeCommand {
                transaction_id: m.rrc_transaction_identifier.0,
                ciphering: alg.ciphering_algorithm.0,
                integrity: alg
                    .integrity_prot_algorithm
                    .map(|a| a.0)
                    .unwrap_or(algo::NIA0),
            }
        }
        DL_DCCH_MessageType_c1::RrcReconfiguration(m) => DlDcch::RrcReconfiguration {
            transaction_id: m.rrc_transaction_identifier.0,
        },
        DL_DCCH_MessageType_c1::RrcRelease(m) => DlDcch::RrcRelease {
            transaction_id: m.rrc_transaction_identifier.0,
        },
        _ => DlDcch::Other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build → encode → parse self-consistency (design/129's per-message gate) ────────────

    #[test]
    fn rrc_setup_request_roundtrips() {
        let id = 0x1_2345_6789 & ((1 << 39) - 1);
        let pdu = rrc_setup_request(id, establishment_cause::MO_SIGNALLING);
        assert_eq!(
            parse_ul_ccch(&pdu),
            Some(UlCcch::RrcSetupRequest {
                ue_identity: id,
                cause: establishment_cause::MO_SIGNALLING
            })
        );
    }

    #[test]
    fn rrc_setup_roundtrips_with_opaque_master_cell_group() {
        let mcg = [0xDE, 0xAD, 0xBE, 0xEF];
        let pdu = rrc_setup(0, &mcg);
        assert_eq!(
            parse_dl_ccch(&pdu),
            Some(DlCcch::RrcSetup {
                transaction_id: 0,
                master_cell_group: mcg.to_vec()
            })
        );
    }

    #[test]
    fn rrc_setup_complete_carries_nas() {
        let nas = vec![0x7e, 0x00, 0x41, 0x01]; // a Registration Request, opaque here
        let pdu = rrc_setup_complete(1, 1, nas.clone());
        assert_eq!(
            parse_ul_dcch(&pdu),
            Some(UlDcch::RrcSetupComplete {
                transaction_id: 1,
                nas
            })
        );
    }

    #[test]
    fn information_transfer_both_directions_carry_nas() {
        let nas = vec![0x7e, 0x02, 0xaa, 0xbb];
        assert_eq!(
            parse_ul_dcch(&ul_information_transfer(nas.clone())),
            Some(UlDcch::UlInformationTransfer { nas: nas.clone() })
        );
        assert_eq!(
            parse_dl_dcch(&dl_information_transfer(2, nas.clone())),
            Some(DlDcch::DlInformationTransfer {
                transaction_id: 2,
                nas
            })
        );
    }

    #[test]
    fn security_mode_procedure_roundtrips() {
        let cmd = security_mode_command(0, algo::NEA2, algo::NIA2);
        assert_eq!(
            parse_dl_dcch(&cmd),
            Some(DlDcch::SecurityModeCommand {
                transaction_id: 0,
                ciphering: algo::NEA2,
                integrity: algo::NIA2
            })
        );
        assert_eq!(
            parse_ul_dcch(&security_mode_complete(0)),
            Some(UlDcch::SecurityModeComplete { transaction_id: 0 })
        );
    }

    #[test]
    fn reconfiguration_and_release_roundtrip() {
        assert_eq!(
            parse_dl_dcch(&rrc_reconfiguration(3)),
            Some(DlDcch::RrcReconfiguration { transaction_id: 3 })
        );
        assert_eq!(
            parse_ul_dcch(&rrc_reconfiguration_complete(3)),
            Some(UlDcch::RrcReconfigurationComplete { transaction_id: 3 })
        );
        // The transaction id is a 2-bit field (0..3); a caller passing more is masked,
        // never panicking the codec.
        assert_eq!(
            parse_dl_dcch(&rrc_release(1)),
            Some(DlDcch::RrcRelease { transaction_id: 1 })
        );
        assert_eq!(
            parse_dl_dcch(&rrc_release(0xFF)),
            Some(DlDcch::RrcRelease { transaction_id: 3 })
        );
    }

    #[test]
    fn malformed_input_never_panics_or_misreads() {
        // Empty / truncated input decodes to None rather than a misread. (UPER is not
        // self-describing, so cross-*direction* decode can succeed structurally — the SRB
        // tells the receiver the direction; the bytes do not. So we only assert on
        // genuinely undecodable input here.)
        assert_eq!(parse_ul_ccch(&[]), None);
        assert_eq!(parse_dl_ccch(&[]), None);
        assert_eq!(parse_ul_dcch(&[]), None);
        assert_eq!(parse_dl_dcch(&[]), None);
        // A non-empty garbage byte may decode to a valid-but-unmodeled envelope
        // (`Other`) or fail — either is fine; the point is it must not panic.
        let _ = parse_ul_dcch(&[0xff]);
        let _ = parse_dl_dcch(&[0x7f]);
    }

    // ── the oracle: OCUDU's golden RRCReconfiguration, byte-identical round-trip ────────────

    /// A real 383-byte RRCReconfiguration (secondary cell group config) from OCUDU's
    /// `asn1_rrc_nr_test.cpp`. design/129 proved Hampi round-trips this byte-identically;
    /// this test keeps that guarantee in CI against any codec regeneration.
    const GOLDEN_RRC_RECONFIGURATION: &str = "08817c5c40b1c07d483a04c03e0104541eb50002e85398df46934b8004d26934000008c98d6d8ca201ff00000000011b82210000040400d1140e70000008c9c6b6c644a0001eb89563e02494220db844700c0210b01d8048f11806ea00080e0125c0c8803708420000881650020c82000020698101450a000e48180001335564841c001040c2050c1c9c409142c60d1c3c8e0000322140302001914a0182000c8c500c1800644280e100032294070a001918a0386000c88502c38006452816206400416c4804628218a008c504b160118a0a6300231416c6804628318e008c506b1e0118a0e64000323140b223100a08409086051043cc3b2a6e4d01a4921e2ee00c10e00000018ffd29498c637281600002197000000000000052f00fa0848ad5450047001800082000e21002408070101084000e21001cb00e0402208001c420039601c0c0421000388400730038200882000710800e60004000000410c04080c100e0d0000e4810000002004000806000809002200a40000238901131c8";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn golden_rrc_reconfiguration_round_trips_byte_identical() {
        let golden = hex(GOLDEN_RRC_RECONFIGURATION);
        let msg =
            decode::<RRCReconfiguration>(&golden).expect("decode the golden RRCReconfiguration");
        // OCUDU asserts transaction id 0 on this vector.
        assert_eq!(
            msg.rrc_transaction_identifier.0, 0,
            "transaction id matches the oracle"
        );
        // The whole message re-encodes to exactly the oracle's bytes — the codec gate.
        assert_eq!(
            encode(&msg),
            golden,
            "RRCReconfiguration re-encodes byte-identical to OCUDU"
        );
    }
}
