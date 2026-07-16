//! Integration test (design/128 Phase 1c): the AS security chain end to end across the
//! three crates it spans — `aka` derives the RRC keys from K_gNB, `pdcp` protects an SRB
//! PDU with them, and `rrc` provides the actual message. This is the unit-level proof
//! that the pieces the gNB will wire together in Phase 1 actually compose.

use pdcp::{PdcpSrb, Role};
use rrc::algo;

/// A K_gNB (as the AMF hands the gNB in the Initial Context Setup) → shared AS keys →
/// an RRC SecurityModeCommand travels over SRB1, integrity-protected, and parses back.
#[test]
fn rrc_security_mode_command_travels_over_pdcp_srb1() {
    let kgnb = [0x5a; 32];
    let keys = aka::rrc_keys(&kgnb, algo::NEA2, algo::NIA2);

    // Both ends of SRB1 turn on integrity (as at the Security Mode procedure — the SMC
    // is integrity-protected but not yet ciphered).
    let mut gnb = PdcpSrb::new(Role::Gnb, 1);
    gnb.activate_integrity(keys.krrc_int, algo::NIA2);
    let mut ue = PdcpSrb::new(Role::Ue, 1);
    ue.activate_integrity(keys.krrc_int, algo::NIA2);

    let rrc_pdu = rrc::security_mode_command(0, algo::NEA2, algo::NIA2);
    let pdcp_pdu = gnb.protect(&rrc_pdu);
    let recovered = ue.unprotect(&pdcp_pdu).expect("UE verifies the SRB1 PDU");

    assert_eq!(
        recovered, rrc_pdu,
        "the RRC message survives the PDCP round trip"
    );
    assert_eq!(
        rrc::parse_dl_dcch(&recovered),
        Some(rrc::DlDcch::SecurityModeCommand {
            transaction_id: 0,
            ciphering: algo::NEA2,
            integrity: algo::NIA2,
        }),
        "and parses back to the SecurityModeCommand the gNB built"
    );

    // The UE's uplink SecurityModeComplete, now both integrity-protected and ciphered.
    gnb.activate_ciphering(keys.krrc_enc, algo::NEA2);
    ue.activate_ciphering(keys.krrc_enc, algo::NEA2);
    let complete = rrc::security_mode_complete(0);
    let recovered = gnb
        .unprotect(&ue.protect(&complete))
        .expect("gNB verifies + deciphers");
    assert_eq!(
        rrc::parse_ul_dcch(&recovered),
        Some(rrc::UlDcch::SecurityModeComplete { transaction_id: 0 })
    );
}
