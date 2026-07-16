//! Integration test (design/128 Phase 2): the user-plane security chain end to end —
//! `aka` derives K_UP from K_gNB, `pdcp` ciphers the DRB PDU, and `sdap` carries the QFI.
//! This is the unit-level proof that the DRB datapath the gNB will wire up composes.

use pdcp::{PdcpDrb, Role};

/// A downlink IP packet on QoS flow 9: gNB adds the SDAP header, PDCP-ciphers it on the
/// DRB, and the UE recovers the exact packet + QFI. Then the uplink reply, the other way.
#[test]
fn ip_packet_travels_over_sdap_and_a_ciphered_drb() {
    let kgnb = [0x5a; 32];
    let keys = aka::up_keys(&kgnb, 2, 2); // NEA2 / NIA2
    let qfi = 9;

    // DRB1 at both ends, ciphered with K_UPenc (the common user-plane config).
    let mut gnb = PdcpDrb::new(Role::Gnb, 1);
    gnb.activate_ciphering(keys.kup_enc, 2);
    let mut ue = PdcpDrb::new(Role::Ue, 1);
    ue.activate_ciphering(keys.kup_enc, 2);

    // Downlink: SDAP(header, qfi) → PDCP DRB cipher → UE deciphers → SDAP strip.
    let dl_ip = b"\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x01 downlink-icmp".to_vec();
    let sdap_pdu = sdap::encap_dl(qfi, false, false, &dl_ip);
    let drb_pdu = gnb.protect(&sdap_pdu);
    assert_ne!(
        &drb_pdu[3..3 + sdap_pdu.len()],
        &sdap_pdu[..],
        "the DRB PDU is ciphered"
    );
    let recovered_sdap = ue.unprotect(&drb_pdu).expect("UE deciphers the DRB PDU");
    let (got_qfi, ip) = sdap::decap(&recovered_sdap).expect("strip the SDAP header");
    assert_eq!(got_qfi, qfi, "the QFI survives the round trip");
    assert_eq!(ip, &dl_ip[..], "the IP packet is recovered exactly");

    // Uplink reply: UE adds the UL SDAP header, PDCP-ciphers, gNB recovers QFI + packet.
    let ul_ip = b"\x45\x00\x00\x1c uplink-reply".to_vec();
    let up_pdu = ue.protect(&sdap::encap_ul(qfi, &ul_ip));
    let recovered = gnb
        .unprotect(&up_pdu)
        .expect("gNB deciphers the uplink DRB PDU");
    assert_eq!(sdap::decap(&recovered), Some((qfi, &ul_ip[..])));
}
