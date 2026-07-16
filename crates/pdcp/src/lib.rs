//! PDCP — Packet Data Convergence Protocol (TS 38.323), SRB data path (design/128
//! Phase 1c). A [`PdcpSrb`] entity wraps an RRC message (the SDU) into a PDCP Data PDU
//! and back: it adds the 12-bit sequence number, and — once AS security is activated —
//! the 32-bit MAC-I (integrity, mandatory for SRBs) and ciphering. The AS keys come from
//! [`aka::rrc_keys`](../aka); the NEA/NIA algorithms are reused from `oxirush-security`.
//!
//! # PDU format (TS 38.323 §6.2.2.1, 12-bit SN, SRB)
//! ```text
//!  octet 0:  0 0 0 0 | SN[11:8]     (top nibble reserved for SRBs — no D/C bit)
//!  octet 1:  SN[7:0]
//!  octet 2..: Data (the RRC message), ciphered when ciphering is active
//!  last 4:   MAC-I, present + ciphered when integrity is active
//! ```
//! Integrity is computed over `header || data`; ciphering then covers `data || MAC-I`
//! (the header stays in clear) — matching OCUDU / TS 38.323 §5.8–5.9.
//!
//! # Security inputs (TS 33.501 §D.3)
//! `COUNT` = `HFN(20) || SN(12)`, per direction; `BEARER` = SRB id − 1; `DIRECTION` =
//! 0 uplink / 1 downlink. Delivery is assumed in order (SRBs run over RLC-AM); full
//! window-based reordering is a Phase-2 concern.

use oxirush_security::{nas_cipher, nas_mac};

/// DIRECTION input to the NEA/NIA algorithms (TS 33.501 §D.3.1): uplink.
const DIRECTION_UPLINK: u8 = 0;
/// DIRECTION input to the NEA/NIA algorithms: downlink.
const DIRECTION_DOWNLINK: u8 = 1;

/// 12-bit PDCP SN mask.
const SN_MASK: u32 = 0x0FFF;
/// Header size for a 12-bit-SN Data PDU.
const HDR_LEN: usize = 2;
/// MAC-I size (TS 38.323): 32 bits.
const MAC_LEN: usize = 4;

/// Which end of the Uu this entity sits at — fixes the TX/RX `DIRECTION` inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The gNB: transmits downlink, receives uplink.
    Gnb,
    /// The UE: transmits uplink, receives downlink.
    Ue,
}

impl Role {
    /// `DIRECTION` for this end's transmissions.
    fn tx_direction(self) -> u8 {
        match self {
            Role::Gnb => DIRECTION_DOWNLINK,
            Role::Ue => DIRECTION_UPLINK,
        }
    }

    /// `DIRECTION` for this end's receptions.
    fn rx_direction(self) -> u8 {
        match self {
            Role::Gnb => DIRECTION_UPLINK,
            Role::Ue => DIRECTION_DOWNLINK,
        }
    }
}

/// A configured algorithm + its 128-bit key.
#[derive(Debug, Clone, Copy)]
struct Algo {
    key: [u8; 16],
    id: u8,
}

/// Errors from [`PdcpSrb::unprotect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PdcpError {
    /// The PDU is shorter than the header (+ MAC-I when integrity is active).
    #[error("PDCP PDU too short")]
    TooShort,
    /// The recomputed MAC-I did not match — a forged, corrupted, or wrong-key PDU.
    #[error("PDCP integrity check failed")]
    IntegrityFailure,
}

/// A PDCP entity for one signalling radio bearer at one end of the Uu.
///
/// Security starts off (RRCSetup/RRCSetupComplete ride SRB1 unprotected). The RRC layer
/// calls [`activate_integrity`](Self::activate_integrity) at the Security Mode procedure
/// (integrity is mandatory once active) and [`activate_ciphering`](Self::activate_ciphering)
/// when ciphering begins — mirroring how the NAS context turns on protection.
#[derive(Debug)]
pub struct PdcpSrb {
    tx_direction: u8,
    rx_direction: u8,
    /// BEARER input to NEA/NIA — the SRB identity minus 1 (TS 33.501).
    bearer: u8,
    /// Next TX COUNT (HFN || SN).
    tx_count: u32,
    /// Next expected RX COUNT.
    rx_count: u32,
    integrity: Option<Algo>,
    ciphering: Option<Algo>,
}

impl PdcpSrb {
    /// A fresh SRB entity for `srb_id` (1 or 2) at `role`, with security off and COUNTs 0.
    pub fn new(role: Role, srb_id: u8) -> Self {
        Self {
            tx_direction: role.tx_direction(),
            rx_direction: role.rx_direction(),
            bearer: srb_id.saturating_sub(1),
            tx_count: 0,
            rx_count: 0,
            integrity: None,
            ciphering: None,
        }
    }

    /// Turn on integrity protection with K_RRCint and the NIA identifier (e.g. 2 = NIA2).
    /// From here every PDU carries a MAC-I, and reception rejects a bad one.
    pub fn activate_integrity(&mut self, krrc_int: [u8; 16], nia: u8) {
        self.integrity = Some(Algo {
            key: krrc_int,
            id: nia,
        });
    }

    /// Turn on ciphering with K_RRCenc and the NEA identifier (e.g. 2 = NEA2). NEA0 (0)
    /// leaves data in clear (a null cipher) while still exercising the path.
    pub fn activate_ciphering(&mut self, krrc_enc: [u8; 16], nea: u8) {
        self.ciphering = Some(Algo {
            key: krrc_enc,
            id: nea,
        });
    }

    /// Whether integrity protection is active.
    pub fn integrity_active(&self) -> bool {
        self.integrity.is_some()
    }

    /// Wrap an RRC message (`sdu`) into a PDCP Data PDU: prepend the SN header, append the
    /// MAC-I if integrity is active, cipher `data || MAC-I` if ciphering is active, and
    /// advance the TX COUNT.
    pub fn protect(&mut self, sdu: &[u8]) -> Vec<u8> {
        let count = self.tx_count;
        let sn = count & SN_MASK;

        let mut pdu = Vec::with_capacity(HDR_LEN + sdu.len() + MAC_LEN);
        pdu.push(((sn >> 8) & 0x0F) as u8); // top nibble reserved for SRBs
        pdu.push((sn & 0xFF) as u8);
        pdu.extend_from_slice(sdu);

        if let Some(int) = self.integrity {
            let mac = nas_mac(
                &int.key,
                count,
                self.bearer,
                self.tx_direction,
                &pdu,
                int.id,
            );
            pdu.extend_from_slice(&mac.to_be_bytes());
        }
        if let Some(cip) = self.ciphering {
            // Cipher the data + MAC-I; the 2-octet header stays in clear.
            nas_cipher(
                &cip.key,
                count,
                self.bearer,
                self.tx_direction,
                &mut pdu[HDR_LEN..],
                cip.id,
            );
        }

        self.tx_count = count.wrapping_add(1);
        pdu
    }

    /// Recover the RRC message from a PDCP Data PDU: decipher, verify the MAC-I (when
    /// integrity is active), and advance the RX COUNT. Errors on a short or forged PDU.
    pub fn unprotect(&mut self, pdu: &[u8]) -> Result<Vec<u8>, PdcpError> {
        if pdu.len() < HDR_LEN {
            return Err(PdcpError::TooShort);
        }
        let sn = (((pdu[0] & 0x0F) as u32) << 8) | pdu[1] as u32;
        let count = self.rx_count_for(sn);

        // Decipher the body (data + MAC-I); the header is never ciphered.
        let mut body = pdu[HDR_LEN..].to_vec();
        if let Some(cip) = self.ciphering {
            nas_cipher(
                &cip.key,
                count,
                self.bearer,
                self.rx_direction,
                &mut body,
                cip.id,
            );
        }

        let sdu = if let Some(int) = self.integrity {
            if body.len() < MAC_LEN {
                return Err(PdcpError::TooShort);
            }
            let split = body.len() - MAC_LEN;
            let received = u32::from_be_bytes(body[split..].try_into().unwrap());
            // The integrity input is header || data (the deciphered SDU, without MAC-I).
            let mut mac_input = Vec::with_capacity(HDR_LEN + split);
            mac_input.extend_from_slice(&pdu[..HDR_LEN]);
            mac_input.extend_from_slice(&body[..split]);
            let expected = nas_mac(
                &int.key,
                count,
                self.bearer,
                self.rx_direction,
                &mac_input,
                int.id,
            );
            if expected != received {
                return Err(PdcpError::IntegrityFailure);
            }
            body.truncate(split);
            body
        } else {
            body
        };

        self.rx_count = count.wrapping_add(1);
        Ok(sdu)
    }

    /// Reconstruct the 32-bit COUNT for a received SN from the current RX HFN (TS 38.323
    /// §5.2.2.1), handling an SN wrap near the window edge. In-order delivery keeps this
    /// equal to the running RX COUNT.
    fn rx_count_for(&self, sn: u32) -> u32 {
        const WINDOW: u32 = 1 << 11; // 2^(sn_size - 1)
        let sn = sn & SN_MASK;
        let ref_hfn = self.rx_count >> 12;
        let ref_sn = self.rx_count & SN_MASK;
        let hfn = if sn < ref_sn && ref_sn - sn > WINDOW {
            ref_hfn.wrapping_add(1)
        } else if sn > ref_sn && sn - ref_sn > WINDOW {
            ref_hfn.wrapping_sub(1)
        } else {
            ref_hfn
        };
        (hfn << 12) | sn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Demo K_RRC keys (arbitrary but fixed); the real ones come from aka::rrc_keys.
    const KINT: [u8; 16] = [0x11; 16];
    const KENC: [u8; 16] = [0x22; 16];
    const NIA2: u8 = 2;
    const NEA2: u8 = 2;

    /// A gNB/UE pair for SRB1 with the same keys and the given security.
    fn pair(integrity: bool, ciphering: bool) -> (PdcpSrb, PdcpSrb) {
        let mut gnb = PdcpSrb::new(Role::Gnb, 1);
        let mut ue = PdcpSrb::new(Role::Ue, 1);
        if integrity {
            gnb.activate_integrity(KINT, NIA2);
            ue.activate_integrity(KINT, NIA2);
        }
        if ciphering {
            gnb.activate_ciphering(KENC, NEA2);
            ue.activate_ciphering(KENC, NEA2);
        }
        (gnb, ue)
    }

    #[test]
    fn header_format_matches_srb_12bit_layout() {
        let mut gnb = PdcpSrb::new(Role::Gnb, 1); // no security
        let pdu = gnb.protect(b"hello");
        assert_eq!(&pdu[..2], &[0x00, 0x00], "SN 0, top nibble reserved");
        assert_eq!(&pdu[2..], b"hello", "no MAC-I / cipher before security");
        // The SN increments and lands in the header (0x00,0x01 ... byte layout).
        let pdu1 = gnb.protect(b"x");
        assert_eq!(&pdu1[..2], &[0x00, 0x01]);
    }

    #[test]
    fn plaintext_round_trip_before_security() {
        let (mut gnb, mut ue) = pair(false, false);
        let sdu = b"RRCSetup".to_vec();
        assert_eq!(ue.unprotect(&gnb.protect(&sdu)).unwrap(), sdu);
    }

    #[test]
    fn integrity_only_round_trip_and_tamper_rejected() {
        // The Security Mode Command is integrity-protected but not yet ciphered.
        let (mut gnb, mut ue) = pair(true, false);
        let sdu = b"SecurityModeCommand".to_vec();
        let pdu = gnb.protect(&sdu);
        assert_eq!(
            &pdu[2..2 + sdu.len()],
            &sdu[..],
            "data is in clear (no ciphering)"
        );
        assert_eq!(pdu.len(), 2 + sdu.len() + 4, "a MAC-I is appended");
        assert_eq!(ue.unprotect(&pdu).unwrap(), sdu);

        // Flip a data bit → the MAC no longer matches.
        let mut ue2 = PdcpSrb::new(Role::Ue, 1);
        ue2.activate_integrity(KINT, NIA2);
        let mut bad = gnb.protect(&sdu);
        bad[3] ^= 0x01;
        assert_eq!(ue2.unprotect(&bad), Err(PdcpError::IntegrityFailure));
    }

    #[test]
    fn ciphered_and_integrity_protected_round_trip_both_directions() {
        let (mut gnb, mut ue) = pair(true, true);
        // Downlink: gNB → UE.
        let dl = b"RRCReconfiguration".to_vec();
        let pdu = gnb.protect(&dl);
        assert_ne!(&pdu[2..2 + dl.len()], &dl[..], "data is ciphered");
        assert_eq!(ue.unprotect(&pdu).unwrap(), dl);
        // Uplink: UE → gNB (opposite DIRECTION, separate COUNT).
        let ul = b"RRCReconfigurationComplete".to_vec();
        assert_eq!(gnb.unprotect(&ue.protect(&ul)).unwrap(), ul);
    }

    #[test]
    fn counts_advance_across_multiple_messages() {
        let (mut gnb, mut ue) = pair(true, true);
        for i in 0..5u8 {
            let sdu = vec![i; 8];
            let pdu = gnb.protect(&sdu);
            assert_eq!(sn_of(&pdu), i as u32, "SN advances per message");
            assert_eq!(ue.unprotect(&pdu).unwrap(), sdu);
        }
    }

    #[test]
    fn wrong_key_fails_integrity() {
        let mut gnb = PdcpSrb::new(Role::Gnb, 1);
        gnb.activate_integrity(KINT, NIA2);
        let pdu = gnb.protect(b"secret");
        let mut ue = PdcpSrb::new(Role::Ue, 1);
        ue.activate_integrity([0x99; 16], NIA2); // different K_RRCint
        assert_eq!(ue.unprotect(&pdu), Err(PdcpError::IntegrityFailure));
    }

    #[test]
    fn different_bearers_produce_different_protection() {
        // SRB1 (bearer 0) and SRB2 (bearer 1) must not cross-verify — the BEARER input
        // differs, so a SRB2 entity rejects a SRB1-protected PDU.
        let mut gnb1 = PdcpSrb::new(Role::Gnb, 1);
        gnb1.activate_integrity(KINT, NIA2);
        let pdu = gnb1.protect(b"on srb1");
        let mut ue2 = PdcpSrb::new(Role::Ue, 2);
        ue2.activate_integrity(KINT, NIA2);
        assert_eq!(ue2.unprotect(&pdu), Err(PdcpError::IntegrityFailure));
    }

    #[test]
    fn short_pdu_is_rejected() {
        let mut ue = PdcpSrb::new(Role::Ue, 1);
        assert_eq!(ue.unprotect(&[0x00]), Err(PdcpError::TooShort));
        ue.activate_integrity(KINT, NIA2);
        // Header present but no room for a MAC-I.
        assert_eq!(ue.unprotect(&[0x00, 0x00, 0x01]), Err(PdcpError::TooShort));
    }

    fn sn_of(pdu: &[u8]) -> u32 {
        (((pdu[0] & 0x0F) as u32) << 8) | pdu[1] as u32
    }
}
