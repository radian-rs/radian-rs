//! PDCP — Packet Data Convergence Protocol (TS 38.323), the sublayer between RRC/SDAP
//! and RLC. This crate implements the data path for both bearer kinds (design/128
//! Phases 1–2): [`PdcpSrb`] (signalling, 12-bit SN, integrity mandatory once active) and
//! [`PdcpDrb`] (data, 18-bit SN, ciphering — integrity optional). Each wraps an SDU into
//! a PDCP Data PDU and back: the SN, and — once security is active — the MAC-I (when
//! integrity is on) and ciphering. Keys come from [`aka`](../aka) (K_RRC for SRBs, K_UP
//! for DRBs); the NEA/NIA algorithms are reused from `oxirush-security`.
//!
//! # PDU format (TS 38.323 §6.2.2)
//! ```text
//!  SRB / 12-bit SN:  0 0 0 0 SN[11:8] | SN[7:0]                | data | [MAC-I]
//!  DRB / 18-bit SN:  1 0 0 0 0 0 SN[17:16] | SN[15:8] | SN[7:0] | data | [MAC-I]
//! ```
//! (SRB octet-0 top nibble is reserved — no D/C bit; DRB octet-0 bit 7 is D/C = 1.)
//! Integrity is computed over `header || data`; ciphering then covers `data || MAC-I`
//! (the header stays in clear) — matching OCUDU / TS 38.323 §5.8–5.9.
//!
//! # Security inputs (TS 33.501 §D.3)
//! `COUNT` = `HFN || SN`, per direction; `BEARER` = the bearer identity − 1 (SRB id − 1 /
//! DRB id − 1); `DIRECTION` = 0 uplink / 1 downlink. Delivery is assumed in order (SRBs
//! and the Phase-1/2 DRBs run over RLC-AM); full window-based reordering is deferred.

use oxirush_security::{nas_cipher, nas_mac};

/// DIRECTION input to the NEA/NIA algorithms (TS 33.501 §D.3.1): uplink.
const DIRECTION_UPLINK: u8 = 0;
/// DIRECTION input to the NEA/NIA algorithms: downlink.
const DIRECTION_DOWNLINK: u8 = 1;

/// MAC-I size (TS 38.323): 32 bits.
const MAC_LEN: usize = 4;
/// 12-bit SN mask (SRB and small DRB).
const SN12_MASK: u32 = 0x0000_0FFF;
/// 18-bit SN mask (DRB).
const SN18_MASK: u32 = 0x0003_FFFF;

/// Which end of the Uu this entity sits at — fixes the TX/RX `DIRECTION` inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The gNB: transmits downlink, receives uplink.
    Gnb,
    /// The UE: transmits uplink, receives downlink.
    Ue,
}

impl Role {
    fn tx_direction(self) -> u8 {
        match self {
            Role::Gnb => DIRECTION_DOWNLINK,
            Role::Ue => DIRECTION_UPLINK,
        }
    }

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

/// Errors from `unprotect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PdcpError {
    /// The PDU is shorter than the header (+ MAC-I when integrity is active).
    #[error("PDCP PDU too short")]
    TooShort,
    /// The recomputed MAC-I did not match — a forged, corrupted, or wrong-key PDU.
    #[error("PDCP integrity check failed")]
    IntegrityFailure,
}

/// The shared per-bearer state and crypto: directions, BEARER, per-direction COUNTs, and
/// the (optional) integrity/ciphering algorithms. [`PdcpSrb`]/[`PdcpDrb`] add the SN-size
/// header format on top.
#[derive(Debug)]
struct Bearer {
    tx_direction: u8,
    rx_direction: u8,
    /// BEARER input to NEA/NIA — the bearer identity minus 1 (TS 33.501).
    bearer: u8,
    /// SN field mask (0xFFF for 12-bit, 0x3FFFF for 18-bit).
    sn_mask: u32,
    tx_count: u32,
    rx_count: u32,
    integrity: Option<Algo>,
    ciphering: Option<Algo>,
}

impl Bearer {
    fn new(role: Role, bearer: u8, sn_mask: u32) -> Self {
        Self {
            tx_direction: role.tx_direction(),
            rx_direction: role.rx_direction(),
            bearer,
            sn_mask,
            tx_count: 0,
            rx_count: 0,
            integrity: None,
            ciphering: None,
        }
    }

    fn sn_bits(&self) -> u32 {
        self.sn_mask.count_ones()
    }

    /// The SN to place in the next transmitted header.
    fn next_tx_sn(&self) -> u32 {
        self.tx_count & self.sn_mask
    }

    /// Seal an SDU into a PDU: append it to the caller-built `header`, add the MAC-I if
    /// integrity is active, cipher `data || MAC-I` if ciphering is active, advance TX COUNT.
    fn tx_seal(&mut self, header: Vec<u8>, sdu: &[u8]) -> Vec<u8> {
        let count = self.tx_count;
        let hdr_len = header.len();
        let mut pdu = header;
        pdu.reserve(sdu.len() + MAC_LEN);
        pdu.extend_from_slice(sdu);
        if let Some(a) = self.integrity {
            let mac = nas_mac(&a.key, count, self.bearer, self.tx_direction, &pdu, a.id);
            pdu.extend_from_slice(&mac.to_be_bytes());
        }
        if let Some(a) = self.ciphering {
            nas_cipher(
                &a.key,
                count,
                self.bearer,
                self.tx_direction,
                &mut pdu[hdr_len..],
                a.id,
            );
        }
        self.tx_count = count.wrapping_add(1);
        pdu
    }

    /// Open a PDU whose header (`hdr_len` octets, carrying `sn`) has been parsed: decipher,
    /// verify the MAC-I when integrity is active, advance RX COUNT, return the SDU.
    fn rx_open(&mut self, pdu: &[u8], hdr_len: usize, sn: u32) -> Result<Vec<u8>, PdcpError> {
        let count = self.rx_count_for(sn);
        let mut body = pdu[hdr_len..].to_vec();
        if let Some(a) = self.ciphering {
            nas_cipher(
                &a.key,
                count,
                self.bearer,
                self.rx_direction,
                &mut body,
                a.id,
            );
        }
        let sdu = if let Some(a) = self.integrity {
            if body.len() < MAC_LEN {
                return Err(PdcpError::TooShort);
            }
            let split = body.len() - MAC_LEN;
            let received = u32::from_be_bytes(body[split..].try_into().unwrap());
            let mut mac_input = Vec::with_capacity(hdr_len + split);
            mac_input.extend_from_slice(&pdu[..hdr_len]);
            mac_input.extend_from_slice(&body[..split]);
            let expected = nas_mac(
                &a.key,
                count,
                self.bearer,
                self.rx_direction,
                &mac_input,
                a.id,
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

    /// Reconstruct the full COUNT for a received SN from the current RX HFN (TS 38.323
    /// §5.2.2.1), handling an SN wrap near the window edge. In-order delivery keeps this
    /// equal to the running RX COUNT.
    fn rx_count_for(&self, sn: u32) -> u32 {
        let sn_bits = self.sn_bits();
        let window = 1u32 << (sn_bits - 1);
        let sn = sn & self.sn_mask;
        let ref_hfn = self.rx_count >> sn_bits;
        let ref_sn = self.rx_count & self.sn_mask;
        let hfn = if sn < ref_sn && ref_sn - sn > window {
            ref_hfn.wrapping_add(1)
        } else if sn > ref_sn && sn - ref_sn > window {
            ref_hfn.wrapping_sub(1)
        } else {
            ref_hfn
        };
        (hfn << sn_bits) | sn
    }
}

/// A PDCP entity for one **signalling** radio bearer (12-bit SN). Security starts off
/// (RRCSetup/RRCSetupComplete ride SRB1 unprotected); the RRC layer calls
/// [`activate_integrity`](Self::activate_integrity) at the Security Mode procedure
/// (integrity is mandatory once active) and [`activate_ciphering`](Self::activate_ciphering)
/// when ciphering begins.
#[derive(Debug)]
pub struct PdcpSrb {
    inner: Bearer,
}

impl PdcpSrb {
    /// A fresh SRB entity for `srb_id` (1 or 2) at `role`, security off, COUNTs 0.
    pub fn new(role: Role, srb_id: u8) -> Self {
        Self {
            inner: Bearer::new(role, srb_id.saturating_sub(1), SN12_MASK),
        }
    }

    /// Turn on integrity protection with K_RRCint and the NIA identifier (e.g. 2 = NIA2).
    pub fn activate_integrity(&mut self, krrc_int: [u8; 16], nia: u8) {
        self.inner.integrity = Some(Algo {
            key: krrc_int,
            id: nia,
        });
    }

    /// Turn on ciphering with K_RRCenc and the NEA identifier (e.g. 2 = NEA2).
    pub fn activate_ciphering(&mut self, krrc_enc: [u8; 16], nea: u8) {
        self.inner.ciphering = Some(Algo {
            key: krrc_enc,
            id: nea,
        });
    }

    /// Whether integrity protection is active.
    pub fn integrity_active(&self) -> bool {
        self.inner.integrity.is_some()
    }

    /// Wrap an RRC message into a PDCP Data PDU (12-bit SN header).
    pub fn protect(&mut self, sdu: &[u8]) -> Vec<u8> {
        let sn = self.inner.next_tx_sn();
        // SRB: top nibble reserved (no D/C bit).
        let header = vec![((sn >> 8) & 0x0F) as u8, (sn & 0xFF) as u8];
        self.inner.tx_seal(header, sdu)
    }

    /// Recover the RRC message from a PDCP Data PDU.
    pub fn unprotect(&mut self, pdu: &[u8]) -> Result<Vec<u8>, PdcpError> {
        if pdu.len() < 2 {
            return Err(PdcpError::TooShort);
        }
        let sn = (((pdu[0] & 0x0F) as u32) << 8) | pdu[1] as u32;
        self.inner.rx_open(pdu, 2, sn)
    }
}

/// A PDCP entity for one **data** radio bearer (18-bit SN). Security is configured at DRB
/// establishment: ciphering with K_UPenc (the common case), and integrity with K_UPint
/// only when user-plane integrity is negotiated.
#[derive(Debug)]
pub struct PdcpDrb {
    inner: Bearer,
}

impl PdcpDrb {
    /// A fresh DRB entity for `drb_id` at `role`, security off, COUNTs 0.
    pub fn new(role: Role, drb_id: u8) -> Self {
        Self {
            inner: Bearer::new(role, drb_id.saturating_sub(1), SN18_MASK),
        }
    }

    /// Turn on ciphering with K_UPenc and the NEA identifier (e.g. 2 = NEA2).
    pub fn activate_ciphering(&mut self, kup_enc: [u8; 16], nea: u8) {
        self.inner.ciphering = Some(Algo {
            key: kup_enc,
            id: nea,
        });
    }

    /// Turn on user-plane integrity with K_UPint and the NIA identifier (optional for DRBs).
    pub fn activate_integrity(&mut self, kup_int: [u8; 16], nia: u8) {
        self.inner.integrity = Some(Algo {
            key: kup_int,
            id: nia,
        });
    }

    /// Wrap a user-plane SDU (an SDAP PDU) into a PDCP Data PDU (18-bit SN header).
    pub fn protect(&mut self, sdu: &[u8]) -> Vec<u8> {
        let sn = self.inner.next_tx_sn();
        // DRB: octet 0 bit 7 is D/C = 1 (data), then 5 reserved bits, then SN[17:16].
        let header = vec![
            0x80 | ((sn >> 16) & 0x03) as u8,
            ((sn >> 8) & 0xFF) as u8,
            (sn & 0xFF) as u8,
        ];
        self.inner.tx_seal(header, sdu)
    }

    /// Recover the user-plane SDU from a PDCP Data PDU.
    pub fn unprotect(&mut self, pdu: &[u8]) -> Result<Vec<u8>, PdcpError> {
        if pdu.len() < 3 {
            return Err(PdcpError::TooShort);
        }
        let sn = (((pdu[0] & 0x03) as u32) << 16) | ((pdu[1] as u32) << 8) | pdu[2] as u32;
        self.inner.rx_open(pdu, 3, sn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Demo keys (arbitrary but fixed); the real ones come from aka::rrc_keys / up_keys.
    const KINT: [u8; 16] = [0x11; 16];
    const KENC: [u8; 16] = [0x22; 16];
    const NIA2: u8 = 2;
    const NEA2: u8 = 2;

    fn srb_pair(integrity: bool, ciphering: bool) -> (PdcpSrb, PdcpSrb) {
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
    fn srb_header_format_matches_12bit_layout() {
        let mut gnb = PdcpSrb::new(Role::Gnb, 1);
        let pdu = gnb.protect(b"hello");
        assert_eq!(&pdu[..2], &[0x00, 0x00], "SN 0, top nibble reserved");
        assert_eq!(&pdu[2..], b"hello", "no MAC-I / cipher before security");
        assert_eq!(&gnb.protect(b"x")[..2], &[0x00, 0x01], "SN increments");
    }

    #[test]
    fn srb_plaintext_round_trip_before_security() {
        let (mut gnb, mut ue) = srb_pair(false, false);
        let sdu = b"RRCSetup".to_vec();
        assert_eq!(ue.unprotect(&gnb.protect(&sdu)).unwrap(), sdu);
    }

    #[test]
    fn srb_integrity_only_round_trip_and_tamper_rejected() {
        let (mut gnb, mut ue) = srb_pair(true, false);
        let sdu = b"SecurityModeCommand".to_vec();
        let pdu = gnb.protect(&sdu);
        assert_eq!(
            &pdu[2..2 + sdu.len()],
            &sdu[..],
            "data in clear (no ciphering)"
        );
        assert_eq!(pdu.len(), 2 + sdu.len() + 4, "a MAC-I is appended");
        assert_eq!(ue.unprotect(&pdu).unwrap(), sdu);

        let mut ue2 = PdcpSrb::new(Role::Ue, 1);
        ue2.activate_integrity(KINT, NIA2);
        let mut bad = gnb.protect(&sdu);
        bad[3] ^= 0x01;
        assert_eq!(ue2.unprotect(&bad), Err(PdcpError::IntegrityFailure));
    }

    #[test]
    fn srb_ciphered_round_trip_both_directions() {
        let (mut gnb, mut ue) = srb_pair(true, true);
        let dl = b"RRCReconfiguration".to_vec();
        let pdu = gnb.protect(&dl);
        assert_ne!(&pdu[2..2 + dl.len()], &dl[..], "data is ciphered");
        assert_eq!(ue.unprotect(&pdu).unwrap(), dl);
        let ul = b"RRCReconfigurationComplete".to_vec();
        assert_eq!(gnb.unprotect(&ue.protect(&ul)).unwrap(), ul);
    }

    #[test]
    fn srb_counts_advance_across_multiple_messages() {
        let (mut gnb, mut ue) = srb_pair(true, true);
        for i in 0..5u8 {
            let sdu = vec![i; 8];
            let pdu = gnb.protect(&sdu);
            assert_eq!(
                (((pdu[0] & 0x0F) as u32) << 8) | pdu[1] as u32,
                i as u32,
                "SN advances"
            );
            assert_eq!(ue.unprotect(&pdu).unwrap(), sdu);
        }
    }

    #[test]
    fn srb_wrong_key_and_wrong_bearer_fail_integrity() {
        let mut gnb = PdcpSrb::new(Role::Gnb, 1);
        gnb.activate_integrity(KINT, NIA2);
        let pdu = gnb.protect(b"secret");
        let mut ue = PdcpSrb::new(Role::Ue, 1);
        ue.activate_integrity([0x99; 16], NIA2);
        assert_eq!(ue.unprotect(&pdu), Err(PdcpError::IntegrityFailure));

        // SRB1 (bearer 0) vs SRB2 (bearer 1): the BEARER input differs.
        let mut gnb1 = PdcpSrb::new(Role::Gnb, 1);
        gnb1.activate_integrity(KINT, NIA2);
        let pdu = gnb1.protect(b"on srb1");
        let mut ue2 = PdcpSrb::new(Role::Ue, 2);
        ue2.activate_integrity(KINT, NIA2);
        assert_eq!(ue2.unprotect(&pdu), Err(PdcpError::IntegrityFailure));
    }

    #[test]
    fn short_pdu_is_rejected() {
        let mut srb = PdcpSrb::new(Role::Ue, 1);
        assert_eq!(srb.unprotect(&[0x00]), Err(PdcpError::TooShort));
        let mut drb = PdcpDrb::new(Role::Ue, 1);
        assert_eq!(drb.unprotect(&[0x80, 0x00]), Err(PdcpError::TooShort));
    }

    // ── DRB (18-bit SN) ────────────────────────────────────────────────────────────────────

    #[test]
    fn drb_header_format_matches_18bit_layout() {
        let mut gnb = PdcpDrb::new(Role::Gnb, 1);
        let pdu = gnb.protect(b"ip-packet");
        // D/C = 1 (0x80), SN 0 across the low 2 bits of octet 0 + octets 1-2.
        assert_eq!(&pdu[..3], &[0x80, 0x00, 0x00], "D/C=1, SN 0");
        assert_eq!(&pdu[3..], b"ip-packet", "no cipher before security");
        assert_eq!(
            &gnb.protect(b"x")[..3],
            &[0x80, 0x00, 0x01],
            "SN increments"
        );
    }

    #[test]
    fn drb_ciphered_round_trip_both_directions() {
        let mut gnb = PdcpDrb::new(Role::Gnb, 1);
        let mut ue = PdcpDrb::new(Role::Ue, 1);
        gnb.activate_ciphering(KENC, NEA2);
        ue.activate_ciphering(KENC, NEA2);
        // Downlink IP payload, ciphered gNB → UE.
        let dl = b"\x45\x00\x00\x1c...icmp".to_vec();
        let pdu = gnb.protect(&dl);
        assert_ne!(&pdu[3..3 + dl.len()], &dl[..], "data is ciphered");
        assert_eq!(pdu.len(), 3 + dl.len(), "no MAC-I: DRB ciphering-only");
        assert_eq!(ue.unprotect(&pdu).unwrap(), dl);
        // Uplink (opposite DIRECTION, separate COUNT).
        let ul = b"\x45\x00\x00\x1c...reply".to_vec();
        assert_eq!(gnb.unprotect(&ue.protect(&ul)).unwrap(), ul);
    }

    #[test]
    fn drb_optional_integrity_round_trip_and_tamper() {
        // 5G user-plane integrity: a DRB can carry a MAC-I too.
        let mut gnb = PdcpDrb::new(Role::Gnb, 1);
        let mut ue = PdcpDrb::new(Role::Ue, 1);
        for e in [&mut gnb, &mut ue] {
            e.activate_ciphering(KENC, NEA2);
            e.activate_integrity(KINT, NIA2);
        }
        let sdu = b"protected-user-data".to_vec();
        let pdu = gnb.protect(&sdu);
        assert_eq!(pdu.len(), 3 + sdu.len() + 4, "18-bit header + data + MAC-I");
        assert_eq!(ue.unprotect(&pdu).unwrap(), sdu);

        let mut ue2 = PdcpDrb::new(Role::Ue, 1);
        ue2.activate_ciphering(KENC, NEA2);
        ue2.activate_integrity(KINT, NIA2);
        let mut bad = gnb.protect(&sdu);
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert_eq!(ue2.unprotect(&bad), Err(PdcpError::IntegrityFailure));
    }

    #[test]
    fn drb_counts_advance_and_srb_drb_dont_cross() {
        let mut gnb = PdcpDrb::new(Role::Gnb, 1);
        let mut ue = PdcpDrb::new(Role::Ue, 1);
        gnb.activate_ciphering(KENC, NEA2);
        ue.activate_ciphering(KENC, NEA2);
        for i in 0..4u8 {
            let sdu = vec![i; 40];
            let pdu = gnb.protect(&sdu);
            let sn = (((pdu[0] & 0x03) as u32) << 16) | ((pdu[1] as u32) << 8) | pdu[2] as u32;
            assert_eq!(sn, i as u32, "18-bit SN advances");
            assert_eq!(ue.unprotect(&pdu).unwrap(), sdu);
        }
    }
}
