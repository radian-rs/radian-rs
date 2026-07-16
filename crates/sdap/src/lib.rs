//! SDAP — Service Data Adaptation Protocol (TS 37.324), the top of the NR user-plane
//! stack. It maps QoS flows to data radio bearers: on the downlink it can mark each
//! packet with reflective-QoS bits, and on both directions it carries the **QFI** so the
//! peer knows which QoS flow a packet belongs to (design/128 Phase 2).
//!
//! This crate is the SDAP **Data PDU header** codec — a single octet (TS 37.324 §6.2.2):
//! ```text
//!  Uplink  (with SDAP header):  D/C | R  | QFI[5:0]
//!  Downlink(with SDAP header):  RDI | RQI | QFI[5:0]
//! ```
//! `D/C` = 1 for a Data PDU; `RDI` (Reflective QoS flow to DRB mapping Indication) and
//! `RQI` (Reflective QoS Indication) drive reflective QoS. A DRB configured **without** an
//! SDAP header is a pass-through — the QFI is fixed per DRB by configuration (OCUDU's
//! default single-flow DRB works this way), so the `encap_*`/[`decap`] helpers here are
//! simply not used for it.

/// The QFI occupies the low 6 bits of the SDAP header octet (TS 23.501: 0..63).
pub const QFI_MASK: u8 = 0x3F;
/// D/C bit (uplink header): 1 = Data PDU.
const DC_DATA: u8 = 0x80;
/// RDI bit (downlink header): reflective QoS flow → DRB mapping.
const RDI: u8 = 0x80;
/// RQI bit (downlink header): reflective QoS indication.
const RQI: u8 = 0x40;

/// A parsed downlink SDAP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlHeader {
    pub qfi: u8,
    /// Reflective QoS Indication — the UE should update its UL QoS-flow → DRB mapping.
    pub rqi: bool,
    /// Reflective QoS flow to DRB mapping Indication.
    pub rdi: bool,
}

/// Prepend an **uplink** SDAP header carrying `qfi` to a user IP packet (UE → gNB).
pub fn encap_ul(qfi: u8, packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + packet.len());
    out.push(DC_DATA | (qfi & QFI_MASK)); // D/C = 1 (data), R = 0
    out.extend_from_slice(packet);
    out
}

/// Prepend a **downlink** SDAP header carrying `qfi` (and the reflective-QoS bits) to a
/// user IP packet (gNB → UE).
pub fn encap_dl(qfi: u8, rqi: bool, rdi: bool, packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + packet.len());
    out.push((if rdi { RDI } else { 0 }) | (if rqi { RQI } else { 0 }) | (qfi & QFI_MASK));
    out.extend_from_slice(packet);
    out
}

/// Strip the 1-octet SDAP header, returning `(qfi, payload)` — the QFI is in the low 6
/// bits regardless of direction. Use this on the uplink (gNB) side, or when only the QFI
/// is needed. `None` if the PDU is empty.
pub fn decap(pdu: &[u8]) -> Option<(u8, &[u8])> {
    let first = *pdu.first()?;
    Some((first & QFI_MASK, &pdu[1..]))
}

/// Strip a **downlink** SDAP header, returning the full [`DlHeader`] (with the
/// reflective-QoS bits) and the payload — used on the UE side.
pub fn decap_dl(pdu: &[u8]) -> Option<(DlHeader, &[u8])> {
    let first = *pdu.first()?;
    let header = DlHeader {
        qfi: first & QFI_MASK,
        rqi: first & RQI != 0,
        rdi: first & RDI != 0,
    };
    Some((header, &pdu[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uplink_header_roundtrips_with_qfi() {
        let ip = b"\x45\x00\x00\x14 ip";
        let pdu = encap_ul(9, ip);
        assert_eq!(pdu[0], 0x80 | 9, "D/C=1, QFI 9");
        assert_eq!(decap(&pdu), Some((9, &ip[..])));
        // QFI is masked to 6 bits.
        assert_eq!(encap_ul(0xFF, b"x")[0] & QFI_MASK, 0x3F);
    }

    #[test]
    fn downlink_header_carries_qfi_and_reflective_bits() {
        let ip = b"\x45\x00 dl";
        let pdu = encap_dl(5, true, false, ip);
        assert_eq!(pdu[0], RQI | 5, "RQI set, RDI clear, QFI 5");
        assert_eq!(
            decap(&pdu),
            Some((5, &ip[..])),
            "the QFI reads out either way"
        );
        assert_eq!(
            decap_dl(&pdu),
            Some((
                DlHeader {
                    qfi: 5,
                    rqi: true,
                    rdi: false
                },
                &ip[..]
            ))
        );
        // Both reflective bits.
        let (h, _) = decap_dl(&encap_dl(1, true, true, b"z")).unwrap();
        assert_eq!(
            h,
            DlHeader {
                qfi: 1,
                rqi: true,
                rdi: true
            }
        );
    }

    #[test]
    fn empty_pdu_is_rejected() {
        assert_eq!(decap(&[]), None);
        assert_eq!(decap_dl(&[]), None);
        // A header-only PDU decaps to an empty payload (degenerate but well-defined).
        assert_eq!(decap(&encap_ul(3, b"")), Some((3, &b""[..])));
    }
}
