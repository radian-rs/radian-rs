//! PSUP — the PDU Session User Plane protocol (TS 38.415): the frames carried in
//! GTP-U's **PDU Session Container** extension header on N3/N9, mapping each
//! G-PDU to its QoS flow (**QFI**) and, downlink, signalling Reflective QoS
//! (**RQI**).
//!
//! Only the minimal 2-octet frames are built (no QMP timestamps, PPI, or QFI
//! sequence numbers); parsing reads QFI/RQI from the first two octets and
//! ignores the optional tail. Field layout cross-checked against OCUDU's
//! `lib/psup` (BSD-3-Clause-Open-MPI).

/// PDU Type 0 — DL PDU SESSION INFORMATION (TS 38.415 §5.5.2.1), UPF → NG-RAN.
pub const DL_PDU_SESSION_INFORMATION: u8 = 0;
/// PDU Type 1 — UL PDU SESSION INFORMATION (TS 38.415 §5.5.2.2), NG-RAN → UPF.
pub const UL_PDU_SESSION_INFORMATION: u8 = 1;

/// The QoS marking read from a PDU Session Container frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduSessionInfo {
    /// Whether the frame is DL PDU SESSION INFORMATION (else UL).
    pub downlink: bool,
    /// QoS Flow Identifier (6 bits).
    pub qfi: u8,
    /// Reflective QoS Indicator — DL only, always `false` on UL frames.
    pub rqi: bool,
}

/// A minimal UL PDU SESSION INFORMATION frame for `qfi`:
/// octet 1 = PDU type 1 (bits 8-5) + QMP/DL-delay/UL-delay/SNP all zero,
/// octet 2 = 2 spare bits + QFI. Two octets — the ext-header framing pads the
/// total to a 4-octet multiple, per the "(n*4-2) octets" rule of TS 38.415 §5.5.1.
pub fn ul_frame(qfi: u8) -> [u8; 2] {
    [UL_PDU_SESSION_INFORMATION << 4, qfi & 0x3F]
}

/// A minimal DL PDU SESSION INFORMATION frame for `qfi`:
/// octet 1 = PDU type 0 + QMP/SNP/spare zero, octet 2 = PPP(0) | RQI | QFI.
pub fn dl_frame(qfi: u8, rqi: bool) -> [u8; 2] {
    [DL_PDU_SESSION_INFORMATION << 4, ((rqi as u8) << 6) | (qfi & 0x3F)]
}

/// Read the QFI (and, downlink, the RQI) from a PDU Session Container frame.
/// Optional fields flagged in octet 1 (timestamps, PPI, sequence numbers) trail
/// the fixed two octets and are ignored. `None` for unknown PDU types.
pub fn parse(frame: &[u8]) -> Option<PduSessionInfo> {
    let second = *frame.get(1)?;
    match frame[0] >> 4 {
        DL_PDU_SESSION_INFORMATION => Some(PduSessionInfo {
            downlink: true,
            qfi: second & 0x3F,
            rqi: second & 0x40 != 0,
        }),
        UL_PDU_SESSION_INFORMATION => Some(PduSessionInfo {
            downlink: false,
            qfi: second & 0x3F,
            rqi: false,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ul_frame_layout_and_parse() {
        assert_eq!(ul_frame(1), [0x10, 0x01]);
        assert_eq!(ul_frame(0x7F), [0x10, 0x3F], "QFI is 6 bits");
        assert_eq!(
            parse(&ul_frame(9)),
            Some(PduSessionInfo { downlink: false, qfi: 9, rqi: false })
        );
    }

    #[test]
    fn dl_frame_layout_and_parse() {
        assert_eq!(dl_frame(1, false), [0x00, 0x01]);
        assert_eq!(dl_frame(5, true), [0x00, 0x45]);
        assert_eq!(
            parse(&dl_frame(5, true)),
            Some(PduSessionInfo { downlink: true, qfi: 5, rqi: true })
        );
    }

    #[test]
    fn unknown_pdu_types_and_short_frames_are_rejected() {
        assert_eq!(parse(&[0x20, 0x01]), None, "PDU type 2 is undefined");
        assert_eq!(parse(&[0x10]), None, "a frame needs both octets");
        assert_eq!(parse(&[]), None);
    }
}
