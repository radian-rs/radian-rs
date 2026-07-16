//! NR-U — the NR User Plane Protocol (TS 38.425): the frames carried in GTP-U's **NR RAN
//! Container** extension header on **F1-U** (CU-UP ↔ DU) and Xn-U. It provides flow control
//! between the CU-UP and the DU: the CU-UP marks each downlink PDCP PDU with an NR-U
//! sequence number (DL USER DATA), and the DU reports back how much buffer it wants for the
//! bearer (DL DATA DELIVERY STATUS).
//!
//! Only the minimal frames are built (no discard/flush blocks, lost-SN ranges, timestamps,
//! or data-rate fields); parsing reads the fixed fields and ignores the optional tail.
//! Field layout cross-checked against OCUDU's `lib/nru`.

/// PDU Type 0 — DL USER DATA (TS 38.425 §5.5.2.1), CU-UP → DU.
pub const DL_USER_DATA: u8 = 0;
/// PDU Type 1 — DL DATA DELIVERY STATUS (TS 38.425 §5.5.2.2), DU → CU-UP.
pub const DL_DATA_DELIVERY_STATUS: u8 = 1;

/// A parsed NR-U frame (the fixed fields our minimal codec carries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NruFrame {
    /// DL USER DATA: the NR-U sequence number of this downlink PDCP PDU.
    DlUserData { nru_sn: u32 },
    /// DL DATA DELIVERY STATUS: the buffer size (octets) the DU wants for the bearer.
    DlDataDeliveryStatus { desired_buffer_size: u32 },
}

/// Build a minimal **DL USER DATA** frame (PDU type 0) carrying `nru_sn` — CU-UP → DU on
/// each downlink PDCP PDU. Padded to `(n*4-2)` octets per TS 38.425 §5.5.1.
pub fn dl_user_data(nru_sn: u32) -> Vec<u8> {
    // octet 0: PDU type (bits 7-4) + spare/flags (all 0); octet 1: flags (all 0);
    // octets 2-4: NR-U Sequence Number (24 bits).
    let mut out = vec![DL_USER_DATA << 4, 0x00];
    out.extend_from_slice(&nru_sn.to_be_bytes()[1..]); // low 24 bits
    pad(&mut out);
    out
}

/// Build a minimal **DL DATA DELIVERY STATUS** frame (PDU type 1) reporting the
/// `desired_buffer_size` (octets) the DU wants for the bearer — DU → CU-UP flow control.
pub fn dl_data_delivery_status(desired_buffer_size: u32) -> Vec<u8> {
    // octet 0: PDU type + flags; octet 1: flags; octets 2-5: Desired Buffer Size (32 bits).
    let mut out = vec![DL_DATA_DELIVERY_STATUS << 4, 0x00];
    out.extend_from_slice(&desired_buffer_size.to_be_bytes());
    pad(&mut out);
    out
}

/// Read an NR-U frame's fixed fields. The NR-U SN / desired buffer size sit at a fixed
/// offset regardless of the optional flags, so this works on frames the peer built with
/// options set. `None` for unknown PDU types or short frames.
pub fn parse(frame: &[u8]) -> Option<NruFrame> {
    match frame.first()? >> 4 {
        DL_USER_DATA => {
            let sn = ((*frame.get(2)? as u32) << 16) | ((*frame.get(3)? as u32) << 8) | *frame.get(4)? as u32;
            Some(NruFrame::DlUserData { nru_sn: sn })
        }
        DL_DATA_DELIVERY_STATUS => {
            let dbs = u32::from_be_bytes([*frame.get(2)?, *frame.get(3)?, *frame.get(4)?, *frame.get(5)?]);
            Some(NruFrame::DlDataDeliveryStatus { desired_buffer_size: dbs })
        }
        _ => None,
    }
}

/// Pad to `(n*4-2)` octets (TS 38.425 §5.5.1) — the NR-U frame plus the 2 GTP-U
/// extension-header framing octets is then a whole number of 4-octet units.
fn pad(out: &mut Vec<u8>) {
    while !(out.len() + 2).is_multiple_of(4) {
        out.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dl_user_data_layout_and_parse() {
        let f = dl_user_data(0x0A_BCDE);
        assert_eq!(f[0], 0x00, "PDU type 0, no flags");
        assert_eq!(&f[2..5], &[0x0A, 0xBC, 0xDE], "24-bit NR-U SN");
        assert!((f.len() + 2).is_multiple_of(4), "padded to n*4-2");
        assert_eq!(parse(&f), Some(NruFrame::DlUserData { nru_sn: 0x0A_BCDE }));
    }

    #[test]
    fn dl_data_delivery_status_layout_and_parse() {
        let f = dl_data_delivery_status(0x0001_0000);
        assert_eq!(f[0], 0x10, "PDU type 1 in the top nibble");
        assert_eq!(&f[2..6], &0x0001_0000u32.to_be_bytes(), "32-bit desired buffer size");
        assert!((f.len() + 2).is_multiple_of(4));
        assert_eq!(parse(&f), Some(NruFrame::DlDataDeliveryStatus { desired_buffer_size: 0x0001_0000 }));
    }

    #[test]
    fn unknown_pdu_types_and_short_frames_are_rejected() {
        assert_eq!(parse(&[0x20, 0, 0, 0, 0, 0]), None, "PDU type 2 not modeled");
        assert_eq!(parse(&[0x00, 0, 0]), None, "too short for a SN");
        assert_eq!(parse(&[]), None);
    }
}
