//! GTP-U — GPRS Tunnelling Protocol, user plane (TS 29.281), used on N3
//! ((R)AN↔UPF) and N9 (UPF↔UPF). Binary header over UDP (port 2152) — not ASN.1.
//!
//! Codec: the mandatory 8-byte header (+4 optional octets when any of the S/E/PN
//! flags is set), **G-PDU** encapsulation/decapsulation, **Echo** path management,
//! and the **extension header** chain (TS 29.281 §5.2.1). The one extension header
//! interpreted is the **PDU Session Container** (type 0x85), whose content is a
//! TS 38.415 PDU Session User Plane protocol frame — see [`psup`] — carrying the
//! **QFI** that maps each G-PDU to its QoS flow on N3.

/// Default GTP-U UDP port (TS 29.281).
pub const GTPU_PORT: u16 = 2152;

// GTP-U message types (TS 29.281 §7.1).
pub const MSG_ECHO_REQUEST: u8 = 1;
pub const MSG_ECHO_RESPONSE: u8 = 2;
pub const MSG_END_MARKER: u8 = 254;
pub const MSG_G_PDU: u8 = 0xFF;

/// Extension header type: PDU Session Container (TS 29.281 §5.2.2.7), whose
/// content is a TS 38.415 [`psup`] frame.
pub const EXT_PDU_SESSION_CONTAINER: u8 = 0x85;

const VERSION_PT: u8 = 0x30; // version=1 (bits 8-6), protocol type=1 (bit 5)
const FLAG_S: u8 = 0x02; // sequence number present
const FLAG_E: u8 = 0x04; // extension header present
const FLAG_PN: u8 = 0x01; // N-PDU number present
const RECOVERY_IE: u8 = 14; // GTPv1 Recovery IE type

pub mod psup;

/// A decoded GTP-U message (borrowing the datagram for the G-PDU payload).
#[derive(Debug, PartialEq, Eq)]
pub enum N3Message<'a> {
    /// User data (T-PDU) for a tunnel. `qfi` is the QoS Flow Identifier from a
    /// PDU Session Container extension header, when the sender attached one.
    GPdu { teid: u32, qfi: Option<u8>, payload: &'a [u8] },
    EchoRequest { sequence: u16 },
    EchoResponse { sequence: u16 },
    /// End Marker (TS 29.281 §7.3.4) on `teid` — the last packet has left this
    /// tunnel (sent by the UPF on the old downlink path after a handover).
    EndMarker { teid: u32 },
    /// Any other / unhandled message type.
    Other(u8),
}

/// Parse a GTP-U datagram, walking any extension-header chain to find where the
/// payload starts (and reading the QFI out of a PDU Session Container).
pub fn parse(data: &[u8]) -> Option<N3Message<'_>> {
    if data.len() < 8 {
        return None;
    }
    let flags = data[0];
    if flags & 0xE0 != 0x20 {
        return None; // not GTP version 1
    }
    let msg_type = data[1];
    let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let has_opt = flags & (FLAG_S | FLAG_E | FLAG_PN) != 0;
    let mut offset = if has_opt { 12 } else { 8 };
    if data.len() < offset {
        return None;
    }
    let sequence = if has_opt {
        u16::from_be_bytes([data[8], data[9]])
    } else {
        0
    };
    // Extension headers (TS 29.281 §5.2.1): the 12th octet is the first "next
    // extension header type"; each header is `length (in 4-octet units) |
    // content | next type`, and type 0 ends the chain.
    let mut qfi = None;
    if flags & FLAG_E != 0 {
        let mut next = data[11];
        while next != 0 {
            let len = 4 * (*data.get(offset)? as usize);
            if len < 4 || data.len() < offset + len {
                return None; // a zero-length or truncated extension header
            }
            if next == EXT_PDU_SESSION_CONTAINER {
                qfi = psup::parse(&data[offset + 1..offset + len - 1]).map(|i| i.qfi);
            }
            next = data[offset + len - 1];
            offset += len;
        }
    }
    let payload = &data[offset..];
    Some(match msg_type {
        MSG_G_PDU => N3Message::GPdu { teid, qfi, payload },
        MSG_ECHO_REQUEST => N3Message::EchoRequest { sequence },
        MSG_ECHO_RESPONSE => N3Message::EchoResponse { sequence },
        MSG_END_MARKER => N3Message::EndMarker { teid },
        other => N3Message::Other(other),
    })
}

/// Encapsulate a user IP packet as a G-PDU for `teid` (the datapath).
pub fn encap(teid: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(VERSION_PT);
    out.push(MSG_G_PDU);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&teid.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Encapsulate an **uplink** packet as a G-PDU carrying a PDU Session Container
/// with the UL PDU SESSION INFORMATION frame for `qfi` (TS 38.415 §5.5.2.2) —
/// how a gNB marks each N3 uplink packet with its QoS flow.
pub fn encap_ul_qfi(teid: u32, qfi: u8, payload: &[u8]) -> Vec<u8> {
    encap_with_container(teid, &psup::ul_frame(qfi), payload)
}

/// Encapsulate a **downlink** packet as a G-PDU carrying a PDU Session Container
/// with the DL PDU SESSION INFORMATION frame for `qfi` (TS 38.415 §5.5.2.1) —
/// how a UPF marks each N3 downlink packet (`rqi` = Reflective QoS Indicator).
pub fn encap_dl_qfi(teid: u32, qfi: u8, rqi: bool, payload: &[u8]) -> Vec<u8> {
    encap_with_container(teid, &psup::dl_frame(qfi, rqi), payload)
}

/// A G-PDU whose extension chain is exactly one PDU Session Container holding a
/// minimal (2-octet) PSUP frame.
fn encap_with_container(teid: u32, frame: &[u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + payload.len());
    out.push(VERSION_PT | FLAG_E);
    out.push(MSG_G_PDU);
    // Length covers everything after the first 8 octets: the 4 optional octets
    // plus the 4-octet extension header plus the payload.
    out.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    out.extend_from_slice(&teid.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, EXT_PDU_SESSION_CONTAINER]); // seq, N-PDU, next type
    out.push(1); // extension header length: one 4-octet unit
    out.extend_from_slice(frame);
    out.push(0); // no further extension headers
    out.extend_from_slice(payload);
    out
}

/// Build a GTP-U **End Marker** (TS 29.281 §7.3.4) for `teid` — a payload-less
/// message on the old downlink tunnel, sent by the UPF after a path switch so the
/// (source) gNB knows the downlink stream on that tunnel has ended and can deliver
/// forwarded then direct-path packets in order.
pub fn end_marker(teid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.push(VERSION_PT);
    out.push(MSG_END_MARKER);
    out.extend_from_slice(&0u16.to_be_bytes()); // no payload
    out.extend_from_slice(&teid.to_be_bytes());
    out
}

/// Decapsulate a G-PDU, returning `(teid, inner_payload)`; `None` if not a G-PDU.
pub fn decap(data: &[u8]) -> Option<(u32, &[u8])> {
    match parse(data)? {
        N3Message::GPdu { teid, payload, .. } => Some((teid, payload)),
        _ => None,
    }
}

/// Build an Echo Request (path management).
pub fn echo_request(sequence: u16) -> Vec<u8> {
    echo(MSG_ECHO_REQUEST, sequence, &[])
}

/// Build an Echo Response carrying a Recovery IE (restart counter 0).
pub fn echo_response(sequence: u16) -> Vec<u8> {
    echo(MSG_ECHO_RESPONSE, sequence, &[RECOVERY_IE, 0x00])
}

fn echo(msg_type: u8, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.push(VERSION_PT | FLAG_S);
    out.push(msg_type);
    out.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // TEID 0 for path management
    out.extend_from_slice(&sequence.to_be_bytes());
    out.push(0); // N-PDU number
    out.push(0); // next extension header type
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpdu_encap_decap_roundtrip() {
        let inner = b"\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x01"; // start of a fake IPv4 packet
        let pkt = encap(0xABCDEF01, inner);
        assert_eq!(decap(&pkt), Some((0xABCDEF01, &inner[..])));
        assert_eq!(
            parse(&pkt),
            Some(N3Message::GPdu { teid: 0xABCDEF01, qfi: None, payload: inner })
        );
    }

    #[test]
    fn ul_qfi_encap_roundtrips_and_matches_the_wire_layout() {
        let inner = b"\x45\x00\x00\x14";
        let pkt = encap_ul_qfi(0x1001, 9, inner);
        // Header: E flag set, length = payload + 8, then seq/N-PDU/next-type,
        // then the one-unit PDU Session Container with the 2-octet UL frame.
        assert_eq!(pkt[0], VERSION_PT | FLAG_E);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, inner.len() + 8);
        assert_eq!(pkt[11], EXT_PDU_SESSION_CONTAINER);
        assert_eq!(&pkt[12..16], &[1, 0x10, 9, 0], "len=1 unit, UL frame, chain end");
        assert_eq!(
            parse(&pkt),
            Some(N3Message::GPdu { teid: 0x1001, qfi: Some(9), payload: &inner[..] })
        );
        // decap ignores the container but must skip it correctly.
        assert_eq!(decap(&pkt), Some((0x1001, &inner[..])));
    }

    #[test]
    fn dl_qfi_encap_roundtrips_with_rqi() {
        let inner = [0u8; 20];
        let pkt = encap_dl_qfi(0x2001, 5, true, &inner);
        assert_eq!(&pkt[12..16], &[1, 0x00, 0x45, 0], "DL frame: RQI + QFI 5");
        match parse(&pkt) {
            Some(N3Message::GPdu { teid, qfi, payload }) => {
                assert_eq!((teid, qfi, payload), (0x2001, Some(5), &inner[..]));
            }
            other => panic!("expected a G-PDU, got {other:?}"),
        }
    }

    #[test]
    fn unknown_extension_headers_are_skipped() {
        // Hand-build a G-PDU with an unknown 8-octet extension header (type 0x40)
        // chained before a PDU Session Container.
        let inner = b"payload";
        let mut pkt = vec![VERSION_PT | FLAG_E, MSG_G_PDU];
        pkt.extend_from_slice(&((4 + 8 + 4 + inner.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&0x42u32.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0x40]); // seq, N-PDU, next = unknown type
        pkt.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, EXT_PDU_SESSION_CONTAINER]); // 2 units
        pkt.extend_from_slice(&[1, 0x10, 3, 0]); // UL frame, QFI 3, chain end
        pkt.extend_from_slice(inner);
        assert_eq!(
            parse(&pkt),
            Some(N3Message::GPdu { teid: 0x42, qfi: Some(3), payload: &inner[..] })
        );
    }

    #[test]
    fn truncated_or_zero_length_extension_chains_are_rejected() {
        let mut pkt = encap_ul_qfi(1, 1, b"x");
        pkt[12] = 0; // extension length 0 would loop forever — must be rejected
        assert_eq!(parse(&pkt), None);
        let pkt = encap_ul_qfi(1, 1, b"x");
        assert_eq!(parse(&pkt[..14]), None, "chain runs past the datagram");
    }

    #[test]
    fn echo_roundtrip() {
        assert_eq!(parse(&echo_request(7)), Some(N3Message::EchoRequest { sequence: 7 }));
        assert_eq!(parse(&echo_response(7)), Some(N3Message::EchoResponse { sequence: 7 }));
    }

    #[test]
    fn end_marker_roundtrips() {
        let em = end_marker(0x00000077);
        assert_eq!(parse(&em), Some(N3Message::EndMarker { teid: 0x00000077 }));
        // Message type 254, no payload (length 0).
        assert_eq!(em[1], MSG_END_MARKER);
        assert_eq!(&em[2..4], &[0x00, 0x00]);
        assert_eq!(em.len(), 8);
        assert!(decap(&em).is_none(), "an End Marker is not a G-PDU");
    }

    #[test]
    fn rejects_non_gtpv1_short_and_non_gpdu() {
        assert!(parse(&[0u8; 4]).is_none());
        assert!(parse(&[0x00, 0xFF, 0, 0, 0, 0, 0, 0]).is_none()); // GTP version 0
        assert!(decap(&echo_request(1)).is_none()); // Echo is not a G-PDU
    }
}
