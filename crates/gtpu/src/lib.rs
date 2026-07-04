//! GTP-U — GPRS Tunnelling Protocol, user plane (TS 29.281), used on N3
//! ((R)AN↔UPF) and N9 (UPF↔UPF). Binary header over UDP (port 2152) — not ASN.1.
//!
//! Minimal codec: the mandatory 8-byte header (+4 optional octets when the
//! sequence flag is set), **G-PDU** encapsulation/decapsulation, and **Echo** path
//! management. Extension headers and N-PDU numbers are parsed-around but not yet
//! interpreted.

/// Default GTP-U UDP port (TS 29.281).
pub const GTPU_PORT: u16 = 2152;

// GTP-U message types (TS 29.281 §7.1).
pub const MSG_ECHO_REQUEST: u8 = 1;
pub const MSG_ECHO_RESPONSE: u8 = 2;
pub const MSG_END_MARKER: u8 = 254;
pub const MSG_G_PDU: u8 = 0xFF;

const VERSION_PT: u8 = 0x30; // version=1 (bits 8-6), protocol type=1 (bit 5)
const FLAG_S: u8 = 0x02; // sequence number present
const FLAG_E: u8 = 0x04; // extension header present
const FLAG_PN: u8 = 0x01; // N-PDU number present
const RECOVERY_IE: u8 = 14; // GTPv1 Recovery IE type

/// A decoded GTP-U message (borrowing the datagram for the G-PDU payload).
#[derive(Debug, PartialEq, Eq)]
pub enum N3Message<'a> {
    /// User data (T-PDU) for a tunnel.
    GPdu { teid: u32, payload: &'a [u8] },
    EchoRequest { sequence: u16 },
    EchoResponse { sequence: u16 },
    /// End Marker (TS 29.281 §7.3.4) on `teid` — the last packet has left this
    /// tunnel (sent by the UPF on the old downlink path after a handover).
    EndMarker { teid: u32 },
    /// Any other / unhandled message type.
    Other(u8),
}

/// Parse a GTP-U datagram.
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
    let header_len = if has_opt { 12 } else { 8 };
    if data.len() < header_len {
        return None;
    }
    let sequence = if has_opt {
        u16::from_be_bytes([data[8], data[9]])
    } else {
        0
    };
    let payload = &data[header_len..];
    Some(match msg_type {
        MSG_G_PDU => N3Message::GPdu { teid, payload },
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
        N3Message::GPdu { teid, payload } => Some((teid, payload)),
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
            Some(N3Message::GPdu { teid: 0xABCDEF01, payload: inner })
        );
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
