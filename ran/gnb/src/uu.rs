//! The P1 **Uu**: the gNB↔UE radio link as one message per UDP datagram. Control-plane
//! signalling now rides **real RRC over PDCP** on signalling radio bearers (design/128
//! Phase 1) — SRB0 carries the raw RRC connection-setup messages (no PDCP, as on CCCH),
//! SRB1 carries PDCP-protected RRC (the DCCH: NAS transport, the security-mode procedure,
//! reconfiguration, release). NAS is opaque inside the RRC. The user plane stays raw IP
//! per PDU session (DRB PDCP/SDAP is Phase 2). The UE side lives in the BDD crate; both
//! ends share this codec so the framing cannot drift.
//!
//! Framing: octet 0 is the message type (uplink `0x0x`, downlink `0x8x`); the trailing
//! field runs to the end of the datagram.

/// A UE→gNB message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UlMessage {
    /// An uplink message on a signalling radio bearer. `srb_id` 0 carries a raw RRC
    /// UL-CCCH message (RRCSetupRequest); `srb_id` 1 carries a PDCP PDU wrapping an
    /// UL-DCCH message. The gNB decodes RRC to drive its NGAP procedures.
    Srb { srb_id: u8, payload: Vec<u8> },
    /// The UE goes radio-idle — the user-inactivity trigger for the gNB's AN release
    /// (→ UEContextReleaseRequest). A real gNB detects this with a timer; the Uu lets
    /// the UE announce it so tests drive the same transition.
    Idle,
    /// An uplink user-plane IP packet on PDU session `psi` (→ N3 G-PDU with QFI).
    Data { psi: u8, packet: Vec<u8> },
}

/// A gNB→UE message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlMessage {
    /// A downlink message on a signalling radio bearer (SRB0 raw RRC, SRB1 PDCP-wrapped
    /// RRC): RRCSetup, DL NAS transport, the security-mode command, reconfiguration,
    /// release.
    Srb { srb_id: u8, payload: Vec<u8> },
    /// A page for the UE holding `tmsi` — broadcast (PCCH) to every camped UE; each
    /// matches its own 5G-TMSI, as on a real paging occasion.
    Paging { tmsi: u32 },
    /// The UE's RAN context was released (AN release completed).
    Released,
    /// A downlink user-plane IP packet on PDU session `psi` (decapped from N3).
    Data { psi: u8, packet: Vec<u8> },
}

const UL_SRB: u8 = 0x01;
const UL_IDLE: u8 = 0x03;
const UL_DATA: u8 = 0x04;
const DL_SRB: u8 = 0x81;
const DL_PAGING: u8 = 0x82;
const DL_RELEASED: u8 = 0x83;
const DL_DATA: u8 = 0x84;

impl UlMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            UlMessage::Srb { srb_id, payload } => srb_frame(UL_SRB, *srb_id, payload),
            UlMessage::Idle => vec![UL_IDLE],
            UlMessage::Data { psi, packet } => data_frame(UL_DATA, *psi, packet),
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        match *data.first()? {
            UL_SRB => Some(UlMessage::Srb { srb_id: *data.get(1)?, payload: data.get(2..)?.to_vec() }),
            UL_IDLE if data.len() == 1 => Some(UlMessage::Idle),
            UL_DATA => Some(UlMessage::Data { psi: *data.get(1)?, packet: data.get(2..)?.to_vec() }),
            _ => None,
        }
    }
}

impl DlMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            DlMessage::Srb { srb_id, payload } => srb_frame(DL_SRB, *srb_id, payload),
            DlMessage::Paging { tmsi } => prefixed(DL_PAGING, &tmsi.to_be_bytes()),
            DlMessage::Released => vec![DL_RELEASED],
            DlMessage::Data { psi, packet } => data_frame(DL_DATA, *psi, packet),
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        match *data.first()? {
            DL_SRB => Some(DlMessage::Srb { srb_id: *data.get(1)?, payload: data.get(2..)?.to_vec() }),
            DL_PAGING => Some(DlMessage::Paging {
                tmsi: u32::from_be_bytes(<[u8; 4]>::try_from(data.get(1..5)?).ok()?),
            }),
            DL_RELEASED if data.len() == 1 => Some(DlMessage::Released),
            DL_DATA => Some(DlMessage::Data { psi: *data.get(1)?, packet: data.get(2..)?.to_vec() }),
            _ => None,
        }
    }
}

fn prefixed(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// A frame carrying an `(id, payload)` — one leading id octet then the payload.
fn srb_frame(kind: u8, srb_id: u8, payload: &[u8]) -> Vec<u8> {
    data_frame(kind, srb_id, payload)
}

fn data_frame(kind: u8, id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(kind);
    out.push(id);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uplink_messages_roundtrip() {
        let msgs = [
            UlMessage::Srb { srb_id: 0, payload: vec![0x10, 0x20] },
            UlMessage::Srb { srb_id: 1, payload: vec![0x00, 0x01, 0x7e, 0x00] },
            UlMessage::Idle,
            UlMessage::Data { psi: 1, packet: vec![0x45, 0x00, 0x00, 0x14] },
        ];
        for msg in msgs {
            assert_eq!(UlMessage::decode(&msg.encode()), Some(msg.clone()), "{msg:?}");
        }
        // An empty SRB payload survives too.
        let empty = UlMessage::Srb { srb_id: 1, payload: vec![] };
        assert_eq!(UlMessage::decode(&empty.encode()), Some(empty));
    }

    #[test]
    fn downlink_messages_roundtrip() {
        let msgs = [
            DlMessage::Srb { srb_id: 0, payload: vec![0x1c, 0x00] },
            DlMessage::Srb { srb_id: 1, payload: vec![0x00, 0x02, 0xaa] },
            DlMessage::Paging { tmsi: 7 },
            DlMessage::Released,
            DlMessage::Data { psi: 1, packet: vec![0x45, 0x00] },
        ];
        for msg in msgs {
            assert_eq!(DlMessage::decode(&msg.encode()), Some(msg.clone()), "{msg:?}");
        }
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert_eq!(UlMessage::decode(&[]), None);
        assert_eq!(UlMessage::decode(&[0x7f]), None, "unknown type");
        assert_eq!(UlMessage::decode(&[UL_SRB]), None, "missing srb id");
        assert_eq!(DlMessage::decode(&[DL_PAGING, 0, 0]), None, "truncated tmsi");
        assert_eq!(DlMessage::decode(&[DL_RELEASED, 0]), None, "trailing junk");
        // Uplink and downlink type spaces do not overlap.
        assert_eq!(UlMessage::decode(&DlMessage::Released.encode()), None);
        assert_eq!(DlMessage::decode(&UlMessage::Idle.encode()), None);
    }
}
