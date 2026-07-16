//! The P0 **fake Uu**: the gNB↔UE link as one message per UDP datagram, carrying
//! NAS and user-plane IP packets directly — no RRC/PDCP yet (design/128 Phase 0;
//! Phase 1 puts real RRC behind the same seam). The UE side lives in the BDD
//! crate; both ends share this codec so the framing cannot drift.
//!
//! Framing: octet 0 is the message type (uplink 0x0x, downlink 0x8x); fields are
//! big-endian; the trailing field runs to the end of the datagram.

/// A UE→gNB message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UlMessage {
    /// The UE's first message on a (new) connection — what RRC Setup carries up:
    /// the tracking area the UE camps on, an optional 5G-S-TMSI (a resuming or
    /// re-registering UE), and the initial NAS message. Makes the gNB allocate a
    /// fresh RAN UE context and send an NGAP InitialUEMessage.
    InitialUe { tac: [u8; 3], s_tmsi: Option<u32>, nas: Vec<u8> },
    /// An uplink NAS message on the established connection (→ UplinkNASTransport).
    Nas { nas: Vec<u8> },
    /// The UE goes radio-idle — the user-inactivity trigger for the gNB's AN
    /// release (→ UEContextReleaseRequest). A real gNB detects this with a timer;
    /// the fake Uu lets the UE announce it so tests drive the same transition.
    Idle,
    /// An uplink user-plane IP packet on PDU session `psi` (→ N3 G-PDU with QFI).
    Data { psi: u8, packet: Vec<u8> },
}

/// A gNB→UE message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlMessage {
    /// A downlink NAS message (from DownlinkNASTransport, or relayed out of an
    /// InitialContextSetup / PDUSessionResourceSetup request).
    Nas { nas: Vec<u8> },
    /// A page for the UE holding `tmsi` — broadcast to every camped UE; each
    /// matches its own 5G-TMSI, as on a real paging occasion.
    Paging { tmsi: u32 },
    /// The UE's RAN context was released (AN release completed).
    Released,
    /// A downlink user-plane IP packet on PDU session `psi` (decapped from N3).
    Data { psi: u8, packet: Vec<u8> },
}

const UL_INITIAL_UE: u8 = 0x01;
const UL_NAS: u8 = 0x02;
const UL_IDLE: u8 = 0x03;
const UL_DATA: u8 = 0x04;
const DL_NAS: u8 = 0x81;
const DL_PAGING: u8 = 0x82;
const DL_RELEASED: u8 = 0x83;
const DL_DATA: u8 = 0x84;

impl UlMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            UlMessage::InitialUe { tac, s_tmsi, nas } => {
                let mut out = vec![UL_INITIAL_UE];
                out.extend_from_slice(tac);
                match s_tmsi {
                    Some(tmsi) => {
                        out.push(1);
                        out.extend_from_slice(&tmsi.to_be_bytes());
                    }
                    None => out.push(0),
                }
                out.extend_from_slice(nas);
                out
            }
            UlMessage::Nas { nas } => prefixed(UL_NAS, nas),
            UlMessage::Idle => vec![UL_IDLE],
            UlMessage::Data { psi, packet } => data_frame(UL_DATA, *psi, packet),
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        match *data.first()? {
            UL_INITIAL_UE => {
                let tac = <[u8; 3]>::try_from(data.get(1..4)?).ok()?;
                let (s_tmsi, nas_at) = match *data.get(4)? {
                    0 => (None, 5),
                    1 => (
                        Some(u32::from_be_bytes(<[u8; 4]>::try_from(data.get(5..9)?).ok()?)),
                        9,
                    ),
                    _ => return None,
                };
                Some(UlMessage::InitialUe { tac, s_tmsi, nas: data.get(nas_at..)?.to_vec() })
            }
            UL_NAS => Some(UlMessage::Nas { nas: data[1..].to_vec() }),
            UL_IDLE if data.len() == 1 => Some(UlMessage::Idle),
            UL_DATA => {
                Some(UlMessage::Data { psi: *data.get(1)?, packet: data.get(2..)?.to_vec() })
            }
            _ => None,
        }
    }
}

impl DlMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            DlMessage::Nas { nas } => prefixed(DL_NAS, nas),
            DlMessage::Paging { tmsi } => prefixed(DL_PAGING, &tmsi.to_be_bytes()),
            DlMessage::Released => vec![DL_RELEASED],
            DlMessage::Data { psi, packet } => data_frame(DL_DATA, *psi, packet),
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        match *data.first()? {
            DL_NAS => Some(DlMessage::Nas { nas: data[1..].to_vec() }),
            DL_PAGING => Some(DlMessage::Paging {
                tmsi: u32::from_be_bytes(<[u8; 4]>::try_from(data.get(1..5)?).ok()?),
            }),
            DL_RELEASED if data.len() == 1 => Some(DlMessage::Released),
            DL_DATA => {
                Some(DlMessage::Data { psi: *data.get(1)?, packet: data.get(2..)?.to_vec() })
            }
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

fn data_frame(kind: u8, psi: u8, packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + packet.len());
    out.push(kind);
    out.push(psi);
    out.extend_from_slice(packet);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uplink_messages_roundtrip() {
        let msgs = [
            UlMessage::InitialUe { tac: [0, 0, 1], s_tmsi: None, nas: vec![0x7e, 0x00, 0x41] },
            UlMessage::InitialUe {
                tac: [0, 0, 2],
                s_tmsi: Some(0xDEAD_BEEF),
                nas: vec![0x7e, 0x00, 0x4c],
            },
            UlMessage::Nas { nas: vec![0x7e, 0x02, 0xaa] },
            UlMessage::Idle,
            UlMessage::Data { psi: 1, packet: vec![0x45, 0x00, 0x00, 0x14] },
        ];
        for msg in msgs {
            assert_eq!(UlMessage::decode(&msg.encode()), Some(msg.clone()), "{msg:?}");
        }
        // Empty NAS survives too (degenerate but must not panic or misparse).
        let empty = UlMessage::Nas { nas: vec![] };
        assert_eq!(UlMessage::decode(&empty.encode()), Some(empty));
    }

    #[test]
    fn downlink_messages_roundtrip() {
        let msgs = [
            DlMessage::Nas { nas: vec![0x7e, 0x00, 0x42] },
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
        assert_eq!(UlMessage::decode(&[UL_INITIAL_UE, 0, 0]), None, "truncated TAC");
        assert_eq!(UlMessage::decode(&[UL_INITIAL_UE, 0, 0, 1, 2]), None, "bad s-tmsi flag");
        assert_eq!(UlMessage::decode(&[UL_INITIAL_UE, 0, 0, 1, 1, 0xde]), None, "truncated s-tmsi");
        assert_eq!(DlMessage::decode(&[DL_PAGING, 0, 0]), None, "truncated tmsi");
        assert_eq!(DlMessage::decode(&[DL_RELEASED, 0]), None, "trailing junk");
        // Uplink and downlink type spaces do not overlap.
        assert_eq!(UlMessage::decode(&DlMessage::Released.encode()), None);
        assert_eq!(DlMessage::decode(&UlMessage::Idle.encode()), None);
    }
}
