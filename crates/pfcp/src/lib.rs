//! PFCP — Packet Forwarding Control Protocol (TS 29.244), the N4 protocol between
//! SMF (control) and UPF (user plane). Binary TLV over UDP — not ASN.1.
//!
//! Wraps the [`rs_pfcp`] codec and adds SMF-side request builders + a stateful
//! UPF-side handler for node-level **association**/**heartbeat** and PFCP
//! **session establishment** (the SMF provisions an uplink PDR/FAR; the UPF
//! allocates an N3 F-TEID and tracks the session). The GTP-U datapath and session
//! modification/deletion come in later slices.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::SystemTime;

pub use rs_pfcp;
pub use rs_pfcp::ie::IeType;
pub use rs_pfcp::message::MsgType;

use rs_pfcp::ie::cause::CauseValue;
use rs_pfcp::ie::create_far::CreateFar;
use rs_pfcp::ie::create_pdr::CreatePdrBuilder;
use rs_pfcp::ie::created_pdr::CreatedPdr;
use rs_pfcp::ie::destination_interface::Interface;
use rs_pfcp::ie::f_teid::Fteid;
use rs_pfcp::ie::far_id::FarId;
use rs_pfcp::ie::fseid::Fseid;
use rs_pfcp::ie::pdi::PdiBuilder;
use rs_pfcp::ie::pdr_id::PdrId;
use rs_pfcp::ie::precedence::Precedence;
use rs_pfcp::message::association_setup_request::AssociationSetupRequestBuilder;
use rs_pfcp::message::association_setup_response::AssociationSetupResponseBuilder;
use rs_pfcp::message::heartbeat_request::HeartbeatRequestBuilder;
use rs_pfcp::message::heartbeat_response::HeartbeatResponseBuilder;
use rs_pfcp::message::session_establishment_request::SessionEstablishmentRequestBuilder;
use rs_pfcp::message::session_establishment_response::SessionEstablishmentResponseBuilder;
use rs_pfcp::message::Message;

/// Default N4 PFCP UDP port (TS 29.244).
pub const N4_PORT: u16 = 8805;

/// Minimal UPF state: the N3 F-TEID and UP-SEID allocators plus a session table
/// (UP-SEID → N3 TEID). The TEIDs are consumed by the GTP-U datapath in a later slice.
pub struct UpfState {
    next_teid: u32,
    next_seid: u64,
    sessions: HashMap<u64, u32>,
}

impl Default for UpfState {
    fn default() -> Self {
        Self::new()
    }
}

impl UpfState {
    pub fn new() -> Self {
        // TEID/SEID 0 are avoided (reserved/"choose" semantics).
        Self {
            next_teid: 1,
            next_seid: 1,
            sessions: HashMap::new(),
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Allocate a UP-SEID + N3 TEID for a new session and record it.
    fn establish(&mut self) -> (u64, u32) {
        let up_seid = self.next_seid;
        let teid = self.next_teid;
        self.next_seid += 1;
        self.next_teid += 1;
        self.sessions.insert(up_seid, teid);
        (up_seid, teid)
    }
}

/// SMF: build a PFCP Association Setup Request advertising this node.
pub fn association_setup_request(node_ip: Ipv4Addr, seq: u32) -> Vec<u8> {
    AssociationSetupRequestBuilder::new(seq)
        .node_id(node_ip)
        .recovery_time_stamp(SystemTime::now())
        .build()
        .marshal()
}

/// SMF: build a PFCP Heartbeat Request.
pub fn heartbeat_request(seq: u32) -> Vec<u8> {
    HeartbeatRequestBuilder::new(seq)
        .recovery_time_stamp(SystemTime::now())
        .build()
        .marshal()
}

/// SMF: build a PFCP Session Establishment Request for a basic uplink PDU session —
/// an uplink PDR (access → forward to core) whose N3 F-TEID the UPF allocates.
pub fn session_establishment_request(cp_seid: u64, seq: u32, smf_ip: Ipv4Addr) -> Vec<u8> {
    let pdi = PdiBuilder::uplink_access()
        .f_teid(Fteid::ipv4(0, smf_ip)) // placeholder; the UPF allocates the real N3 F-TEID
        .build()
        .expect("build PDI");
    let pdr = CreatePdrBuilder::new(PdrId::new(1))
        .precedence(Precedence::new(100))
        .pdi(pdi)
        .far_id(FarId::new(1))
        .build()
        .expect("build Create PDR");
    let far = CreateFar::builder(FarId::new(1))
        .forward_to(Interface::Core)
        .build()
        .expect("build Create FAR");

    SessionEstablishmentRequestBuilder::new(0u64, seq) // header SEID 0 — UPF has none yet
        .node_id(smf_ip)
        .fseid(cp_seid, smf_ip) // CP F-SEID
        .create_pdrs(vec![pdr.to_ie()])
        .create_fars(vec![far.to_ie()])
        .build()
        .expect("build Session Establishment Request")
        .marshal()
}

/// UPF: handle an inbound N4 message, returning the response to send (if any).
pub fn handle_n4(data: &[u8], node_ip: Ipv4Addr, state: &mut UpfState) -> Option<Vec<u8>> {
    let msg = rs_pfcp::message::parse(data).ok()?;
    let seq = msg.sequence();
    match msg.msg_type() {
        MsgType::AssociationSetupRequest => Some(
            AssociationSetupResponseBuilder::new(seq)
                .cause_accepted()
                .node_id(node_ip)
                .recovery_time_stamp(SystemTime::now())
                .build()
                .marshal(),
        ),
        MsgType::HeartbeatRequest => Some(
            HeartbeatResponseBuilder::new(seq)
                .recovery_time_stamp(SystemTime::now())
                .build()
                .marshal(),
        ),
        MsgType::SessionEstablishmentRequest => {
            // The SMF's CP F-SEID identifies its end of the session.
            let cp_fseid = msg
                .ies(IeType::Fseid)
                .next()
                .and_then(|ie| Fseid::unmarshal(&ie.payload).ok())?;
            let (up_seid, teid) = state.establish();
            let created_pdr = CreatedPdr::new(PdrId::new(1), Fteid::ipv4(teid, node_ip)).to_ie();
            Some(
                SessionEstablishmentResponseBuilder::new(
                    cp_fseid.seid,
                    seq,
                    CauseValue::RequestAccepted,
                )
                .node_id(node_ip)
                .fseid(up_seid, node_ip) // UP F-SEID
                .created_pdr(created_pdr)
                .build()
                .ok()?
                .marshal(),
            )
        }
        // Session modification/deletion and others arrive in later slices.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_establishment_allocates_and_tracks() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        let req = session_establishment_request(0xCAFE, 1, node_ip);
        let resp = handle_n4(&req, node_ip, &mut state).expect("session response");

        assert_eq!(state.session_count(), 1, "UPF tracks the session");
        let parsed = rs_pfcp::message::parse(&resp).unwrap();
        assert_eq!(parsed.msg_type(), MsgType::SessionEstablishmentResponse);
        assert_eq!(parsed.ies(IeType::CreatedPdr).count(), 1, "Created PDR with allocated F-TEID");
        assert_eq!(parsed.ies(IeType::Fseid).count(), 1, "UP F-SEID returned");
    }

    /// Full N4 round-trip over real UDP: associate, heartbeat, establish a session.
    #[tokio::test]
    async fn n4_exchange_over_udp() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf.local_addr().unwrap();
        tokio::spawn(async move {
            let mut state = UpfState::new();
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = upf.recv_from(&mut buf).await.unwrap();
                if let Some(resp) = handle_n4(&buf[..n], upf_ip, &mut state) {
                    upf.send_to(&resp, peer).await.unwrap();
                }
            }
        });

        let smf = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        smf.connect(upf_addr).await.unwrap();
        let mut buf = [0u8; 2048];

        async fn round_trip(smf: &tokio::net::UdpSocket, buf: &mut [u8], req: Vec<u8>) -> MsgType {
            smf.send(&req).await.unwrap();
            let n = smf.recv(buf).await.unwrap();
            rs_pfcp::message::parse(&buf[..n]).unwrap().msg_type()
        }

        assert_eq!(
            round_trip(&smf, &mut buf, association_setup_request(upf_ip, 1)).await,
            MsgType::AssociationSetupResponse
        );
        assert_eq!(
            round_trip(&smf, &mut buf, heartbeat_request(2)).await,
            MsgType::HeartbeatResponse
        );
        assert_eq!(
            round_trip(&smf, &mut buf, session_establishment_request(0x1234, 3, upf_ip)).await,
            MsgType::SessionEstablishmentResponse
        );
    }
}
