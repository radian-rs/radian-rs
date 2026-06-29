//! PFCP — Packet Forwarding Control Protocol (TS 29.244), the N4 protocol between
//! SMF (control) and UPF (user plane). Binary TLV over UDP — not ASN.1.
//!
//! Wraps the [`rs_pfcp`] codec and adds SMF-side request builders plus a UPF-side
//! handler for the node-level **association** and **heartbeat**. PFCP session
//! establishment (PDRs/FARs/F-TEID) and the GTP-U datapath come in later slices.

use std::net::Ipv4Addr;
use std::time::SystemTime;

pub use rs_pfcp;
pub use rs_pfcp::message::MsgType;

use rs_pfcp::message::association_setup_request::AssociationSetupRequestBuilder;
use rs_pfcp::message::association_setup_response::AssociationSetupResponseBuilder;
use rs_pfcp::message::heartbeat_request::HeartbeatRequestBuilder;
use rs_pfcp::message::heartbeat_response::HeartbeatResponseBuilder;
use rs_pfcp::message::Message;

/// Default N4 PFCP UDP port (TS 29.244).
pub const N4_PORT: u16 = 8805;

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

/// UPF: handle an inbound N4 message, returning the response to send (if any).
pub fn handle_n4(data: &[u8], node_ip: Ipv4Addr) -> Option<Vec<u8>> {
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
        // Session establishment, modification, etc. arrive in a later slice.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full N4 round-trip over real UDP: an SMF associates with a UPF, then beats.
    #[tokio::test]
    async fn n4_association_and_heartbeat() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = upf.recv_from(&mut buf).await.unwrap();
                if let Some(resp) = handle_n4(&buf[..n], upf_ip) {
                    upf.send_to(&resp, peer).await.unwrap();
                }
            }
        });

        let smf = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        smf.connect(upf_addr).await.unwrap();
        let mut buf = [0u8; 2048];

        // Association Setup → Response.
        smf.send(&association_setup_request(Ipv4Addr::new(127, 0, 0, 1), 1)).await.unwrap();
        let n = smf.recv(&mut buf).await.unwrap();
        let resp = rs_pfcp::message::parse(&buf[..n]).unwrap();
        assert_eq!(resp.msg_type(), MsgType::AssociationSetupResponse);

        // Heartbeat → Response.
        smf.send(&heartbeat_request(2)).await.unwrap();
        let n = smf.recv(&mut buf).await.unwrap();
        let resp = rs_pfcp::message::parse(&buf[..n]).unwrap();
        assert_eq!(resp.msg_type(), MsgType::HeartbeatResponse);
    }
}
