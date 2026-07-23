//! The test's SMF + gNB roles: drive a live UPF's N4 (PFCP) and N3 (GTP-U) so a crafted
//! ICMP echo traverses the real datapath and comes back.
//!
//! Flow: play the **SMF** to establish + modify a PFCP session (UPF allocates the uplink N3
//! F-TEID; we install a downlink gNB F-TEID pointing back at ourselves), then play the **gNB**
//! — GTP-U-encap an ICMP echo to the UPF, which decaps it to its N6 TUN. The UPF's namespace
//! kernel answers the ping (the echo targets the TUN's own gateway address), the UPF routes
//! the reply back by UE IP and GTP-U-encaps it to our gNB F-TEID. Receiving that reply proves
//! the full N3→N6→N3 round trip.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Internet checksum (RFC 1071): one's-complement sum of 16-bit words.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 ICMP **echo request** from `src` to `dst`, with both checksums filled in.
pub fn icmp_echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut icmp = vec![8u8, 0, 0, 0]; // type=echo request, code=0, checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let total = 20 + icmp.len();
    let mut ip = vec![0x45u8, 0x00];
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, 1, 0, 0]); // id, DF+frag, TTL, proto=ICMP, cksum ph
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// Whether `pkt` is an IPv4 ICMP **echo reply** from `from` to `to`.
pub fn is_icmp_echo_reply(pkt: &[u8], from: Ipv4Addr, to: Ipv4Addr) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return false; // too short / not IPv4 / not ICMP
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    // ICMP type sits at the start of the payload; 0 = echo reply.
    matches!(pkt.get(ihl), Some(0)) && src == from && dst == to
}

/// The ICMPv6 checksum (RFC 4443 §2.3): the internet checksum over the IPv6
/// pseudo-header (src, dst, upper-layer length, next header 58) plus the ICMPv6 message.
fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + icmp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&(icmp.len() as u32).to_be_bytes()); // upper-layer packet length
    buf.extend_from_slice(&[0, 0, 0, 58]); // 3 zero bytes + next header (ICMPv6)
    buf.extend_from_slice(icmp);
    checksum(&buf)
}

/// Build an IPv6 ICMPv6 **echo request** (type 128) from `src` to `dst`, with the
/// pseudo-header checksum filled in (design/131).
pub fn icmpv6_echo_request(src: Ipv6Addr, dst: Ipv6Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut icmp = vec![128u8, 0, 0, 0]; // type=echo request, code=0, checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = icmpv6_checksum(src, dst, &icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    // IPv6 header (40 bytes): version 6, payload length, next header 58 (ICMPv6), hop limit.
    let mut ip = vec![0x60, 0x00, 0x00, 0x00];
    ip.extend_from_slice(&(icmp.len() as u16).to_be_bytes()); // payload length
    ip.push(58); // next header: ICMPv6
    ip.push(64); // hop limit
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(&icmp);
    ip
}

/// Whether `pkt` is an IPv6 ICMPv6 **echo reply** (type 129) from `from` to `to`.
pub fn is_icmpv6_echo_reply(pkt: &[u8], from: Ipv6Addr, to: Ipv6Addr) -> bool {
    if pkt.len() < 41 || pkt[0] >> 4 != 6 || pkt[6] != 58 {
        return false; // too short / not IPv6 / not ICMPv6 (assumes no extension headers)
    }
    let Ok(src) = <[u8; 16]>::try_from(&pkt[8..24]) else { return false };
    let Ok(dst) = <[u8; 16]>::try_from(&pkt[24..40]) else { return false };
    pkt[40] == 129 && Ipv6Addr::from(src) == from && Ipv6Addr::from(dst) == to
}

/// Send one PFCP request and await its response (3s).
async fn transact(sock: &UdpSocket, req: &[u8]) -> Result<Vec<u8>> {
    sock.send(req).await.context("PFCP send")?;
    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .context("PFCP response timeout")?
        .context("PFCP recv")?;
    buf.truncate(n);
    Ok(buf)
}

/// Play the SMF: associate, establish a session for `ue_ip`, and modify it to install the
/// downlink gNB target `(gnb_teid, gnb_ip)`. Returns the UPF-allocated **uplink N3 F-TEID**.
pub async fn establish_session(
    upf_n4: SocketAddrV4,
    smf_ip: Ipv4Addr,
    ue_ip: Ipv4Addr,
    gnb_teid: u32,
    gnb_ip: Ipv4Addr,
) -> Result<u32> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind SMF socket")?;
    sock.connect(upf_n4).await.context("connect UPF N4")?;

    let assoc = transact(&sock, &pfcp::association_setup_request(smf_ip, 1)).await?;
    anyhow::ensure!(pfcp::response_accepted(&assoc), "UPF rejected PFCP association");

    let est_resp =
        transact(&sock, &pfcp::session_establishment_request(0xCAFE, 2, smf_ip, ue_ip, "internet", None, &[], None)).await?;
    let est = pfcp::parse_session_establishment_response(&est_resp)
        .context("parse session establishment response")?;

    let mod_resp =
        transact(&sock, &pfcp::session_modification_request(est.up_seid, 3, 2, gnb_teid, gnb_ip, "internet", false)).await?;
    anyhow::ensure!(pfcp::response_accepted(&mod_resp), "UPF rejected session modification");

    Ok(est.n3_teid)
}

/// Play the gNB: GTP-U-encap an ICMP echo (from the UE IP to the DN gateway) on the uplink
/// TEID and send it to the UPF's N3, then wait for the downlink G-PDU carrying the reply.
/// Retries a few times. Returns `true` if the echo reply came back through the datapath.
pub async fn ping_through_datapath(
    gnb_bind: SocketAddrV4, // our N3 endpoint (host veth ip:2152) — also the installed gNB F-TEID addr
    upf_n3: SocketAddrV4,   // the UPF's N3 endpoint
    uplink_teid: u32,       // the UPF-allocated uplink F-TEID (encap target)
    gnb_teid: u32,          // the downlink F-TEID we installed (expected on the reply)
    ue_ip: Ipv4Addr,
    gw_ip: Ipv4Addr,
) -> Result<bool> {
    let gnb = UdpSocket::bind(gnb_bind).await.context("bind gNB N3 socket")?;
    let mut buf = vec![0u8; 2048];

    for seq in 1..=3u16 {
        let echo = icmp_echo_request(ue_ip, gw_ip, 0x1234, seq, b"radian-datapath");
        gnb.send_to(&gtpu::encap(uplink_teid, &echo), upf_n3).await.context("send uplink G-PDU")?;

        // Drain replies for up to 1s; a matching echo reply means the round trip closed.
        let until = tokio::time::Instant::now() + Duration::from_secs(1);
        while let Ok(Ok((n, _))) =
            timeout(until.saturating_duration_since(tokio::time::Instant::now()), gnb.recv_from(&mut buf)).await
        {
            if let Some((teid, inner)) = gtpu::decap(&buf[..n]) {
                if teid == gnb_teid && is_icmp_echo_reply(inner, gw_ip, ue_ip) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// The IPv6 analog of [`ping_through_datapath`] (design/131 Phase B): GTP-U-encap an
/// ICMPv6 echo (UE's v6 address → the DN gateway) on the uplink TEID, and expect the
/// reply back on our DL F-TEID — the full N3 → N6 → N3 round trip over IPv6.
pub async fn ping_through_datapath_v6(
    gnb_bind: SocketAddrV4,
    upf_n3: SocketAddrV4,
    uplink_teid: u32,
    gnb_teid: u32,
    ue_ip: Ipv6Addr,
    gw_ip: Ipv6Addr,
) -> Result<bool> {
    let gnb = UdpSocket::bind(gnb_bind).await.context("bind gNB N3 socket")?;
    let mut buf = vec![0u8; 2048];

    for seq in 1..=3u16 {
        let echo = icmpv6_echo_request(ue_ip, gw_ip, 0x1234, seq, b"radian-datapath-v6");
        gnb.send_to(&gtpu::encap(uplink_teid, &echo), upf_n3).await.context("send uplink G-PDU")?;

        let until = tokio::time::Instant::now() + Duration::from_secs(1);
        while let Ok(Ok((n, _))) =
            timeout(until.saturating_duration_since(tokio::time::Instant::now()), gnb.recv_from(&mut buf)).await
        {
            if let Some((teid, inner)) = gtpu::decap(&buf[..n]) {
                if teid == gnb_teid && is_icmpv6_echo_reply(inner, gw_ip, ue_ip) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Bind a gNB N3 (GTP-U) socket at `addr` and keep it — used to receive a downlink
/// G-PDU the UPF flushes after a CM-IDLE resume, which requires the socket to already
/// be listening when the flush arrives.
pub async fn bind_gnb_n3(addr: SocketAddrV4) -> Result<UdpSocket> {
    UdpSocket::bind(addr).await.context("bind gNB N3 socket")
}

/// Receive a downlink G-PDU on an already-bound gNB N3 socket, returning the inner
/// IP packet when its TEID matches `expected_teid`. `None` if none arrives within
/// `secs`.
pub async fn recv_downlink_gpdu(
    sock: &UdpSocket,
    expected_teid: u32,
    secs: u64,
) -> Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while let Ok(Ok((n, _))) =
        timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), sock.recv_from(&mut buf)).await
    {
        if let Some((_, inner)) = gtpu::decap(&buf[..n]).filter(|(teid, _)| *teid == expected_teid) {
            return Ok(Some(inner.to_vec()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_echo_request_has_valid_checksums() {
        let src = Ipv4Addr::new(10, 45, 0, 2);
        let dst = Ipv4Addr::new(10, 45, 0, 1);
        let pkt = icmp_echo_request(src, dst, 0x1234, 1, b"hi");
        // Full-header checksums verify to zero when re-summed.
        assert_eq!(checksum(&pkt[..20]), 0, "IPv4 header checksum valid");
        assert_eq!(checksum(&pkt[20..]), 0, "ICMP checksum valid");
        assert_eq!(pkt[20], 8, "ICMP echo request");
    }

    #[test]
    fn recognises_echo_reply_by_addresses_and_type() {
        let ue = Ipv4Addr::new(10, 45, 0, 2);
        let gw = Ipv4Addr::new(10, 45, 0, 1);
        // A reply is IPv4/ICMP, from gw to ue, type 0.
        let mut reply = icmp_echo_request(gw, ue, 1, 1, b"x");
        reply[20] = 0; // echo reply
        assert!(is_icmp_echo_reply(&reply, gw, ue));
        assert!(!is_icmp_echo_reply(&reply, ue, gw), "wrong direction");
        let request = icmp_echo_request(ue, gw, 1, 1, b"x"); // type 8
        assert!(!is_icmp_echo_reply(&request, ue, gw), "echo request is not a reply");
    }

    #[test]
    fn icmpv6_echo_request_has_valid_checksum() {
        let src: Ipv6Addr = "2001:db8:0:1::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let pkt = icmpv6_echo_request(src, dst, 0x1234, 1, b"hi");
        assert_eq!(pkt[0] >> 4, 6, "IPv6");
        assert_eq!(pkt[6], 58, "next header = ICMPv6");
        assert_eq!(pkt[40], 128, "ICMPv6 echo request");
        // Re-summing the pseudo-header + ICMPv6 message (checksum filled) yields 0.
        assert_eq!(icmpv6_checksum(src, dst, &pkt[40..]), 0, "ICMPv6 checksum valid");
    }

    #[test]
    fn recognises_icmpv6_echo_reply_by_addresses_and_type() {
        let ue: Ipv6Addr = "2001:db8:0:1::1".parse().unwrap();
        let gw: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut reply = icmpv6_echo_request(gw, ue, 1, 1, b"x");
        reply[40] = 129; // echo reply (type not checked against checksum here)
        assert!(is_icmpv6_echo_reply(&reply, gw, ue));
        assert!(!is_icmpv6_echo_reply(&reply, ue, gw), "wrong direction");
        let request = icmpv6_echo_request(ue, gw, 1, 1, b"x"); // type 128
        assert!(!is_icmpv6_echo_reply(&request, ue, gw), "echo request is not a reply");
    }
}
