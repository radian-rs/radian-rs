//! N6 — the UPF's interface to the **data network** (the DN, e.g. the internet),
//! and the forwarding plane that bridges it to N3 (GTP-U).
//!
//! This crate holds the two forwarding **decisions** the UPF makes, as pure functions
//! over the PFCP session table ([`pfcp::UpfState`]):
//!
//! - [`uplink`] — a G-PDU arrived on N3, was decapsulated, and its inner IP packet is
//!   headed *out* to the data network. We check the TEID is a known session and that the
//!   packet's source is the UE's assigned IP (a basic anti-spoofing guard), then forward.
//! - [`downlink`] — an IP packet arrived *from* the data network on N6. We route it by
//!   destination IP to the session that owns that UE address, and encapsulate it toward
//!   that session's gNB N3 tunnel.
//!
//! The concrete data-network device (a Linux **TUN** interface) lives in [`tun`]; it is
//! the privileged edge (needs `CAP_NET_ADMIN`) and is kept deliberately thin so the
//! routing logic here stays testable without any special privileges.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pfcp::UpfState;

pub mod tun;

/// Parse the source and destination addresses of a bare IPv4 packet (as carried on N3/N6,
/// with no L2 header). `None` if it is too short or not IPv4.
pub fn ipv4_addrs(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    // Smallest IPv4 header is 20 bytes; the version is the high nibble of byte 0.
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some((src, dst))
}

/// Parse the source and destination addresses of a bare IPv6 packet (the fixed 40-byte
/// header, no L2). `None` if too short or not IPv6 (design/131). Extension headers, if
/// any, follow the fixed header and don't affect the addresses.
pub fn ipv6_addrs(pkt: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
    Some((src, dst))
}

/// Whether IPv6 address `addr` falls within the /64 `prefix` (top 64 bits match).
fn in_prefix64(addr: Ipv6Addr, prefix: Ipv6Addr) -> bool {
    addr.octets()[..8] == prefix.octets()[..8]
}

/// What to do with an uplink packet decapsulated from an N3 G-PDU.
#[derive(Debug, PartialEq, Eq)]
pub enum Uplink<'a> {
    /// Forward this inner packet out to N6 (the data network) — this UPF is the anchor.
    ToN6(&'a [u8]),
    /// Re-encapsulate and forward on to another node (GTP-U to `peer` under `teid`) —
    /// this UPF is an intermediate node in a chain (design/134). It covers **both**
    /// directions: uplink on to the next UPF over N9, and downlink coming back from the
    /// anchor over N9 on to the gNB over N3. Mechanically identical, so one outcome.
    Forward { teid: u32, peer: Ipv4Addr, pkt: &'a [u8] },
    /// The G-PDU's TEID matches no established session — drop.
    UnknownTeid,
    /// The inner packet's source is not the UE's assigned address — likely spoofing;
    /// drop. For IPv6 `assigned` is the session's /64 prefix.
    Spoofed { claimed: IpAddr, assigned: IpAddr },
    /// The session's uplink AMBR is exceeded — policed (dropped).
    RateLimited,
    /// The UE sent an ICMPv6 **Router Solicitation** — the UPF answers it with a Router
    /// Advertisement (design/131 Phase C) rather than forwarding it to N6.
    RouterSolicitation,
}

/// Decide the fate of an uplink packet (`inner`) that arrived on N3 under `teid`,
/// at `now_nanos` (the UPF's monotonic clock, for AMBR policing).
///
/// Anti-spoofing is best-effort at L3: an IPv4 inner's source must equal the UE's
/// assigned IPv4; an IPv6 inner's source must fall in the UE's assigned /64 (the UE
/// forms its address there via SLAAC); anything else is forwarded as-is (the DN device
/// drops what it can't route). A packet that passes is metered against the uplink AMBR.
pub fn uplink<'a>(state: &mut UpfState, teid: u32, inner: &'a [u8], now_nanos: u64) -> Uplink<'a> {
    // On an intermediate UPF, a TEID matching its downlink N9 ingress is traffic coming
    // *back* from the anchor — forward it on to the gNB rather than treating it as
    // uplink (design/134). Checked first: the direction is decided by which ingress the
    // TEID belongs to, not by the packet.
    if let Some((gnb_teid, gnb_ip)) = state.downlink_via_n9_ingress(teid) {
        return Uplink::Forward { teid: gnb_teid, peer: gnb_ip, pkt: inner };
    }
    if !state.knows_teid(teid) {
        return Uplink::UnknownTeid;
    }
    // A Router Solicitation (from the UE's link-local, so it fails the /64 spoof check)
    // is answered with a Router Advertisement, not forwarded (design/131 Phase C).
    if state.ue_ipv6_for_teid(teid).is_some() && is_router_solicitation(inner) {
        return Uplink::RouterSolicitation;
    }
    if let Some((src, _dst)) = ipv4_addrs(inner) {
        if let Some(ue_ip) = state.ue_ip_for_teid(teid)
            && src != ue_ip
        {
            return Uplink::Spoofed { claimed: src.into(), assigned: ue_ip.into() };
        }
    } else if let Some((src, _dst)) = ipv6_addrs(inner)
        && let Some(prefix) = state.ue_ipv6_for_teid(teid)
        && !in_prefix64(src, prefix)
    {
        return Uplink::Spoofed { claimed: src.into(), assigned: prefix.into() };
    }
    if !state.admit_uplink(teid, now_nanos, inner) {
        return Uplink::RateLimited;
    }
    // An anchor sends it out to the data network; an intermediate UPF forwards it on to
    // the next UPF over N9 (design/134). On an **uplink classifier** the choice is made
    // per packet — a branch rule can send this one to a different anchor while the rest
    // of the session takes the default egress (design/134 Phase 2).
    match state.uplink_egress_for(teid, inner) {
        Some(pfcp::Egress::ToPeer { teid, addr }) => {
            Uplink::Forward { teid, peer: addr, pkt: inner }
        }
        _ => Uplink::ToN6(inner),
    }
}

/// What to do with a downlink packet that arrived from N6 (the data network).
#[derive(Debug, PartialEq, Eq)]
pub enum Downlink {
    /// Send this G-PDU toward the gNB at `gnb_ip` on N3.
    ToN3 { gnb_ip: Ipv4Addr, gpdu: Vec<u8> },
    /// The owning session is **CM-IDLE**: the packet was buffered and a Downlink
    /// Data Report raised (paging trigger) — nothing to send now.
    Buffered,
    /// No session owns the destination UE address, or its downlink isn't installed yet — drop.
    NoRoute,
    /// The packet is neither IPv4 nor IPv6 — drop.
    Unsupported,
    /// The session's downlink AMBR is exceeded — policed (dropped).
    RateLimited,
}

/// Decide the fate of a downlink IP packet (`pkt`) that arrived from N6 at
/// `now_nanos`: route it by destination to the owning session, meter it against
/// that session's downlink AMBR, and encapsulate it toward the session's gNB tunnel.
/// Handles IPv4 (by exact UE address) and IPv6 (by the session's /64, design/131).
pub fn downlink(state: &mut UpfState, pkt: &[u8], now_nanos: u64) -> Downlink {
    if let Some((_src, dst)) = ipv4_addrs(pkt) {
        let Some((gnb_teid, gnb_ip)) = state.route_downlink(dst) else {
            // No installed tunnel: a CM-IDLE (buffering) session holds the packet and
            // triggers paging; otherwise there's no route.
            return if state.buffer_downlink(dst, pkt) { Downlink::Buffered } else { Downlink::NoRoute };
        };
        if !state.admit_downlink(dst, now_nanos, pkt) {
            return Downlink::RateLimited;
        }
        Downlink::ToN3 { gnb_ip, gpdu: gtpu::encap(gnb_teid, pkt) }
    } else if let Some((_src, dst)) = ipv6_addrs(pkt) {
        // IPv6 CM-IDLE buffering/paging is a later design/131 phase — an idle v6
        // session simply has no route for now.
        let Some((gnb_teid, gnb_ip)) = state.route_downlink_v6(dst) else {
            return Downlink::NoRoute;
        };
        if !state.admit_downlink_v6(dst, now_nanos, pkt) {
            return Downlink::RateLimited;
        }
        Downlink::ToN3 { gnb_ip, gpdu: gtpu::encap(gnb_teid, pkt) }
    } else {
        Downlink::Unsupported
    }
}

// ── IPv6 Router Advertisement / SLAAC (design/131 Phase C, RFC 4861) ─────────────────

/// The UPF's link-local address acting as the on-link router (RFC 4861 §6).
const ROUTER_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
/// The IPv6 all-nodes multicast address — the destination of an unsolicited RA.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// The internet checksum (RFC 1071): one's-complement sum of 16-bit words.
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

/// The ICMPv6 checksum (RFC 4443 §2.3): over the IPv6 pseudo-header + the message.
fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + icmp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 58]); // zeros + next header (ICMPv6)
    buf.extend_from_slice(icmp);
    checksum(&buf)
}

/// Wrap an ICMPv6 message in a 40-byte IPv6 header from `src` to `dst`.
fn ipv6_icmp_packet(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8, icmp: &[u8]) -> Vec<u8> {
    let mut ip = vec![0x60, 0x00, 0x00, 0x00];
    ip.extend_from_slice(&(icmp.len() as u16).to_be_bytes()); // payload length
    ip.push(58); // next header: ICMPv6
    ip.push(hop_limit);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(icmp);
    ip
}

/// Build an ICMPv6 **Router Advertisement** (RFC 4861 §4.2) carrying `prefix`/`prefix_len`
/// as a Prefix Information option with the **A** (autonomous SLAAC) + **L** (on-link)
/// flags, so a UE forms its global address `prefix ‖ IID`. Sent from the router
/// link-local to `dst` (the all-nodes multicast for an unsolicited RA, or the
/// solicitor). M=O=0 (no DHCPv6); hop limit 255 (RFC 4861 requires it).
pub fn router_advertisement(prefix: Ipv6Addr, prefix_len: u8, dst: Ipv6Addr) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(48);
    icmp.extend_from_slice(&[134, 0, 0, 0]); // type=134 (RA), code=0, checksum placeholder
    icmp.push(64); // cur hop limit advertised to hosts
    icmp.push(0x00); // flags: M=0, O=0
    icmp.extend_from_slice(&1800u16.to_be_bytes()); // router lifetime (s)
    icmp.extend_from_slice(&0u32.to_be_bytes()); // reachable time
    icmp.extend_from_slice(&0u32.to_be_bytes()); // retransmit timer
    // Prefix Information option (type 3, length 4×8 = 32 bytes).
    icmp.extend_from_slice(&[3, 4, prefix_len, 0xC0]); // type, len, prefix len, flags L|A
    icmp.extend_from_slice(&86_400u32.to_be_bytes()); // valid lifetime (s)
    icmp.extend_from_slice(&14_400u32.to_be_bytes()); // preferred lifetime (s)
    icmp.extend_from_slice(&0u32.to_be_bytes()); // reserved
    icmp.extend_from_slice(&prefix.octets()); // the /64 prefix
    let c = icmpv6_checksum(ROUTER_LINK_LOCAL, dst, &icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    ipv6_icmp_packet(ROUTER_LINK_LOCAL, dst, 255, &icmp)
}

/// Whether a bare IP packet is an ICMPv6 **Router Solicitation** (type 133). Assumes
/// no extension headers (the UE's ND packets carry none).
pub fn is_router_solicitation(pkt: &[u8]) -> bool {
    pkt.len() >= 41 && pkt[0] >> 4 == 6 && pkt[6] == 58 && pkt[40] == 133
}

/// The Prefix Information `(prefix, prefix_len)` from an ICMPv6 **Router Advertisement**
/// (type 134) — a UE reads the /64 to run SLAAC. `None` if `pkt` is not an RA or carries
/// no Prefix Information option.
pub fn ra_prefix(pkt: &[u8]) -> Option<(Ipv6Addr, u8)> {
    if pkt.len() < 41 || pkt[0] >> 4 != 6 || pkt[6] != 58 || pkt[40] != 134 {
        return None;
    }
    // Options follow the 40-byte IPv6 header + the 16-byte RA header.
    let mut i = 40 + 16;
    while i + 8 <= pkt.len() {
        let opt_len = pkt[i + 1] as usize * 8; // ND option length is in units of 8 octets
        if opt_len == 0 {
            break;
        }
        if pkt[i] == 3 && i + 32 <= pkt.len() {
            let prefix_len = pkt[i + 2];
            let prefix = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[i + 16..i + 32]).ok()?);
            return Some((prefix, prefix_len));
        }
        i += opt_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPF_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const UE_IP: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);
    const GNB_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
    const GNB_TEID: u32 = 0x5678;

    /// A minimal well-formed IPv4 packet from `src` to `dst` (20-byte header + payload).
    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        pkt.extend_from_slice(payload);
        pkt
    }

    /// A UPF session table with one established + downlink-installed session for `UE_IP`,
    /// built through the real PFCP path so `n3_teid` is the UPF-allocated value (1).
    fn established_upf() -> (UpfState, u32) {
        established_upf_ambr(None)
    }

    /// Like [`established_upf`], with an optional session AMBR provisioned via a QER.
    fn established_upf_ambr(ambr: Option<pfcp::SessionAmbr>) -> (UpfState, u32) {
        established_upf_flows(ambr, &[])
    }

    /// Like [`established_upf_ambr`], also provisioning per-flow (GBR) QERs.
    fn established_upf_flows(
        ambr: Option<pfcp::SessionAmbr>,
        flows: &[pfcp::FlowQer],
    ) -> (UpfState, u32) {
        let mut state = UpfState::new();
        pfcp::handle_n4(
            &pfcp::session_establishment_request(0xCAFE, 1, UPF_IP, UE_IP, "internet", ambr, flows, None),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("establish");
        let n3_teid = 1; // first UPF allocation
        pfcp::handle_n4(
            &pfcp::session_modification_request(1, 2, 2, GNB_TEID, GNB_IP, "internet", false),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("modify");
        (state, n3_teid)
    }

    #[test]
    fn parses_ipv4_addrs_and_rejects_non_ipv4() {
        let pkt = ipv4_packet(UE_IP, GNB_IP, b"hi");
        assert_eq!(ipv4_addrs(&pkt), Some((UE_IP, GNB_IP)));
        assert_eq!(ipv4_addrs(&[0u8; 8]), None, "too short");
        assert_eq!(ipv4_addrs(&[0x60; 20]), None, "IPv6, not IPv4");
    }

    #[test]
    fn downlink_routes_by_ue_ip_and_encaps_to_gnb() {
        let (mut state, _) = established_upf();
        let inner = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), UE_IP, b"downlink");
        match downlink(&mut state, &inner, 0) {
            Downlink::ToN3 { gnb_ip, gpdu } => {
                assert_eq!(gnb_ip, GNB_IP, "sent toward the session's gNB");
                assert_eq!(gtpu::decap(&gpdu), Some((GNB_TEID, &inner[..])), "encapped to gNB TEID");
            }
            other => panic!("expected ToN3, got {other:?}"),
        }
    }

    #[test]
    fn downlink_drops_unknown_dst_and_non_ipv4() {
        let (mut state, _) = established_upf();
        let stranger = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 45, 0, 3), b"x");
        assert_eq!(downlink(&mut state, &stranger, 0), Downlink::NoRoute, "no session owns that UE IP");
        assert_eq!(downlink(&mut state, &[0u8; 20], 0), Downlink::Unsupported, "non-IP dropped");
    }

    #[test]
    fn uplink_forwards_matching_source_to_n6() {
        let (mut state, teid) = established_upf();
        let inner = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), b"uplink");
        assert_eq!(uplink(&mut state, teid, &inner, 0), Uplink::ToN6(&inner[..]));
    }

    /// On an **intermediate UPF** the uplink is re-encapsulated toward the next UPF over
    /// N9 rather than handed to N6 (design/134) — the chain's forwarding hop.
    #[test]
    fn uplink_on_an_intermediate_upf_forwards_over_n9() {
        let peer = Ipv4Addr::new(127, 0, 0, 2);
        let mut state = UpfState::new();
        pfcp::handle_n4(
            &pfcp::session_establishment_request_via_peer(
                0xCAFE, 1, UPF_IP, UE_IP, "internet", 0x9001, peer, &[],
            ),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("establish intermediate UPF");

        let pkt = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), b"uplink");
        assert_eq!(
            uplink(&mut state, 1, &pkt, 0),
            Uplink::Forward { teid: 0x9001, peer, pkt: &pkt[..] },
            "forwarded on to the next UPF, not out to N6"
        );
        // Anti-spoofing still applies on the chain's first hop.
        let spoofed = ipv4_packet(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(8, 8, 8, 8), b"x");
        assert!(matches!(uplink(&mut state, 1, &spoofed, 0), Uplink::Spoofed { .. }));
    }

    /// The **uplink classifier** (design/134 Phase 2): one session, two anchors. Traffic
    /// for the branch prefix is steered to a second PSA while everything else keeps
    /// taking the session's default N9 egress — the egress is a per-packet decision.
    #[test]
    fn uplink_classifier_steers_matching_destinations_to_a_second_anchor() {
        let (psa1, psa2) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3));
        let edge = pfcp::FlowFilter::to_prefix(pfcp::IpPrefix::new(Ipv4Addr::new(10, 99, 0, 0), 16));
        let mut state = UpfState::new();
        pfcp::handle_n4(
            &pfcp::session_establishment_request_via_peer(
                0xCAFE,
                1,
                UPF_IP,
                UE_IP,
                "internet",
                0x9001,
                psa1,
                &[(edge, pfcp::Egress::ToPeer { teid: 0x9002, addr: psa2 })],
            ),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("establish uplink classifier");

        let branched = ipv4_packet(UE_IP, Ipv4Addr::new(10, 99, 1, 1), b"edge");
        assert_eq!(
            uplink(&mut state, 1, &branched, 0),
            Uplink::Forward { teid: 0x9002, peer: psa2, pkt: &branched[..] },
            "a destination in the branch prefix goes to the second anchor"
        );
        let default = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), b"internet");
        assert_eq!(
            uplink(&mut state, 1, &default, 0),
            Uplink::Forward { teid: 0x9001, peer: psa1, pkt: &default[..] },
            "everything else still takes the session's default egress"
        );
        // The classifier does not weaken the edge checks it sits behind.
        let spoofed = ipv4_packet(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(10, 99, 1, 1), b"x");
        assert!(
            matches!(uplink(&mut state, 1, &spoofed, 0), Uplink::Spoofed { .. }),
            "a spoofed source is dropped even when it matches a branch"
        );
    }

    /// A ULCL can also **break out locally**: the branch's egress is this node's own N6
    /// rather than another UPF, so matched traffic never enters the tunnel to the anchor.
    #[test]
    fn uplink_classifier_can_break_out_to_local_n6() {
        let psa = Ipv4Addr::new(127, 0, 0, 2);
        let edge = pfcp::FlowFilter::to_prefix(pfcp::IpPrefix::new(Ipv4Addr::new(10, 99, 0, 0), 16));
        let mut state = UpfState::new();
        pfcp::handle_n4(
            &pfcp::session_establishment_request_via_peer(
                0xCAFE,
                1,
                UPF_IP,
                UE_IP,
                "internet",
                0x9001,
                psa,
                &[(edge, pfcp::Egress::ToN6)],
            ),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("establish uplink classifier");

        let local = ipv4_packet(UE_IP, Ipv4Addr::new(10, 99, 1, 1), b"local");
        assert_eq!(
            uplink(&mut state, 1, &local, 0),
            Uplink::ToN6(&local[..]),
            "the branch breaks out to this node's data network"
        );
        let remote = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), b"remote");
        assert_eq!(
            uplink(&mut state, 1, &remote, 0),
            Uplink::Forward { teid: 0x9001, peer: psa, pkt: &remote[..] },
            "the rest still tunnels to the anchor"
        );
    }

    /// The chain's **return path** (design/134): a G-PDU arriving on the intermediate
    /// UPF's downlink N9 ingress — traffic coming back from the anchor — is forwarded on
    /// to the gNB rather than treated as uplink. Direction is decided by *which ingress*
    /// the TEID belongs to.
    #[test]
    fn downlink_from_the_anchor_is_forwarded_on_to_the_gnb() {
        let peer = Ipv4Addr::new(127, 0, 0, 2);
        let mut state = UpfState::new();
        let resp = pfcp::handle_n4(
            &pfcp::session_establishment_request_via_peer(
                0xCAFE, 1, UPF_IP, UE_IP, "internet", 0x9001, peer, &[],
            ),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("establish intermediate UPF");
        let est = pfcp::parse_session_establishment_response(&resp).expect("parse response");
        let (dl_teid, _) =
            est.dl_ingress.expect("the intermediate UPF allocated a downlink N9 ingress");
        assert_ne!(dl_teid, est.n3_teid, "the two ingresses are distinct TEIDs");

        // The SMF points its downlink FAR at the gNB, exactly as for an anchor.
        pfcp::handle_n4(
            &pfcp::session_modification_request(
                est.up_seid, 2, 2, GNB_TEID, GNB_IP, "internet", false,
            ),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("modify");

        // Downlink arriving from the anchor goes on to the gNB.
        let down = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), UE_IP, b"downlink");
        assert_eq!(
            uplink(&mut state, dl_teid, &down, 0),
            Uplink::Forward { teid: GNB_TEID, peer: GNB_IP, pkt: &down[..] },
            "the chain's return path reaches the gNB"
        );
        // ...and the uplink ingress still goes the other way, on to the anchor.
        let up = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), b"uplink");
        assert_eq!(
            uplink(&mut state, est.n3_teid, &up, 0),
            Uplink::Forward { teid: 0x9001, peer, pkt: &up[..] },
            "uplink still goes on to the anchor"
        );
    }

    #[test]
    fn uplink_drops_unknown_teid_and_spoofed_source() {
        let (mut state, teid) = established_upf();
        let good = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), b"x");
        assert_eq!(uplink(&mut state, 999, &good, 0), Uplink::UnknownTeid, "no session owns TEID 999");

        let spoofed = ipv4_packet(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(8, 8, 8, 8), b"x");
        assert_eq!(
            uplink(&mut state, teid, &spoofed, 0),
            Uplink::Spoofed { claimed: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), assigned: IpAddr::V4(UE_IP) },
            "source that isn't the UE's assigned IP is rejected"
        );
    }

    // ── IPv6 datapath (design/131 Phase B) ──────────────────────────────────────────

    const UE_V6_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xa, 1, 0, 0, 0, 0); // /64
    const UE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xa, 1, 0, 0, 0, 1); // prefix::iid
    const GW_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

    /// A minimal well-formed IPv6 packet (40-byte fixed header + payload).
    fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // version 6
        pkt[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        pkt[6] = 59; // next header: no next header
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&src.octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt.extend_from_slice(payload);
        pkt
    }

    /// A UPF with one established + downlink-installed **IPv6** session (a /64 prefix).
    fn established_upf_v6() -> (UpfState, u32) {
        let mut state = UpfState::new();
        let ue = pfcp::UeAddr { v4: None, v6: Some(UE_V6_PREFIX) };
        pfcp::handle_n4(
            &pfcp::session_establishment_request(0xCAFE, 1, UPF_IP, ue, "internet", None, &[], None),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("establish");
        pfcp::handle_n4(
            &pfcp::session_modification_request(1, 2, 2, GNB_TEID, GNB_IP, "internet", false),
            UPF_IP,
            &mut state,
            0,
        )
        .expect("modify");
        (state, 1)
    }

    #[test]
    fn parses_ipv6_addrs() {
        let pkt = ipv6_packet(UE_V6, GW_V6, b"hi");
        assert_eq!(ipv6_addrs(&pkt), Some((UE_V6, GW_V6)));
        assert_eq!(ipv6_addrs(&[0x60; 20]), None, "too short for IPv6");
        assert_eq!(ipv6_addrs(&[0x45; 40]), None, "IPv4, not IPv6");
    }

    #[test]
    fn ipv6_uplink_forwards_in_prefix_source_and_rejects_spoof() {
        let (mut state, teid) = established_upf_v6();
        // Source in the UE's /64 → forwarded.
        let good = ipv6_packet(UE_V6, GW_V6, b"uplink");
        assert_eq!(uplink(&mut state, teid, &good, 0), Uplink::ToN6(&good[..]));
        // Source outside the /64 → spoofing.
        let bad_src = Ipv6Addr::new(0x2001, 0xdb8, 0xb, 1, 0, 0, 0, 1);
        let spoofed = ipv6_packet(bad_src, GW_V6, b"x");
        assert_eq!(
            uplink(&mut state, teid, &spoofed, 0),
            Uplink::Spoofed { claimed: IpAddr::V6(bad_src), assigned: IpAddr::V6(UE_V6_PREFIX) },
            "an IPv6 source outside the assigned /64 is rejected"
        );
    }

    #[test]
    fn ipv6_downlink_routes_by_prefix_and_encaps() {
        let (mut state, _) = established_upf_v6();
        // Any destination in the /64 routes to the session's gNB.
        let inner = ipv6_packet(GW_V6, UE_V6, b"downlink");
        match downlink(&mut state, &inner, 0) {
            Downlink::ToN3 { gnb_ip, gpdu } => {
                assert_eq!(gnb_ip, GNB_IP);
                assert_eq!(gtpu::decap(&gpdu), Some((GNB_TEID, &inner[..])), "encapped to the gNB TEID");
            }
            other => panic!("expected ToN3, got {other:?}"),
        }
        // A destination outside any session's /64 is unrouted.
        let stranger = ipv6_packet(GW_V6, Ipv6Addr::new(0x2001, 0xdb8, 0xff, 1, 0, 0, 0, 1), b"x");
        assert_eq!(downlink(&mut state, &stranger, 0), Downlink::NoRoute);
    }

    /// A minimal ICMPv6 Router Solicitation (type 133) from a UE link-local.
    fn router_solicitation() -> Vec<u8> {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1234);
        let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2); // all-routers
        let mut icmp = vec![133u8, 0, 0, 0, 0, 0, 0, 0]; // type, code, checksum, reserved(4)
        let c = icmpv6_checksum(src, dst, &icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        ipv6_icmp_packet(src, dst, 255, &icmp)
    }

    #[test]
    fn router_advertisement_roundtrips_and_checksum_valid() {
        let ra = router_advertisement(UE_V6_PREFIX, 64, ALL_NODES);
        assert_eq!(ra[0] >> 4, 6, "IPv6");
        assert_eq!(ra[6], 58, "ICMPv6");
        assert_eq!(ra[40], 134, "Router Advertisement");
        assert_eq!(ra_prefix(&ra), Some((UE_V6_PREFIX, 64)), "the Prefix Information round-trips");
        // The A + L flags are set (autonomous SLAAC + on-link) at the option's 4th byte.
        assert_eq!(ra[40 + 16 + 3], 0xC0, "prefix flags: L|A");
        assert_eq!(icmpv6_checksum(ROUTER_LINK_LOCAL, ALL_NODES, &ra[40..]), 0, "ICMPv6 checksum valid");
    }

    #[test]
    fn detects_router_solicitation() {
        let rs = router_solicitation();
        assert!(is_router_solicitation(&rs));
        let ra = router_advertisement(UE_V6_PREFIX, 64, ALL_NODES);
        assert!(!is_router_solicitation(&ra), "an RA is not an RS");
        assert_eq!(ra_prefix(&rs), None, "an RS carries no prefix");
    }

    #[test]
    fn uplink_router_solicitation_is_answered_not_forwarded() {
        let (mut state, teid) = established_upf_v6();
        assert_eq!(
            uplink(&mut state, teid, &router_solicitation(), 0),
            Uplink::RouterSolicitation,
            "a Router Solicitation on a v6 session is answered with an RA"
        );
    }

    /// A session AMBR provisioned via QER polices both directions: a burst is
    /// admitted, the next packet over the bucket is dropped, and tokens refill
    /// with elapsed time.
    #[test]
    fn session_ambr_polices_uplink_and_refills() {
        // 80_000 bps uplink → an 80_000-bit (10_000-byte) burst, then throttle.
        let ambr = pfcp::SessionAmbr { uplink_bps: 80_000, downlink_bps: 80_000 };
        let (mut state, teid) = established_upf_ambr(Some(ambr));

        // A 1000-byte (8_000-bit) UE-sourced uplink packet.
        let pkt = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), &[0u8; 980]);
        assert_eq!(pkt.len(), 1000);

        // At t=0 the bucket holds 80_000 bits = ten 1000-byte packets.
        for i in 0..10 {
            assert_eq!(uplink(&mut state, teid, &pkt, 0), Uplink::ToN6(&pkt[..]), "packet {i} within burst");
        }
        // The eleventh (still t=0) exceeds the bucket — policed.
        assert_eq!(uplink(&mut state, teid, &pkt, 0), Uplink::RateLimited, "burst exhausted");

        // After 100 ms, 8_000 bits refill — exactly one more packet.
        assert_eq!(
            uplink(&mut state, teid, &pkt, 100_000_000),
            Uplink::ToN6(&pkt[..]),
            "one packet's worth of tokens refilled"
        );
        assert_eq!(uplink(&mut state, teid, &pkt, 100_000_000), Uplink::RateLimited, "and no more");
    }

    /// Downlink is policed by the same session AMBR.
    #[test]
    fn session_ambr_polices_downlink() {
        let ambr = pfcp::SessionAmbr { uplink_bps: 80_000, downlink_bps: 80_000 };
        let (mut state, _) = established_upf_ambr(Some(ambr));
        let pkt = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), UE_IP, &[0u8; 980]); // 1000 bytes to the UE
        for _ in 0..10 {
            assert!(matches!(downlink(&mut state, &pkt, 0), Downlink::ToN3 { .. }));
        }
        assert_eq!(downlink(&mut state, &pkt, 0), Downlink::RateLimited, "downlink burst exhausted");
    }

    /// A UDP packet from `src`/`sport` to `dst`/`dport`, padded to `len` bytes.
    fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, len: usize) -> Vec<u8> {
        let mut p = ipv4_packet(src, dst, &vec![0u8; len.saturating_sub(20)]);
        p[9] = 17; // UDP
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    /// A per-flow GBR QER polices matched traffic through the datapath, independently
    /// of the (much larger) session AMBR that carries everything else.
    #[test]
    fn per_flow_gbr_policed_through_datapath() {
        let ambr = pfcp::SessionAmbr { uplink_bps: 1_000_000_000, downlink_bps: 1_000_000_000 };
        let flow = pfcp::FlowQer {
            qfi: 2,
            filter: pfcp::FlowFilter::transport(17, 5000, 5010),
            mfbr_dl_bps: 80_000,
            mfbr_ul_bps: 80_000,
        };
        let (mut state, teid) = established_upf_flows(Some(ambr), &[flow]);

        // UE→DN UDP to :5005 (matches the GBR flow): 10×1000-byte burst then policed.
        let matched = udp_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), 40000, 5005, 1000);
        for _ in 0..10 {
            assert!(matches!(uplink(&mut state, teid, &matched, 0), Uplink::ToN6(_)));
        }
        assert_eq!(uplink(&mut state, teid, &matched, 0), Uplink::RateLimited, "GBR MFBR exhausted");

        // Non-matching UDP (:9999) rides the big session AMBR — still forwarded.
        let other = udp_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), 40000, 9999, 1000);
        assert!(
            matches!(uplink(&mut state, teid, &other, 0), Uplink::ToN6(_)),
            "non-GBR traffic uses the session AMBR, unaffected by the exhausted per-flow bucket"
        );
    }
}
