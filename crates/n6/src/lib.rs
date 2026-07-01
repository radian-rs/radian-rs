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

use std::net::Ipv4Addr;

use pfcp::UpfState;

pub mod tun;

/// Parse the source and destination addresses of a bare IPv4 packet (as carried on N3/N6,
/// with no L2 header). `None` if it is too short or not IPv4 — the only family these
/// single-stack PDU sessions carry.
pub fn ipv4_addrs(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    // Smallest IPv4 header is 20 bytes; the version is the high nibble of byte 0.
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some((src, dst))
}

/// What to do with an uplink packet decapsulated from an N3 G-PDU.
#[derive(Debug, PartialEq, Eq)]
pub enum Uplink<'a> {
    /// Forward this inner packet out to N6 (the data network).
    ToN6(&'a [u8]),
    /// The G-PDU's TEID matches no established session — drop.
    UnknownTeid,
    /// The inner packet's source is not the UE's assigned IP — likely spoofing; drop.
    Spoofed { claimed: Ipv4Addr, assigned: Ipv4Addr },
}

/// Decide the fate of an uplink packet (`inner`) that arrived on N3 under `teid`.
///
/// Anti-spoofing is best-effort at L3: if the inner packet parses as IPv4, its source
/// must equal the UE's assigned address; a non-IPv4 inner is forwarded as-is (an IPv4
/// PDU session shouldn't carry one, and the DN device drops what it can't route).
pub fn uplink<'a>(state: &UpfState, teid: u32, inner: &'a [u8]) -> Uplink<'a> {
    let Some(ue_ip) = state.ue_ip_for_teid(teid) else {
        return Uplink::UnknownTeid;
    };
    if let Some((src, _dst)) = ipv4_addrs(inner)
        && src != ue_ip
    {
        return Uplink::Spoofed { claimed: src, assigned: ue_ip };
    }
    Uplink::ToN6(inner)
}

/// What to do with a downlink packet that arrived from N6 (the data network).
#[derive(Debug, PartialEq, Eq)]
pub enum Downlink {
    /// Send this G-PDU toward the gNB at `gnb_ip` on N3.
    ToN3 { gnb_ip: Ipv4Addr, gpdu: Vec<u8> },
    /// No session owns the destination UE IP, or its downlink isn't installed yet — drop.
    NoRoute,
    /// The packet is not IPv4 (only IPv4 PDU sessions are supported) — drop.
    NotIpv4,
}

/// Decide the fate of a downlink IP packet (`pkt`) that arrived from N6: route it by
/// destination to the owning session and encapsulate it toward that session's gNB tunnel.
pub fn downlink(state: &UpfState, pkt: &[u8]) -> Downlink {
    let Some((_src, dst)) = ipv4_addrs(pkt) else {
        return Downlink::NotIpv4;
    };
    match state.route_downlink(dst) {
        Some((gnb_teid, gnb_ip)) => Downlink::ToN3 { gnb_ip, gpdu: gtpu::encap(gnb_teid, pkt) },
        None => Downlink::NoRoute,
    }
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
        let mut state = UpfState::new();
        pfcp::handle_n4(
            &pfcp::session_establishment_request(0xCAFE, 1, UPF_IP, UE_IP),
            UPF_IP,
            &mut state,
        )
        .expect("establish");
        let n3_teid = 1; // first UPF allocation
        pfcp::handle_n4(
            &pfcp::session_modification_request(1, 2, 2, GNB_TEID, GNB_IP),
            UPF_IP,
            &mut state,
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
        let (state, _) = established_upf();
        let inner = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), UE_IP, b"downlink");
        match downlink(&state, &inner) {
            Downlink::ToN3 { gnb_ip, gpdu } => {
                assert_eq!(gnb_ip, GNB_IP, "sent toward the session's gNB");
                assert_eq!(gtpu::decap(&gpdu), Some((GNB_TEID, &inner[..])), "encapped to gNB TEID");
            }
            other => panic!("expected ToN3, got {other:?}"),
        }
    }

    #[test]
    fn downlink_drops_unknown_dst_and_non_ipv4() {
        let (state, _) = established_upf();
        let stranger = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 45, 0, 3), b"x");
        assert_eq!(downlink(&state, &stranger), Downlink::NoRoute, "no session owns that UE IP");
        assert_eq!(downlink(&state, &[0x60; 20]), Downlink::NotIpv4, "IPv6 dropped");
    }

    #[test]
    fn uplink_forwards_matching_source_to_n6() {
        let (state, teid) = established_upf();
        let inner = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), b"uplink");
        assert_eq!(uplink(&state, teid, &inner), Uplink::ToN6(&inner[..]));
    }

    #[test]
    fn uplink_drops_unknown_teid_and_spoofed_source() {
        let (state, teid) = established_upf();
        let good = ipv4_packet(UE_IP, Ipv4Addr::new(8, 8, 8, 8), b"x");
        assert_eq!(uplink(&state, 999, &good), Uplink::UnknownTeid, "no session owns TEID 999");

        let spoofed = ipv4_packet(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(8, 8, 8, 8), b"x");
        assert_eq!(
            uplink(&state, teid, &spoofed),
            Uplink::Spoofed { claimed: Ipv4Addr::new(1, 2, 3, 4), assigned: UE_IP },
            "source that isn't the UE's assigned IP is rejected"
        );
    }
}
