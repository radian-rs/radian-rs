//! PFCP — Packet Forwarding Control Protocol (TS 29.244), the N4 protocol between
//! SMF (control) and UPF (user plane). Binary TLV over UDP — not ASN.1.
//!
//! Wraps the [`rs_pfcp`] codec and adds SMF-side request builders + a stateful
//! UPF-side handler for node-level **association**/**heartbeat** and PFCP
//! **session establishment** (the SMF provisions an uplink PDR/FAR; the UPF
//! allocates an N3 F-TEID and tracks the session). The GTP-U datapath and session
//! modification/deletion come in later slices.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

pub use rs_pfcp;
pub use rs_pfcp::ie::IeType;
pub use rs_pfcp::message::MsgType;

use rs_pfcp::ie::cause::CauseValue;
use rs_pfcp::ie::create_far::CreateFar;
use rs_pfcp::ie::create_pdr::{CreatePdr, CreatePdrBuilder};
use rs_pfcp::ie::created_pdr::CreatedPdr;
use rs_pfcp::ie::destination_interface::{DestinationInterface, Interface};
use rs_pfcp::ie::f_teid::{Fteid, FteidBuilder};
use rs_pfcp::ie::far_id::FarId;
use rs_pfcp::ie::fseid::Fseid;
use rs_pfcp::ie::pdi::{Pdi, PdiBuilder};
use rs_pfcp::ie::pdr_id::PdrId;
use rs_pfcp::ie::precedence::Precedence;
use rs_pfcp::ie::ue_ip_address::UeIpAddress;
use rs_pfcp::ie::apply_action::ApplyAction;
use rs_pfcp::ie::create_qer::CreateQer;
use rs_pfcp::ie::create_urr::CreateUrr;
use rs_pfcp::ie::measurement_method::MeasurementMethod;
use rs_pfcp::ie::reporting_triggers::ReportingTriggers;
use rs_pfcp::ie::sequence_number::SequenceNumber;
use rs_pfcp::ie::report_type::ReportType;
use rs_pfcp::ie::urr_id::UrrId;
use rs_pfcp::ie::usage_report::UsageReport;
use rs_pfcp::ie::usage_report_srr::UsageReportSrr;
use rs_pfcp::ie::usage_report_trigger::UsageReportTrigger;
use rs_pfcp::ie::volume_measurement::VolumeMeasurement;
use rs_pfcp::ie::volume_threshold::VolumeThreshold;
use rs_pfcp::ie::mbr::Mbr;
use rs_pfcp::ie::network_instance::NetworkInstance;
use rs_pfcp::ie::pfcpsm_req_flags::PfcpsmReqFlags;
use rs_pfcp::ie::outer_header_creation::OuterHeaderCreation;
use rs_pfcp::ie::qer_id::QerId;
use rs_pfcp::ie::remove_pdr::RemovePdr;
use rs_pfcp::ie::remove_qer::RemoveQer;
use rs_pfcp::ie::sdf_filter::SdfFilter;
use rs_pfcp::ie::update_far::UpdateFar;
use rs_pfcp::ie::update_forwarding_parameters::UpdateForwardingParameters;
use rs_pfcp::ie::update_qer::UpdateQer;
use rs_pfcp::ie::Ie;
use rs_pfcp::message::association_setup_request::AssociationSetupRequestBuilder;
use rs_pfcp::message::association_setup_response::AssociationSetupResponseBuilder;
use rs_pfcp::message::heartbeat_request::HeartbeatRequestBuilder;
use rs_pfcp::message::heartbeat_response::HeartbeatResponseBuilder;
use rs_pfcp::message::session_establishment_request::SessionEstablishmentRequestBuilder;
use rs_pfcp::message::session_establishment_response::SessionEstablishmentResponseBuilder;
use rs_pfcp::message::session_deletion_request::SessionDeletionRequestBuilder;
use rs_pfcp::message::session_deletion_response::SessionDeletionResponseBuilder;
use rs_pfcp::message::session_modification_request::SessionModificationRequestBuilder;
use rs_pfcp::message::session_modification_response::SessionModificationResponseBuilder;
use rs_pfcp::message::session_report_request::SessionReportRequestBuilder;
use rs_pfcp::message::session_report_response::SessionReportResponseBuilder;
use rs_pfcp::message::Message;

/// Default N4 PFCP UDP port (TS 29.244).
pub const N4_PORT: u16 = 8805;

/// The QER id the session-AMBR QER carries (one session-level QER per session).
const AMBR_QER_ID: u32 = 1;
/// The uplink FAR's id — forwards to the core (N6), or over N9 to the next UPF when
/// the SMF gave it an Outer Header Creation (design/134).
const UPLINK_FAR_ID: u32 = 1;
/// The downlink FAR's id — the one a Session Modification re-points at the gNB tunnel
/// (or, on an anchor behind a chain, at the intermediate UPF's N9 ingress).
const DOWNLINK_FAR_ID: u32 = 2;
/// The downlink PDR's id. On an anchor it matches the UE address; on an intermediate
/// UPF it instead carries an F-TEID, because downlink arrives back from the anchor over
/// N9 (design/134).
const DOWNLINK_PDR_ID: u16 = 2;
/// A GBR flow's per-flow QER id is `PER_FLOW_QER_BASE + qfi` (distinct from the
/// session-AMBR QER), and its classifier PDR id is `PER_FLOW_PDR_BASE + index`.
const PER_FLOW_QER_BASE: u32 = 1000;
const PER_FLOW_PDR_BASE: u16 = 100;
/// A **ULCL branch**'s classifier PDR id is `ULCL_PDR_BASE + index` and its FAR id
/// `ULCL_FAR_BASE + index` (design/134 Phase 2). The PDR band clears the per-flow one
/// (`100..=355`, QFI being a `u8`); the FAR band clears the uplink (1) and downlink (2)
/// FARs. A branch PDR outranks the per-flow QoS classifiers on precedence, since
/// choosing an egress has to happen before the packet is policed on its way there.
const ULCL_PDR_BASE: u16 = 400;
const ULCL_FAR_BASE: u32 = 3;
const ULCL_PRECEDENCE: u32 = 40;
/// The session-level volume URR id (usage measurement + final report at deletion).
const SESSION_URR_ID: u32 = 1;
/// A GBR flow's per-flow volume URR id is `PER_FLOW_URR_BASE + qfi` — its usage is
/// measured separately (per-rating-group charging) and reported at deletion.
pub const PER_FLOW_URR_BASE: u32 = 2000;

/// An IP prefix — an SDF filter's destination match (`dst=10.99.0.0/16`). Holds both
/// families so a ULCL can steer IPv6 traffic too (design/131 shipped v6 sessions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl IpPrefix {
    pub fn new(addr: impl Into<IpAddr>, len: u8) -> Self {
        Self { addr: addr.into(), len }
    }

    /// Whether `ip` falls in this prefix. A mismatched family never matches.
    pub fn contains(&self, ip: IpAddr) -> bool {
        fn masked(bytes: &[u8], len: u8) -> Vec<u8> {
            let len = usize::from(len).min(bytes.len() * 8);
            let (full, rem) = (len / 8, len % 8);
            let mut out = bytes[..full].to_vec();
            if rem > 0 {
                out.push(bytes[full] & (0xffu8 << (8 - rem)));
            }
            out
        }
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                masked(&net.octets(), self.len) == masked(&ip.octets(), self.len)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                masked(&net.octets(), self.len) == masked(&ip.octets(), self.len)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl std::str::FromStr for IpPrefix {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        let (addr, len) = s.split_once('/').ok_or(())?;
        Ok(Self { addr: addr.parse().map_err(|_| ())?, len: len.parse().map_err(|_| ())? })
    }
}

/// The classification inputs one packet offers an SDF filter.
#[derive(Debug, Clone, Copy)]
struct PacketKey {
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dst: IpAddr,
}

/// A compact packet classifier — a greenfield stand-in for a full TS 29.244 SDF filter
/// (a production UPF parses IPFilterRule syntax). Carried in the PDR's SDF filter field
/// as a self-described `flow_description`. Every component is optional and an absent one
/// matches anything, so one type serves both users: a **QoS** classifier picks a flow by
/// protocol + ports, while a **ULCL branch** picks an egress by destination prefix
/// (design/134 Phase 2). Nothing stops a rule from combining them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowFilter {
    /// Transport protocol; `None` matches any.
    pub protocol: Option<u8>,
    /// An inclusive port range matched against **either** endpoint; `None` matches any.
    pub ports: Option<(u16, u16)>,
    /// Prefix the packet's **destination** must fall in; `None` matches any. Unlike
    /// `ports` this is directional — steering by where traffic is going is exactly what
    /// an uplink classifier does.
    pub dst: Option<IpPrefix>,
}

impl FlowFilter {
    /// A QoS classifier: a transport protocol and a port range on either endpoint.
    pub fn transport(protocol: u8, port_low: u16, port_high: u16) -> Self {
        Self { protocol: Some(protocol), ports: Some((port_low, port_high)), dst: None }
    }

    /// A ULCL branch classifier: everything destined into `prefix`.
    pub fn to_prefix(prefix: IpPrefix) -> Self {
        Self { protocol: None, ports: None, dst: Some(prefix) }
    }

    /// Whether a packet matches. An all-`None` filter matches everything.
    fn matches(&self, key: &PacketKey) -> bool {
        self.protocol.is_none_or(|p| p == key.protocol)
            && self.ports.is_none_or(|(lo, hi)| {
                (lo..=hi).contains(&key.src_port) || (lo..=hi).contains(&key.dst_port)
            })
            && self.dst.is_none_or(|d| d.contains(key.dst))
    }

    /// Encode as the PDR SDF filter's flow-description string. Absent components are
    /// omitted, so a filter written before `dst` existed round-trips unchanged.
    fn to_flow_description(self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = self.protocol {
            parts.push(format!("proto={p}"));
        }
        if let Some((lo, hi)) = self.ports {
            parts.push(format!("ports={lo}-{hi}"));
        }
        if let Some(d) = self.dst {
            parts.push(format!("dst={d}"));
        }
        parts.join(";")
    }

    /// Parse a flow-description written by [`to_flow_description`]. `None` only if a
    /// present component is malformed — an empty description is the match-all filter.
    fn from_flow_description(s: &str) -> Option<Self> {
        let mut f = FlowFilter { protocol: None, ports: None, dst: None };
        for part in s.split(';').filter(|p| !p.is_empty()) {
            let (k, v) = part.split_once('=')?;
            match k {
                "proto" => f.protocol = Some(v.parse().ok()?),
                "ports" => {
                    let (lo, hi) = v.split_once('-')?;
                    f.ports = Some((lo.parse().ok()?, hi.parse().ok()?));
                }
                "dst" => f.dst = Some(v.parse().ok()?),
                _ => {}
            }
        }
        Some(f)
    }
}

/// A GBR flow's per-flow QER the SMF installs at the UPF: its classifier + MFBR.
#[derive(Debug, Clone, Copy)]
pub struct FlowQer {
    pub qfi: u8,
    pub filter: FlowFilter,
    pub mfbr_dl_bps: u64,
    pub mfbr_ul_bps: u64,
}

/// A per-flow policer at the UPF: the classifier + its MFBR token buckets, plus
/// the flow's own volume counters (its per-flow URR measurement).
struct FlowEnforcer {
    qfi: u8,
    filter: FlowFilter,
    ul_bucket: TokenBucket,
    dl_bucket: TokenBucket,
    /// Per-flow URR volume measurement: forwarded bytes each direction.
    ul_bytes: u64,
    dl_bytes: u64,
}

/// Extract the classification inputs from a bare IP packet: protocol, ports and
/// destination address. Ports are 0 for protocols that don't carry them. `None` if the
/// packet is neither IPv4 nor IPv6, or is truncated.
///
/// IPv6 extension headers are not walked — a packet carrying them classifies as its
/// first next-header with ports 0, which is the same conservative treatment IPv4 gives
/// an unrecognised protocol.
fn packet_key(pkt: &[u8]) -> Option<PacketKey> {
    // TCP (6), UDP (17), SCTP (132) carry ports in the first 4 L4-header bytes.
    fn ports(pkt: &[u8], protocol: u8, off: usize) -> (u16, u16) {
        match protocol {
            6 | 17 | 132 if pkt.len() >= off + 4 => (
                u16::from_be_bytes([pkt[off], pkt[off + 1]]),
                u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]),
            ),
            _ => (0, 0),
        }
    }
    match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 20 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            let protocol = pkt[9];
            let (src_port, dst_port) = ports(pkt, protocol, ihl);
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            Some(PacketKey { protocol, src_port, dst_port, dst: dst.into() })
        }
        Some(6) if pkt.len() >= 40 => {
            let protocol = pkt[6]; // next header
            let (src_port, dst_port) = ports(pkt, protocol, 40);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&pkt[24..40]);
            Some(PacketKey { protocol, src_port, dst_port, dst: Ipv6Addr::from(dst).into() })
        }
        _ => None,
    }
}

/// The Create QER + classifier Create PDR (SDF filter) + volume Create URR IEs for
/// one per-flow QER — used at establishment and in a mid-session flow modification.
/// The QER/PDR/URR ids are `PER_FLOW_{QER,PDR,URR}_BASE + qfi` (all stable per QFI,
/// so a later modification can update or remove them).
fn flow_create_ies(f: &FlowQer) -> (Ie, Ie, Ie) {
    let flow_qer_id = QerId::new(PER_FLOW_QER_BASE + u32::from(f.qfi));
    let flow_urr_id = UrrId::new(PER_FLOW_URR_BASE + u32::from(f.qfi));
    let qer = CreateQer::builder(flow_qer_id)
        .rate_limit(f.mfbr_ul_bps, f.mfbr_dl_bps)
        .build()
        .expect("build per-flow Create QER");
    // Per-flow volume URR: this flow's usage measured separately (its own
    // rating group toward charging), reported at deletion.
    let urr = CreateUrr::new(
        flow_urr_id,
        MeasurementMethod::new(false, true, false), // volume
        ReportingTriggers::new(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let flow_pdi = PdiBuilder::uplink_access()
        .sdf_filter(SdfFilter::new(&f.filter.to_flow_description()))
        .build()
        .expect("build per-flow PDI");
    let pdr = CreatePdrBuilder::new(PdrId::new(PER_FLOW_PDR_BASE + u16::from(f.qfi)))
        .precedence(Precedence::new(50)) // higher precedence than the match-all PDRs
        .pdi(flow_pdi)
        .far_id(FarId::new(1))
        .qer_id(flow_qer_id)
        .urr_id(UrrId::new(PER_FLOW_URR_BASE + u32::from(f.qfi)))
        .build()
        .expect("build per-flow Create PDR");
    (qer.to_ie(), pdr.to_ie(), urr.to_ie())
}

/// Build the FAR forwarding parameters for one egress: plain N6 (this node delivers the
/// traffic to the data network) or a GTP-U tunnel toward another UPF over N9.
fn egress_forwarding_parameters(
    egress: Egress,
    dnn: &str,
) -> rs_pfcp::ie::forwarding_parameters::ForwardingParameters {
    let params = rs_pfcp::ie::forwarding_parameters::ForwardingParameters::new(
        DestinationInterface::new(Interface::Core),
    )
    .with_network_instance(NetworkInstance::new(dnn));
    match egress {
        Egress::ToN6 => params,
        Egress::ToPeer { teid, addr } => {
            params.with_outer_header_creation(OuterHeaderCreation::gtpu_ipv4(teid, addr))
        }
    }
}

/// The classifier Create PDR + Create FAR IEs for one **ULCL branch** (design/134
/// Phase 2): a PDR whose SDF filter selects traffic by destination, bound to a FAR of
/// its own so the matched subset leaves by a different egress than the session default.
/// `index` distinguishes the branches of one session and fixes both ids, so a later
/// modification can address a branch.
fn branch_create_ies(index: usize, filter: &FlowFilter, egress: Egress, dnn: &str) -> (Ie, Ie) {
    let far_id = FarId::new(ULCL_FAR_BASE + index as u32);
    let pdi = PdiBuilder::uplink_access()
        .sdf_filter(SdfFilter::new(&filter.to_flow_description()))
        .build()
        .expect("build branch PDI");
    let pdr = CreatePdrBuilder::new(PdrId::new(ULCL_PDR_BASE + index as u16))
        .precedence(Precedence::new(ULCL_PRECEDENCE))
        .pdi(pdi)
        .far_id(far_id)
        .build()
        .expect("build branch Create PDR");
    let far = CreateFar::builder(far_id)
        .apply_action(ApplyAction::FORW)
        .forwarding_parameters(egress_forwarding_parameters(egress, dnn))
        .build()
        .expect("build branch Create FAR");
    (pdr.to_ie(), far.to_ie())
}

/// Parse the **ULCL branch** rules a message provisions: each classifier PDR in the
/// branch id band, paired with the egress of the FAR it points at. Ordered by PDR id so
/// the UPF evaluates them the way the SMF numbered them.
fn parse_branches(msg: &dyn rs_pfcp::message::Message) -> Vec<(FlowFilter, Egress)> {
    let far_egress: HashMap<u32, Egress> = msg
        .ies(IeType::CreateFar)
        .filter_map(|ie| CreateFar::unmarshal(&ie.payload).ok())
        .map(|far| {
            let egress = far
                .forwarding_parameters
                .and_then(|fp| fp.outer_header_creation)
                .and_then(|ohc| {
                    Some(Egress::ToPeer { teid: u32::from(ohc.teid?), addr: ohc.ipv4_address? })
                })
                .unwrap_or(Egress::ToN6);
            (far.far_id.value, egress)
        })
        .collect();
    let mut pdrs: Vec<CreatePdr> = msg
        .ies(IeType::CreatePdr)
        .filter_map(|ie| CreatePdr::unmarshal(&ie.payload).ok())
        .filter(|pdr| pdr.pdr_id.value >= ULCL_PDR_BASE)
        .collect();
    pdrs.sort_by_key(|pdr| pdr.pdr_id.value);
    pdrs.into_iter()
        .filter_map(|pdr| {
            let filter = FlowFilter::from_flow_description(&pdr.pdi.sdf_filter?.flow_description)?;
            Some((filter, *far_egress.get(&pdr.far_id?.value)?))
        })
        .collect()
}

/// Parse the per-flow QERs a message provisions: each classifier PDR (SDF filter)
/// linked by `qer_id` to a Create QER's MBR. Used at establishment and when a
/// mid-session modification adds flows.
fn parse_created_flows(msg: &dyn rs_pfcp::message::Message) -> Vec<FlowQer> {
    let qer_mbrs: HashMap<u32, Mbr> = msg
        .ies(IeType::CreateQer)
        .filter_map(|ie| CreateQer::unmarshal(&ie.payload).ok())
        .filter_map(|q| q.mbr.map(|m| (q.qer_id.value, m)))
        .collect();
    msg.ies(IeType::CreatePdr)
        .filter_map(|ie| CreatePdr::unmarshal(&ie.payload).ok())
        .filter_map(|pdr| {
            let filter = FlowFilter::from_flow_description(&pdr.pdi.sdf_filter?.flow_description)?;
            let qer_id = pdr.qer_id?.value;
            let mbr = qer_mbrs.get(&qer_id)?;
            let qfi = qer_id.saturating_sub(PER_FLOW_QER_BASE) as u8;
            Some(FlowQer { qfi, filter, mfbr_dl_bps: mbr.downlink, mfbr_ul_bps: mbr.uplink })
        })
        .collect()
}

/// A session's aggregate maximum bit rate (uplink/downlink), bits per second — the
/// value the UPF enforces via a per-session [`TokenBucket`] (TS 23.501 §5.7.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAmbr {
    pub uplink_bps: u64,
    pub downlink_bps: u64,
}

/// The UE address(es) a PDU session carries — an IPv4 address, an IPv6 **/64
/// prefix**, or both (design/131). The UPF keys downlink routing and anti-spoofing
/// on these. `From<Ipv4Addr>` keeps the common IPv4-only call sites terse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UeAddr {
    pub v4: Option<Ipv4Addr>,
    /// The assigned IPv6 /64 prefix (low 64 bits zero); the UE forms its address
    /// within it via SLAAC.
    pub v6: Option<Ipv6Addr>,
}

impl From<Ipv4Addr> for UeAddr {
    fn from(v4: Ipv4Addr) -> Self {
        UeAddr { v4: Some(v4), v6: None }
    }
}

/// Where a session's **uplink** traffic goes once decapsulated (design/134).
///
/// A PDU Session Anchor sends it out to the data network; an **intermediate UPF** (an
/// I-UPF / uplink classifier) forwards it on to the next UPF over **N9**, which is
/// GTP-U like N3 and rides the same socket — the peer's F-TEID distinguishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Egress {
    /// Out to the data network over N6 — the anchor's behaviour.
    #[default]
    ToN6,
    /// On to another UPF over N9, addressed by that peer's F-TEID.
    ToPeer { teid: u32, addr: Ipv4Addr },
}

/// Whether IPv6 address `addr` falls within the /64 `prefix` (top 64 bits match).
fn ipv6_in_prefix64(addr: Ipv6Addr, prefix: Ipv6Addr) -> bool {
    let (a, p) = (addr.octets(), prefix.octets());
    a[..8] == p[..8]
}

/// A token-bucket rate limiter (bits), used to police a session's AMBR. Pure and
/// clock-injected (the caller passes `now_nanos`) so the policing is unit-testable
/// without real time. `rate_bps == 0` means *unlimited* (always admit).
#[derive(Debug, Clone)]
struct TokenBucket {
    rate_bps: u64,
    /// Bucket capacity in bits — the largest burst admitted after an idle period.
    burst_bits: u64,
    /// Current tokens (bits) available.
    level_bits: u64,
    /// Timestamp of the last refill.
    last_nanos: u64,
}

impl TokenBucket {
    /// A bucket for `rate_bps`, starting full at `now_nanos`. Capacity is ~1s of
    /// rate, floored at one jumbo frame so a single packet can always eventually
    /// pass.
    fn new(rate_bps: u64, now_nanos: u64) -> Self {
        // ~one oversized MTU in bits — a packet must never exceed the capacity.
        const MIN_BURST_BITS: u64 = 8 * 4096;
        let burst_bits = rate_bps.max(MIN_BURST_BITS);
        Self { rate_bps, burst_bits, level_bits: burst_bits, last_nanos: now_nanos }
    }

    /// Refill for the elapsed time, then admit `bytes` if enough tokens remain.
    /// `rate_bps == 0` ⇒ unlimited.
    fn poll(&mut self, now_nanos: u64, bytes: usize) -> bool {
        if self.rate_bps == 0 {
            return true;
        }
        let elapsed = now_nanos.saturating_sub(self.last_nanos);
        self.last_nanos = now_nanos;
        let refill = (u128::from(self.rate_bps) * u128::from(elapsed) / 1_000_000_000u128) as u64;
        self.level_bits = self.level_bits.saturating_add(refill).min(self.burst_bits);
        let need = (bytes as u64).saturating_mul(8);
        if self.level_bits >= need {
            self.level_bits -= need;
            true
        } else {
            false
        }
    }

    /// Re-rate the bucket (a mid-session AMBR change): refill to now under the old
    /// rate, then adopt the new rate/capacity, clamping the level to the new cap.
    fn set_rate(&mut self, rate_bps: u64, now_nanos: u64) {
        self.poll(now_nanos, 0); // refill to `now` under the old rate
        let fresh = TokenBucket::new(rate_bps, now_nanos);
        self.rate_bps = fresh.rate_bps;
        self.burst_bits = fresh.burst_bits;
        self.level_bits = self.level_bits.min(fresh.burst_bits);
        self.last_nanos = now_nanos;
    }
}

/// One PFCP session's UPF state: the uplink N3 F-TEID, the SMF-allocated **UE IP**
/// (how the UPF routes a downlink packet arriving from N6 to this session), and —
/// once the SMF runs a Session Modification after N2 setup — the gNB downlink target
/// `(TEID, IP)` for GTP-U Outer Header Creation.
struct Session {
    n3_teid: u32,
    /// The SMF's F-SEID for this session — the header SEID a UPF-initiated
    /// Session Report Request must carry (TS 29.244 messages address the peer).
    cp_seid: u64,
    ue_ip: Option<Ipv4Addr>,
    /// The assigned IPv6 /64 prefix (design/131) — downlink packets whose destination
    /// falls in it route to this session; `None` for an IPv4-only session.
    ue_ipv6: Option<Ipv6Addr>,
    downlink: Option<(u32, Ipv4Addr)>,
    /// Where this session's uplink goes after decapsulation — out to N6 (an anchor) or
    /// on to the next UPF over N9 (an intermediate UPF, design/134). Seeded from the
    /// uplink FAR's Outer Header Creation at establishment. This is the **default**: a
    /// packet matching a `branch` leaves by that branch's egress instead.
    uplink: Egress,
    /// **Uplink classifier** rules (TS 23.501 §5.6.4, design/134 Phase 2), consulted in
    /// order; the first match wins. Each pairs an SDF filter with its own egress, so a
    /// subset of the session's uplink can break out to a different anchor while the rest
    /// takes `uplink`. Empty ⇒ this node does not branch.
    branches: Vec<(FlowFilter, Egress)>,
    /// An intermediate UPF's **downlink N9 ingress** TEID: the anchor sends downlink
    /// back here under it, and this node forwards it on to `downlink` (the gNB). `None`
    /// on an anchor, whose downlink arrives from N6 and is routed by UE address.
    dl_ingress_teid: Option<u32>,
    /// Session AMBR (from a Create/Update QER), when provisioned.
    ambr: Option<SessionAmbr>,
    /// Per-direction AMBR policers. `None` ⇒ that direction is unlimited.
    ul_bucket: Option<TokenBucket>,
    dl_bucket: Option<TokenBucket>,
    /// Per-GBR-flow policers (MFBR), checked by classifier before the session AMBR.
    flow_qers: Vec<FlowEnforcer>,
    /// URR volume measurement: forwarded (admitted) bytes each direction.
    ul_bytes: u64,
    dl_bytes: u64,
    /// Volume threshold (bytes, total) from the session URR's Reporting Triggers —
    /// crossing it flags a usage report toward the SMF (VOLTH).
    usage_threshold: Option<u64>,
    /// Bytes already covered by previous threshold reports (per direction), so each
    /// report carries the delta since the last one.
    reported_ul: u64,
    reported_dl: u64,
    /// A threshold crossing awaiting pickup by [`UpfState::take_due_report`].
    report_due: bool,
    /// The downlink FAR is **buffering** (CM-IDLE, AN release): downlink packets are
    /// held in `dl_buffer` and a Downlink Data Report is raised, instead of being
    /// forwarded. Cleared when the tunnel is re-installed (Service Request resume).
    buffering: bool,
    /// Buffered downlink packets (bounded), flushed to the gNB on re-activation.
    dl_buffer: std::collections::VecDeque<Vec<u8>>,
    /// A first buffered packet awaiting a Downlink Data Report toward the SMF
    /// (paging trigger), picked up by [`UpfState::take_dl_data_report`].
    dl_data_report_due: bool,
}

/// Max downlink packets buffered per CM-IDLE session before dropping the oldest —
/// enough to hold the trigger packet(s) until paging completes (TS 23.501 §5.6.11).
const DL_BUFFER_CAP: usize = 64;

impl Session {
    /// Admit `pkt` in the given direction: classify it to a GBR flow and police it
    /// against that flow's MFBR, else against the session AMBR. `true` = forward.
    ///
    /// Forwarded bytes are counted under exactly **one** URR — the matched flow's,
    /// else the session-level one — mirroring TS 29.244 (a URR measures what its
    /// own PDRs carry), so a charging system summing all rating groups sees the
    /// true total. A crossed session-URR volume threshold flags a report.
    fn admit(&mut self, uplink: bool, now_nanos: u64, pkt: &[u8]) -> bool {
        let bytes = pkt.len();
        let flow_idx = packet_key(pkt)
            .and_then(|key| self.flow_qers.iter().position(|f| f.filter.matches(&key)));
        let bucket: Option<&mut TokenBucket> = match flow_idx {
            Some(i) if uplink => Some(&mut self.flow_qers[i].ul_bucket),
            Some(i) => Some(&mut self.flow_qers[i].dl_bucket),
            None if uplink => self.ul_bucket.as_mut(),
            None => self.dl_bucket.as_mut(),
        };
        let admitted = bucket.is_none_or(|b| b.poll(now_nanos, bytes));
        if admitted {
            match flow_idx {
                Some(i) => {
                    let f = &mut self.flow_qers[i];
                    if uplink {
                        f.ul_bytes = f.ul_bytes.saturating_add(bytes as u64);
                    } else {
                        f.dl_bytes = f.dl_bytes.saturating_add(bytes as u64);
                    }
                }
                None => {
                    if uplink {
                        self.ul_bytes = self.ul_bytes.saturating_add(bytes as u64);
                    } else {
                        self.dl_bytes = self.dl_bytes.saturating_add(bytes as u64);
                    }
                    // VOLTH: unreported session-URR volume crossed the threshold →
                    // a report is due. (Per-flow thresholds are deferred.)
                    if let Some(th) = self.usage_threshold {
                        let unreported =
                            (self.ul_bytes - self.reported_ul) + (self.dl_bytes - self.reported_dl);
                        if unreported >= th {
                            self.report_due = true;
                        }
                    }
                }
            }
        }
        admitted
    }
}

/// One URR's measured volume, as carried in usage reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageVolume {
    pub urr_id: u32,
    pub total: u64,
    pub uplink: u64,
    pub downlink: u64,
}

/// A threshold-triggered usage report awaiting transmission to the SMF.
#[derive(Debug, Clone, Copy)]
pub struct DueReport {
    /// The SMF's F-SEID — the Session Report Request's header SEID.
    pub cp_seid: u64,
    pub usage: UsageVolume,
}

/// Minimal UPF state: the N3 F-TEID and UP-SEID allocators plus a session table
/// (UP-SEID → [`Session`]).
pub struct UpfState {
    next_teid: u32,
    next_seid: u64,
    sessions: HashMap<u64, Session>,
    /// Buffered downlink packets to send on N3 after a re-activation, as
    /// `(gNB TEID, gNB IP, inner IP packet)` — drained by
    /// [`take_flush`](UpfState::take_flush) and GTP-U-encapsulated by the caller.
    pending_flush: Vec<(u32, Ipv4Addr, Vec<u8>)>,
    /// GTP-U End Markers to send on N3 after a downlink path switch, as the **old**
    /// `(gNB TEID, gNB IP)` — drained by [`take_end_markers`](UpfState::take_end_markers).
    pending_end_markers: Vec<(u32, Ipv4Addr)>,
    /// Unsolicited IPv6 Router Advertisements to send on N3 once a v6 session's
    /// downlink is installed, as `(gNB TEID, gNB IP, /64 prefix)` — drained by
    /// [`take_pending_ra`](UpfState::take_pending_ra) (design/131 Phase C).
    pending_ra: Vec<(u32, Ipv4Addr, Ipv6Addr)>,
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
            pending_flush: Vec::new(),
            pending_end_markers: Vec::new(),
            pending_ra: Vec::new(),
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Whether any session owns this N3 TEID (used by the GTP-U datapath to route
    /// an uplink G-PDU to a known session).
    pub fn knows_teid(&self, teid: u32) -> bool {
        self.sessions.values().any(|s| s.n3_teid == teid)
    }

    /// The gNB downlink target `(TEID, IP)` for a session, once a Session Modification
    /// has installed it. The GTP-U datapath uses it to encapsulate downlink packets.
    /// The **default** egress of the session owning this uplink N3/N9 TEID — N6 for an
    /// anchor, an N9 peer for an intermediate UPF (design/134). `None` if the TEID is
    /// unknown. Ignores branch rules; the datapath wants [`uplink_egress_for`].
    ///
    /// [`uplink_egress_for`]: UpfState::uplink_egress_for
    pub fn uplink_egress_for_teid(&self, teid: u32) -> Option<Egress> {
        self.sessions.values().find(|s| s.n3_teid == teid).map(|s| s.uplink)
    }

    /// Where this uplink packet goes once decapsulated. An **uplink classifier** node
    /// consults its branch rules first, so egress is a *per-packet* decision rather than
    /// a per-session one — that is the whole point of a ULCL (design/134 Phase 2). Falls
    /// back to the session's default egress when nothing matches. `None` if the TEID is
    /// unknown.
    pub fn uplink_egress_for(&self, teid: u32, pkt: &[u8]) -> Option<Egress> {
        let s = self.sessions.values().find(|s| s.n3_teid == teid)?;
        let branched = packet_key(pkt).and_then(|key| {
            s.branches.iter().find(|(filter, _)| filter.matches(&key)).map(|(_, e)| *e)
        });
        Some(branched.unwrap_or(s.uplink))
    }

    /// The branch rules installed on the session owning this uplink TEID — the SMF's
    /// view of what this node steers away from its default egress.
    pub fn branches_for_teid(&self, teid: u32) -> Vec<(FlowFilter, Egress)> {
        self.sessions
            .values()
            .find(|s| s.n3_teid == teid)
            .map(|s| s.branches.clone())
            .unwrap_or_default()
    }

    /// If `teid` is an intermediate UPF's **downlink N9 ingress**, the gNB target to
    /// forward that traffic on to (design/134). `None` for an uplink or unknown TEID —
    /// which is what distinguishes the two directions on a chained node.
    pub fn downlink_via_n9_ingress(&self, teid: u32) -> Option<(u32, Ipv4Addr)> {
        self.sessions
            .values()
            .find(|s| s.dl_ingress_teid == Some(teid))
            .and_then(|s| s.downlink)
    }

    pub fn downlink_for(&self, up_seid: u64) -> Option<(u32, Ipv4Addr)> {
        self.sessions.get(&up_seid).and_then(|s| s.downlink)
    }

    /// Route a downlink packet arriving from N6 (the data network): find the session
    /// whose assigned UE IP is `dst` and return its installed gNB target `(TEID, IP)`.
    /// `None` if no session owns that UE IP or its downlink is not yet installed.
    pub fn route_downlink(&self, dst: Ipv4Addr) -> Option<(u32, Ipv4Addr)> {
        self.sessions
            .values()
            .find(|s| s.ue_ip == Some(dst))
            .and_then(|s| s.downlink)
    }

    /// Route an IPv6 downlink packet: find the session whose assigned /64 prefix
    /// contains `dst` and return its installed gNB target `(TEID, IPv4 N3 addr)` — the
    /// N3 transport stays IPv4 (design/131). `None` if unrouted / downlink not installed.
    pub fn route_downlink_v6(&self, dst: Ipv6Addr) -> Option<(u32, Ipv4Addr)> {
        self.sessions
            .values()
            .find(|s| s.ue_ipv6.is_some_and(|p| ipv6_in_prefix64(dst, p)))
            .and_then(|s| s.downlink)
    }

    /// The UE IP assigned to the session owning this uplink N3 TEID — the uplink datapath
    /// uses it to verify a decapsulated packet's source is the UE it claims to be (a basic
    /// anti-spoofing guard). `None` if the TEID is unknown or no UE IP was assigned.
    pub fn ue_ip_for_teid(&self, teid: u32) -> Option<Ipv4Addr> {
        self.sessions
            .values()
            .find(|s| s.n3_teid == teid)
            .and_then(|s| s.ue_ip)
    }

    /// The IPv6 /64 prefix assigned to the session owning this uplink N3 TEID — the
    /// uplink datapath verifies a decapsulated IPv6 packet's source falls in it.
    pub fn ue_ipv6_for_teid(&self, teid: u32) -> Option<Ipv6Addr> {
        self.sessions
            .values()
            .find(|s| s.n3_teid == teid)
            .and_then(|s| s.ue_ipv6)
    }


    /// Remove a session (PFCP Session Deletion) — its TEID and UE-IP routes go with
    /// it. Returns the session's final volume usage: the session-level URR plus one
    /// entry per per-flow URR. The session URR carries only the volume **not yet
    /// covered by a threshold report** (so a charging system summing all reports
    /// sees the true total once). `None` if the session didn't exist.
    fn remove(&mut self, up_seid: u64) -> Option<Vec<UsageVolume>> {
        self.sessions.remove(&up_seid).map(|s| {
            let (ul, dl) = (s.ul_bytes - s.reported_ul, s.dl_bytes - s.reported_dl);
            let mut usages = vec![UsageVolume {
                urr_id: SESSION_URR_ID,
                total: ul + dl,
                uplink: ul,
                downlink: dl,
            }];
            usages.extend(s.flow_qers.iter().map(|f| UsageVolume {
                urr_id: PER_FLOW_URR_BASE + u32::from(f.qfi),
                total: f.ul_bytes + f.dl_bytes,
                uplink: f.ul_bytes,
                downlink: f.dl_bytes,
            }));
            usages
        })
    }

    /// Allocate a UP-SEID + N3 TEID for a new session and record it (with the
    /// SMF-allocated UE IP, if the establishment carried one).
    #[allow(clippy::too_many_arguments)]
    fn establish(
        &mut self,
        cp_seid: u64,
        ue: UeAddr,
        ambr: Option<SessionAmbr>,
        flows: &[FlowQer],
        usage_threshold: Option<u64>,
        now_nanos: u64,
        uplink: Egress,
        branches: Vec<(FlowFilter, Egress)>,
        wants_dl_ingress: bool,
    ) -> (u64, u32, Option<u32>) {
        let up_seid = self.next_seid;
        let teid = self.next_teid;
        self.next_seid += 1;
        self.next_teid += 1;
        // An intermediate UPF also needs an ingress TEID for downlink arriving back from
        // the anchor over N9 (design/134).
        let dl_ingress_teid = wants_dl_ingress.then(|| {
            let t = self.next_teid;
            self.next_teid += 1;
            t
        });
        let ul_bucket = ambr.map(|a| TokenBucket::new(a.uplink_bps, now_nanos));
        let dl_bucket = ambr.map(|a| TokenBucket::new(a.downlink_bps, now_nanos));
        let flow_qers = flows
            .iter()
            .map(|f| FlowEnforcer {
                qfi: f.qfi,
                filter: f.filter,
                ul_bucket: TokenBucket::new(f.mfbr_ul_bps, now_nanos),
                dl_bucket: TokenBucket::new(f.mfbr_dl_bps, now_nanos),
                ul_bytes: 0,
                dl_bytes: 0,
            })
            .collect();
        self.sessions.insert(
            up_seid,
            Session {
                n3_teid: teid,
                cp_seid,
                ue_ip: ue.v4,
                ue_ipv6: ue.v6,
                downlink: None,
                uplink,
                branches,
                ambr,
                ul_bucket,
                dl_bucket,
                flow_qers,
                ul_bytes: 0,
                dl_bytes: 0,
                usage_threshold,
                reported_ul: 0,
                reported_dl: 0,
                report_due: false,
                buffering: false,
                dl_buffer: std::collections::VecDeque::new(),
                dl_data_report_due: false,
                dl_ingress_teid,
            },
        );
        (up_seid, teid, dl_ingress_teid)
    }

    /// Take one pending threshold-triggered usage report, if any session crossed its
    /// volume threshold since the last report. The report carries the **delta** since
    /// the previous report; taking it advances the reported watermark (so the next
    /// report starts a fresh accumulation toward the threshold).
    pub fn take_due_report(&mut self) -> Option<DueReport> {
        let s = self.sessions.values_mut().find(|s| s.report_due)?;
        s.report_due = false;
        let (ul, dl) = (s.ul_bytes - s.reported_ul, s.dl_bytes - s.reported_dl);
        s.reported_ul = s.ul_bytes;
        s.reported_dl = s.dl_bytes;
        Some(DueReport {
            cp_seid: s.cp_seid,
            usage: UsageVolume { urr_id: SESSION_URR_ID, total: ul + dl, uplink: ul, downlink: dl },
        })
    }

    /// Install the gNB downlink target for a session (from a Session Modification).
    /// Also stops buffering and **flushes** any downlink packets held while the UE
    /// was CM-IDLE — encapsulated to the new tunnel — onto the pending-flush queue.
    fn set_downlink(
        &mut self,
        up_seid: u64,
        gnb_teid: u32,
        gnb_ip: Ipv4Addr,
        send_end_marker: bool,
    ) -> bool {
        // A path switch (SNDEM requested and the downlink actually moved to a new gNB
        // tunnel): queue a GTP-U End Marker on the OLD tunnel before switching.
        if send_end_marker {
            if let Some(old) = self
                .sessions
                .get(&up_seid)
                .and_then(|s| s.downlink)
                .filter(|&old| old != (gnb_teid, gnb_ip))
            {
                self.pending_end_markers.push(old);
            }
        }
        let Some(s) = self.sessions.get_mut(&up_seid) else {
            return false;
        };
        s.downlink = Some((gnb_teid, gnb_ip));
        s.buffering = false;
        s.dl_data_report_due = false;
        let ue_ipv6 = s.ue_ipv6;
        let flushed: Vec<(u32, Ipv4Addr, Vec<u8>)> =
            s.dl_buffer.drain(..).map(|pkt| (gnb_teid, gnb_ip, pkt)).collect();
        if !flushed.is_empty() {
            self.pending_flush.extend(flushed);
        }
        // Queue an unsolicited Router Advertisement so a v6 UE can SLAAC as soon as its
        // downlink tunnel is up (design/131 Phase C) — also re-sent on a resume.
        if let Some(prefix) = ue_ipv6 {
            self.pending_ra.push((gnb_teid, gnb_ip, prefix));
        }
        true
    }

    /// Clear a session's gNB downlink target and **start buffering** (AN release /
    /// UP deactivation): downlink packets are held (and a Downlink Data Report
    /// raised on the first) instead of forwarded, until a Service Request
    /// re-installs the tunnel.
    fn clear_downlink(&mut self, up_seid: u64) -> bool {
        match self.sessions.get_mut(&up_seid) {
            Some(s) => {
                s.downlink = None;
                s.buffering = true;
                true
            }
            None => false,
        }
    }

    /// Buffer a downlink packet for a **CM-IDLE** session owning `dst` (the UE IP),
    /// raising a Downlink Data Report on the first buffered packet. Returns whether
    /// the packet was buffered (i.e. a buffering session owns `dst`).
    pub fn buffer_downlink(&mut self, dst: Ipv4Addr, pkt: &[u8]) -> bool {
        let Some(s) = self.sessions.values_mut().find(|s| s.ue_ip == Some(dst) && s.buffering) else {
            return false;
        };
        if s.dl_buffer.is_empty() {
            s.dl_data_report_due = true; // first arrival → notify the SMF (paging)
        }
        if s.dl_buffer.len() >= DL_BUFFER_CAP {
            s.dl_buffer.pop_front(); // bounded: drop the oldest
        }
        s.dl_buffer.push_back(pkt.to_vec());
        true
    }

    /// Take one pending **Downlink Data Report** (a CM-IDLE session that just
    /// received its first buffered packet), returning the SMF's F-SEID to address
    /// the Session Report to. Consumed once per idle period.
    pub fn take_dl_data_report(&mut self) -> Option<u64> {
        let s = self.sessions.values_mut().find(|s| s.dl_data_report_due)?;
        s.dl_data_report_due = false;
        Some(s.cp_seid)
    }

    /// Drain the buffered downlink packets to send on N3 after re-activations, as
    /// `(gNB TEID, gNB IP, inner IP packet)` — the caller GTP-U-encapsulates each.
    pub fn take_flush(&mut self) -> Vec<(u32, Ipv4Addr, Vec<u8>)> {
        std::mem::take(&mut self.pending_flush)
    }

    /// Drain the pending GTP-U **End Markers** to send on N3 after a downlink path
    /// switch, as the old `(gNB TEID, gNB IP)` — the caller builds
    /// [`gtpu::end_marker`] for each and sends it to the gNB's N3 address.
    pub fn take_end_markers(&mut self) -> Vec<(u32, Ipv4Addr)> {
        std::mem::take(&mut self.pending_end_markers)
    }

    /// Drain the pending unsolicited **Router Advertisements** to send on N3, as
    /// `(gNB TEID, gNB IP, /64 prefix)` — the caller builds `n6::router_advertisement`
    /// for each and GTP-U-encapsulates it toward the gNB (design/131 Phase C).
    pub fn take_pending_ra(&mut self) -> Vec<(u32, Ipv4Addr, Ipv6Addr)> {
        std::mem::take(&mut self.pending_ra)
    }

    /// For a Router Solicitation arriving on uplink `teid`: the session's /64 prefix and
    /// its installed gNB downlink target `(prefix, gNB TEID, gNB IP)`, so the caller can
    /// build + send the answering Router Advertisement. `None` if the TEID is unknown,
    /// the session has no IPv6 prefix, or its downlink isn't installed yet.
    pub fn ra_target_for_teid(&self, teid: u32) -> Option<(Ipv6Addr, u32, Ipv4Addr)> {
        let s = self.sessions.values().find(|s| s.n3_teid == teid)?;
        let prefix = s.ue_ipv6?;
        let (gnb_teid, gnb_ip) = s.downlink?;
        Some((prefix, gnb_teid, gnb_ip))
    }

    /// Whether a session owning `dst` is currently buffering (test/inspection).
    pub fn is_buffering(&self, dst: Ipv4Addr) -> bool {
        self.sessions.values().any(|s| s.ue_ip == Some(dst) && s.buffering)
    }

    /// Set/replace a session's AMBR (from a Create or Update QER), re-rating its
    /// policers to `now_nanos`. Creates the buckets if the session had none.
    fn set_ambr(&mut self, up_seid: u64, ambr: SessionAmbr, now_nanos: u64) -> bool {
        match self.sessions.get_mut(&up_seid) {
            Some(s) => {
                match &mut s.ul_bucket {
                    Some(b) => b.set_rate(ambr.uplink_bps, now_nanos),
                    None => s.ul_bucket = Some(TokenBucket::new(ambr.uplink_bps, now_nanos)),
                }
                match &mut s.dl_bucket {
                    Some(b) => b.set_rate(ambr.downlink_bps, now_nanos),
                    None => s.dl_bucket = Some(TokenBucket::new(ambr.downlink_bps, now_nanos)),
                }
                s.ambr = Some(ambr);
                true
            }
            None => false,
        }
    }

    /// Install (or replace, by QFI) a per-flow GBR policer — from a Create QER +
    /// classifier PDR, at establishment or a mid-session flow modification.
    fn add_flow(&mut self, up_seid: u64, f: FlowQer, now_nanos: u64) {
        if let Some(s) = self.sessions.get_mut(&up_seid) {
            s.flow_qers.retain(|e| e.qfi != f.qfi);
            s.flow_qers.push(FlowEnforcer {
                qfi: f.qfi,
                filter: f.filter,
                ul_bucket: TokenBucket::new(f.mfbr_ul_bps, now_nanos),
                dl_bucket: TokenBucket::new(f.mfbr_dl_bps, now_nanos),
                ul_bytes: 0,
                dl_bytes: 0,
            });
        }
    }

    /// Re-rate a per-flow policer's MFBR (a mid-session Update QER).
    fn update_flow_rate(&mut self, up_seid: u64, qfi: u8, mfbr_dl_bps: u64, mfbr_ul_bps: u64, now_nanos: u64) {
        if let Some(e) =
            self.sessions.get_mut(&up_seid).and_then(|s| s.flow_qers.iter_mut().find(|e| e.qfi == qfi))
        {
            e.ul_bucket.set_rate(mfbr_ul_bps, now_nanos);
            e.dl_bucket.set_rate(mfbr_dl_bps, now_nanos);
        }
    }

    /// Drop a per-flow policer (a mid-session Remove QER).
    fn remove_flow(&mut self, up_seid: u64, qfi: u8) {
        if let Some(s) = self.sessions.get_mut(&up_seid) {
            s.flow_qers.retain(|e| e.qfi != qfi);
        }
    }

    /// The session AMBR the UPF is enforcing for `up_seid`, if any.
    pub fn ambr_for(&self, up_seid: u64) -> Option<SessionAmbr> {
        self.sessions.get(&up_seid).and_then(|s| s.ambr)
    }

    /// The QFIs of the per-flow (GBR) policers installed for a session.
    pub fn flow_qfis(&self, up_seid: u64) -> Vec<u8> {
        self.sessions
            .get(&up_seid)
            .map(|s| s.flow_qers.iter().map(|f| f.qfi).collect())
            .unwrap_or_default()
    }

    /// Admit an uplink packet on `teid`: classify it and police it against the
    /// matched GBR flow's MFBR, else the session AMBR. `true` (admit) when the TEID
    /// is unknown here (the caller's TEID check handles that) or unlimited.
    pub fn admit_uplink(&mut self, teid: u32, now_nanos: u64, pkt: &[u8]) -> bool {
        match self.sessions.values_mut().find(|s| s.n3_teid == teid) {
            Some(s) => s.admit(true, now_nanos, pkt),
            None => true,
        }
    }

    /// Admit a downlink packet destined to UE IP `dst`: classify + police as above.
    pub fn admit_downlink(&mut self, dst: Ipv4Addr, now_nanos: u64, pkt: &[u8]) -> bool {
        match self.sessions.values_mut().find(|s| s.ue_ip == Some(dst)) {
            Some(s) => s.admit(false, now_nanos, pkt),
            None => true,
        }
    }

    /// Admit an IPv6 downlink packet destined into the /64 of the session owning
    /// `dst`: classify + police against that session's AMBR (design/131).
    pub fn admit_downlink_v6(&mut self, dst: Ipv6Addr, now_nanos: u64, pkt: &[u8]) -> bool {
        match self.sessions.values_mut().find(|s| s.ue_ipv6.is_some_and(|p| ipv6_in_prefix64(dst, p))) {
            Some(s) => s.admit(false, now_nanos, pkt),
            None => true,
        }
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

/// A **CHOOSE** uplink F-TEID (TS 29.244 §8.2.3, CH flag set): the SMF asks the UPF
/// to allocate the ingress F-TEID (TEID + its own N3 address) and report it back in
/// the Created PDR — the standard "UPF-assigned F-TEID" signal, rather than the
/// zero-address placeholder a strict UPF would (correctly) treat as SMF-assigned and
/// not allocate. (`teid(0)` is a required builder placeholder; the CH flag marks it
/// as *not* the assignment. Note: rs-pfcp still emits the 4-octet TEID field for a
/// CHOOSE F-TEID — the CH flag is the signal a peer acts on.)
fn upf_chooses_fteid() -> Fteid {
    FteidBuilder::new()
        .choose_ipv4()
        .teid(0u32)
        .build()
        .expect("build CHOOSE F-TEID")
}

/// SMF: build a PFCP Session Establishment Request for a basic PDU session. Provisions
/// two rules: an **uplink** PDR (access → forward to core) whose N3 F-TEID the UPF
/// allocates, and a **downlink** PDR matching the SMF-allocated `ue_ip` (core → forward
/// to access) whose FAR the later Session Modification points at the gNB. Carrying the
/// UE IP here is what lets the UPF route a downlink packet from N6 back to this session.
pub fn session_establishment_request(
    cp_seid: u64,
    seq: u32,
    smf_ip: Ipv4Addr,
    ue: impl Into<UeAddr>,
    dnn: &str,
    ambr: Option<SessionAmbr>,
    flows: &[FlowQer],
    usage_threshold_bytes: Option<u64>,
) -> Vec<u8> {
    let ue: UeAddr = ue.into();
    // When a session AMBR is authorized, provision a session-level QER (open gate +
    // MBR) and bind both PDRs to it, so the UPF polices the aggregate rate.
    let qer_id = ambr.map(|_| QerId::new(AMBR_QER_ID));

    let ul_pdi = PdiBuilder::uplink_access()
        .f_teid(upf_chooses_fteid()) // CHOOSE: the UPF allocates the real N3 F-TEID
        .build()
        .expect("build uplink PDI");
    let mut ul_pdr = CreatePdrBuilder::new(PdrId::new(1))
        .precedence(Precedence::new(100))
        .pdi(ul_pdi)
        .far_id(FarId::new(1))
        .urr_id(UrrId::new(SESSION_URR_ID)); // measure uplink volume
    if let Some(q) = qer_id {
        ul_pdr = ul_pdr.qer_id(q);
    }
    let ul_pdr = ul_pdr.build().expect("build uplink Create PDR");
    // Forward to the core, tagging the FAR with the session's Network Instance (the
    // DNN/APN, TS 29.244 §8.2.4) — an operator binds that name to a VRF, and a
    // downstream controller (e.g. a MUP/SRv6 mobile-backhaul) maps the session to it.
    let ul_far = CreateFar::builder(FarId::new(1))
        .forward_to_network(Interface::Core, NetworkInstance::new(dnn))
        .build()
        .expect("build uplink Create FAR");

    // Downlink: match packets destined to the UE's IPv4 address and/or its IPv6 /64
    // prefix (design/131); its FAR (id 2) is where the Session Modification installs
    // Outer Header Creation toward the gNB.
    let dl_pdi = Pdi::downlink_core_with_ue_ip(UeIpAddress::new(ue.v4, ue.v6));
    let mut dl_pdr = CreatePdrBuilder::new(PdrId::new(2))
        .precedence(Precedence::new(200))
        .pdi(dl_pdi)
        .far_id(FarId::new(2))
        .urr_id(UrrId::new(SESSION_URR_ID)); // measure downlink volume
    if let Some(q) = qer_id {
        dl_pdr = dl_pdr.qer_id(q);
    }
    let dl_pdr = dl_pdr.build().expect("build downlink Create PDR");
    let dl_far = CreateFar::builder(FarId::new(2))
        .forward_to_network(Interface::Access, NetworkInstance::new(dnn))
        .build()
        .expect("build downlink Create FAR");

    let mut create_pdrs = vec![ul_pdr.to_ie(), dl_pdr.to_ie()];
    let mut create_qers = Vec::new();
    if let Some(a) = ambr {
        let qer = CreateQer::builder(QerId::new(AMBR_QER_ID))
            .rate_limit(a.uplink_bps, a.downlink_bps)
            .build()
            .expect("build session-AMBR Create QER");
        create_qers.push(qer.to_ie());
    }

    // A session-level volume URR (measure uplink+downlink bytes; final report at
    // deletion) — both match-all PDRs reference it by id. With a usage threshold,
    // the URR also reports mid-session: crossing the threshold triggers a
    // UPF-initiated Session Report Request (VOLTH — quota-style charging).
    let triggers = ReportingTriggers::new().with_volume_threshold(usage_threshold_bytes.is_some());
    let threshold = usage_threshold_bytes
        .map(|b| VolumeThreshold::new(true, false, false, Some(b), None, None));
    let urr = CreateUrr::new(
        UrrId::new(SESSION_URR_ID),
        MeasurementMethod::new(false, true, false), // volume
        triggers,
        None,
        threshold,
        None,
        None,
        None,
        None,
    );
    let mut create_urrs = vec![urr.to_ie()];

    // Per-GBR-flow QoS: a Create QER (MFBR) + classifier PDR (SDF filter) + volume
    // URR per flow. The UPF links them by id: matched packets are policed against
    // the flow MFBR and measured under the flow's own URR.
    for f in flows {
        let (qer, pdr, urr) = flow_create_ies(f);
        create_qers.push(qer);
        create_pdrs.push(pdr);
        create_urrs.push(urr);
    }

    let mut builder = SessionEstablishmentRequestBuilder::new(0u64, seq) // header SEID 0 — UPF has none yet
        .node_id(smf_ip)
        .fseid(cp_seid, smf_ip) // CP F-SEID
        .create_pdrs(create_pdrs)
        .create_fars(vec![ul_far.to_ie(), dl_far.to_ie()])
        .create_urrs(create_urrs);
    if !create_qers.is_empty() {
        builder = builder.create_qers(create_qers);
    }
    builder.build().expect("build Session Establishment Request").marshal()
}

/// SMF: build a Session Establishment Request for an **intermediate UPF** — an I-UPF /
/// uplink classifier (design/134). Same shape as [`session_establishment_request`],
/// except the uplink FAR carries an **Outer Header Creation** toward the next UPF's N9
/// F-TEID, so decapsulated uplink leaves over N9 rather than out to N6. The downlink
/// PDR is pointed at the gNB by a later Session Modification, exactly as for an anchor.
pub fn session_establishment_request_via_peer(
    cp_seid: u64,
    seq: u32,
    smf_ip: Ipv4Addr,
    ue: impl Into<UeAddr>,
    dnn: &str,
    peer_teid: u32,
    peer_addr: Ipv4Addr,
    branches: &[(FlowFilter, Egress)],
) -> Vec<u8> {
    let ue: UeAddr = ue.into();
    // Uplink: the gNB sends here on a UPF-allocated N3 F-TEID; forward over N9 to the
    // next UPF via Outer Header Creation. The UE address rides on the *uplink* PDI here
    // (an anchor carries it on the downlink one) so the chain's first hop — the node
    // closest to the RAN — can still anti-spoof.
    let ul_pdi = PdiBuilder::uplink_access()
        .f_teid(upf_chooses_fteid())
        .ue_ip_address(UeIpAddress::new(ue.v4, ue.v6))
        .build()
        .expect("build uplink PDI");
    let ul_pdr = CreatePdrBuilder::new(PdrId::new(1))
        .precedence(Precedence::new(100))
        .pdi(ul_pdi)
        .far_id(FarId::new(UPLINK_FAR_ID))
        .build()
        .expect("build uplink Create PDR");
    let ul_params = rs_pfcp::ie::forwarding_parameters::ForwardingParameters::new(
        rs_pfcp::ie::destination_interface::DestinationInterface::new(Interface::Core),
    )
    .with_outer_header_creation(OuterHeaderCreation::gtpu_ipv4(peer_teid, peer_addr));
    let ul_far = CreateFar::builder(FarId::new(UPLINK_FAR_ID))
        .apply_action(ApplyAction::FORW)
        .forwarding_parameters(ul_params)
        .build()
        .expect("build uplink Create FAR");

    // Downlink: unlike an anchor (which matches the UE address on traffic from N6), an
    // intermediate UPF receives downlink back from the anchor over **N9** — so its
    // downlink PDR takes a CHOOSE F-TEID and the UPF reports the ingress it allocated.
    // Its FAR gains Outer Header Creation toward the gNB on the Session Modification.
    let dl_pdi = PdiBuilder::downlink_core()
        .f_teid(upf_chooses_fteid())
        .build()
        .expect("build downlink PDI");
    let dl_pdr = CreatePdrBuilder::new(PdrId::new(DOWNLINK_PDR_ID))
        .precedence(Precedence::new(200))
        .pdi(dl_pdi)
        .far_id(FarId::new(2))
        .build()
        .expect("build downlink Create PDR");
    let dl_far = CreateFar::builder(FarId::new(2))
        .forward_to_network(Interface::Access, NetworkInstance::new(dnn))
        .build()
        .expect("build downlink Create FAR");

    // Uplink-classifier branches: each is a higher-precedence classifier PDR bound to a
    // FAR of its own, so traffic it matches leaves by a different egress than the N9
    // default above — this node is then a ULCL (design/134 Phase 2).
    let mut pdrs = vec![ul_pdr.to_ie(), dl_pdr.to_ie()];
    let mut fars = vec![ul_far.to_ie(), dl_far.to_ie()];
    for (i, (filter, egress)) in branches.iter().enumerate() {
        let (pdr, far) = branch_create_ies(i, filter, *egress, dnn);
        pdrs.push(pdr);
        fars.push(far);
    }

    SessionEstablishmentRequestBuilder::new(0u64, seq)
        .node_id(smf_ip)
        .fseid(cp_seid, smf_ip)
        .create_pdrs(pdrs)
        .create_fars(fars)
        .build()
        .expect("build intermediate-UPF Session Establishment Request")
        .marshal()
}

/// SMF: build a PFCP Session Establishment Request for an **indirect data
/// forwarding** tunnel (TS 23.502 §4.9.1.3.3). One PDR matches packets arriving on
/// a UPF-allocated Access-facing F-TEID (the ingress the source gNB forwards to);
/// its FAR forwards them, with Outer Header Creation set at establishment, to the
/// **target** gNB's DL forwarding F-TEID. The UPF returns the allocated ingress
/// F-TEID in the response's Created PDR (id 1), which the AMF hands the source in
/// the Handover Command.
pub fn session_establishment_request_indirect_forwarding(
    cp_seid: u64,
    seq: u32,
    smf_ip: Ipv4Addr,
    target_teid: u32,
    target_addr: Ipv4Addr,
) -> Vec<u8> {
    let pdi = PdiBuilder::uplink_access()
        .f_teid(upf_chooses_fteid()) // CHOOSE: the UPF allocates the ingress F-TEID
        .build()
        .expect("build forwarding PDI");
    let pdr = CreatePdrBuilder::new(PdrId::new(1))
        .precedence(Precedence::new(100))
        .pdi(pdi)
        .far_id(FarId::new(1))
        .build()
        .expect("build forwarding Create PDR");
    let params = rs_pfcp::ie::forwarding_parameters::ForwardingParameters::new(
        rs_pfcp::ie::destination_interface::DestinationInterface::new(Interface::Access),
    )
    .with_outer_header_creation(OuterHeaderCreation::gtpu_ipv4(target_teid, target_addr));
    let far = CreateFar::builder(FarId::new(1))
        .apply_action(ApplyAction::FORW)
        .forwarding_parameters(params)
        .build()
        .expect("build forwarding Create FAR");
    SessionEstablishmentRequestBuilder::new(0u64, seq)
        .node_id(smf_ip)
        .fseid(cp_seid, smf_ip)
        .create_pdrs(vec![pdr.to_ie()])
        .create_fars(vec![far.to_ie()])
        .build()
        .expect("build indirect-forwarding Session Establishment Request")
        .marshal()
}

/// SMF: build a PFCP Session Modification Request that re-rates the session-AMBR
/// QER (a mid-session policy change) — an Update QER carrying the new MBR.
pub fn session_qer_update_request(up_seid: u64, seq: u32, ambr: SessionAmbr) -> Vec<u8> {
    let update_qer = UpdateQer::builder(QerId::new(AMBR_QER_ID))
        .mbr(Mbr::new(ambr.uplink_bps, ambr.downlink_bps))
        .build()
        .expect("build Update QER");
    SessionModificationRequestBuilder::new(up_seid, seq)
        .update_qers(vec![update_qer.to_ie()])
        .build()
        .marshal()
}

/// SMF: build a PFCP Session Modification Request for a **mid-session per-flow QoS
/// change** — `create` new GBR flows (Create QER + classifier PDR), `update`
/// existing flows' MFBR (Update QER), and `remove` flows by QFI (Remove QER + PDR).
pub fn session_flow_modification_request(
    up_seid: u64,
    seq: u32,
    create: &[FlowQer],
    update: &[FlowQer],
    remove_qfis: &[u8],
) -> Vec<u8> {
    let mut builder = SessionModificationRequestBuilder::new(up_seid, seq);
    if !create.is_empty() {
        let (mut qers, mut pdrs, mut urrs) = (Vec::new(), Vec::new(), Vec::new());
        for f in create {
            let (qer, pdr, urr) = flow_create_ies(f);
            qers.push(qer);
            pdrs.push(pdr);
            urrs.push(urr);
        }
        builder = builder.create_qers(qers).create_pdrs(pdrs).create_urrs(urrs);
    }
    if !update.is_empty() {
        let uqers = update
            .iter()
            .map(|f| {
                UpdateQer::builder(QerId::new(PER_FLOW_QER_BASE + u32::from(f.qfi)))
                    .mbr(Mbr::new(f.mfbr_ul_bps, f.mfbr_dl_bps))
                    .build()
                    .expect("build per-flow Update QER")
                    .to_ie()
            })
            .collect();
        builder = builder.update_qers(uqers);
    }
    if !remove_qfis.is_empty() {
        let rqers = remove_qfis
            .iter()
            .map(|q| RemoveQer::new(QerId::new(PER_FLOW_QER_BASE + u32::from(*q))).to_ie())
            .collect();
        let rpdrs = remove_qfis
            .iter()
            .map(|q| RemovePdr::new(PdrId::new(PER_FLOW_PDR_BASE + u16::from(*q))).to_ie())
            .collect();
        builder = builder.remove_qers(rqers).remove_pdrs(rpdrs);
    }
    builder.build().marshal()
}

/// SMF: build a PFCP Session Modification Request that **deactivates** the downlink
/// user-plane connection (TS 23.502 §4.2.6 AN release) — an Update FAR set to
/// **BUFF**er downlink (and notify the CP on first arrival, `NOCP`), clearing its
/// Outer Header Creation. The UPF then holds downlink for the CM-IDLE UE and raises
/// a Downlink Data Report (paging trigger) instead of dropping it. The uplink path
/// and the session persist; a Service Request re-activates via
/// [`session_modification_request`], which flushes the buffer.
pub fn session_deactivate_request(up_seid: u64, seq: u32, far_id: u32) -> Vec<u8> {
    let update_far = UpdateFar::builder(FarId::new(far_id))
        .apply_action(ApplyAction::BUFF | ApplyAction::NOCP)
        .build()
        .expect("build deactivate Update FAR");
    SessionModificationRequestBuilder::new(up_seid, seq)
        .update_fars(vec![update_far.to_ie()])
        .build()
        .marshal()
}

/// SMF: build a PFCP Session Modification Request that installs the downlink path —
/// an Update FAR carrying Outer Header Creation (GTP-U/IPv4) to the gNB's N3 F-TEID
/// (learned from the N2 PDU Session Resource Setup Response). Addressed by UP-SEID.
pub fn session_modification_request(
    up_seid: u64,
    seq: u32,
    far_id: u32,
    gnb_teid: u32,
    gnb_ip: Ipv4Addr,
    dnn: &str,
    send_end_marker: bool,
) -> Vec<u8> {
    // Re-point the downlink FAR at the gNB tunnel. Re-send the destination interface
    // (Access) and the session's Network Instance (DNN) alongside the Outer Header
    // Creation so the Update FAR is fully specified — matching free5GC and keeping
    // the DNN→VRF binding visible to a downstream controller on every update.
    let mut params = UpdateForwardingParameters::new()
        .with_destination_interface(DestinationInterface::new(Interface::Access))
        .with_network_instance(NetworkInstance::new(dnn));
    params.outer_header_creation = Some(OuterHeaderCreation::gtpu_ipv4(gnb_teid, gnb_ip));
    let update_far = UpdateFar::builder(FarId::new(far_id))
        .apply_action(ApplyAction::FORW)
        .update_forwarding_parameters(params)
        .build()
        .expect("build Update FAR");

    let mut builder =
        SessionModificationRequestBuilder::new(up_seid, seq).update_fars(vec![update_far.to_ie()]);
    // On a handover / path switch (the downlink is re-pointed from an existing gNB
    // tunnel to a new one), request a GTP-U **End Marker** via PFCPSMReq-Flags SNDEM
    // (TS 29.244 §8.2.79): the UPF marks the end of the old path before switching, so
    // the target gNB delivers downlink in order across the move.
    if send_end_marker {
        builder = builder.pfcpsm_req_flags(Ie::new(
            IeType::PfcpsmReqFlags,
            PfcpsmReqFlags::SNDEM.marshal().to_vec(),
        ));
    }
    builder.build().marshal()
}

/// SMF: build a PFCP Session Deletion Request (TS 29.244 §7.5.6) — addressed by
/// UP-SEID; the UPF drops the session and every rule provisioned under it.
pub fn session_deletion_request(up_seid: u64, seq: u32) -> Vec<u8> {
    SessionDeletionRequestBuilder::new(up_seid, seq).build().marshal()
}

/// UPF: handle an inbound N4 message, returning the response to send (if any).
/// `now_nanos` is the UPF's monotonic clock, used to base a session's AMBR
/// policers (must share the clock the datapath [`UpfState::admit_uplink`] /
/// [`UpfState::admit_downlink`] polls with).
pub fn handle_n4(
    data: &[u8],
    node_ip: Ipv4Addr,
    state: &mut UpfState,
    now_nanos: u64,
) -> Option<Vec<u8>> {
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
            // The SMF-allocated UE address(es) ride in a downlink PDR's PDI (UE IP
            // Address IE); the UPF records them to route N6 downlink traffic back to
            // this session — IPv4, an IPv6 /64 prefix, or both (design/131).
            let ue = msg
                .ies(IeType::CreatePdr)
                .filter_map(|ie| CreatePdr::unmarshal(&ie.payload).ok())
                .find_map(|pdr| {
                    pdr.pdi.ue_ip_address.map(|u| UeAddr { v4: u.ipv4_address, v6: u.ipv6_address })
                })
                .unwrap_or_default();
            // The session-AMBR Create QER carries the aggregate MBR the UPF polices.
            let ambr = msg
                .ies(IeType::CreateQer)
                .filter_map(|ie| CreateQer::unmarshal(&ie.payload).ok())
                .find(|q| q.qer_id.value == AMBR_QER_ID)
                .and_then(|q| q.mbr)
                .map(|m| SessionAmbr { uplink_bps: m.uplink, downlink_bps: m.downlink });
            // Per-flow policers: a classifier PDR (SDF filter) linked by QER id to its MFBR.
            let flows = parse_created_flows(msg.as_ref());
            // The session URR's volume threshold (total bytes), when the SMF asked
            // for mid-session usage reporting (VOLTH).
            let usage_threshold = msg
                .ies(IeType::CreateUrr)
                .filter_map(|ie| CreateUrr::unmarshal(&ie.payload).ok())
                .find(|u| u.urr_id.id == SESSION_URR_ID)
                .and_then(|u| u.volume_threshold)
                .and_then(|t| t.total_volume);
            // The uplink FAR's Outer Header Creation: when the SMF pointed this
            // session's uplink at another UPF, the traffic leaves over **N9** instead of
            // N6 (design/134 — an I-UPF / uplink classifier). Absent ⇒ this node is the
            // anchor. Until now establishment-time FARs were never read at all, so
            // indirect data forwarding (design/84) built a FAR this UPF ignored.
            let uplink = msg
                .ies(IeType::CreateFar)
                .filter_map(|ie| CreateFar::unmarshal(&ie.payload).ok())
                .find(|far| far.far_id.value == UPLINK_FAR_ID)
                .and_then(|far| far.forwarding_parameters)
                .and_then(|fp| fp.outer_header_creation)
                .and_then(|ohc| {
                    Some(Egress::ToPeer { teid: u32::from(ohc.teid?), addr: ohc.ipv4_address? })
                })
                .unwrap_or(Egress::ToN6);
            // An intermediate UPF asks for a **downlink** ingress F-TEID too: its
            // downlink PDR (id 2) carries an F-TEID rather than matching a UE address,
            // because downlink arrives back from the anchor over N9 (design/134).
            let wants_dl_ingress = msg
                .ies(IeType::CreatePdr)
                .filter_map(|ie| CreatePdr::unmarshal(&ie.payload).ok())
                .any(|pdr| pdr.pdr_id.value == DOWNLINK_PDR_ID && pdr.pdi.f_teid.is_some());
            // Uplink-classifier rules: a subset of uplink steered to its own egress
            // (design/134 Phase 2). Empty on a node that doesn't branch.
            let branches = parse_branches(msg.as_ref());
            let (up_seid, teid, dl_ingress_teid) = state.establish(
                cp_fseid.seid.into(),
                ue,
                ambr,
                &flows,
                usage_threshold,
                now_nanos,
                uplink,
                branches,
                wants_dl_ingress,
            );
            let mut builder = SessionEstablishmentResponseBuilder::new(
                cp_fseid.seid,
                seq,
                CauseValue::RequestAccepted,
            )
            .node_id(node_ip)
            .fseid(up_seid, node_ip) // UP F-SEID
            .created_pdr(CreatedPdr::new(PdrId::new(1), Fteid::ipv4(teid, node_ip)).to_ie());
            // An intermediate UPF also reports the downlink N9 ingress F-TEID it
            // allocated — the SMF hands it to the anchor as its downlink target.
            if let Some(dl) = dl_ingress_teid {
                builder = builder.created_pdr(
                    CreatedPdr::new(PdrId::new(DOWNLINK_PDR_ID), Fteid::ipv4(dl, node_ip)).to_ie(),
                );
            }
            Some(builder.build().ok()?.marshal())
        }
        MsgType::SessionModificationRequest => {
            // Addressed by UP-SEID (the header SEID the UPF handed out at establishment).
            let up_seid = u64::from(msg.seid()?);
            // PFCPSMReq-Flags SNDEM (TS 29.244 §8.2.79): on a downlink path switch the
            // SMF asks for a GTP-U End Marker on the old tunnel.
            let send_end_marker = msg
                .ies(IeType::PfcpsmReqFlags)
                .next()
                .and_then(|ie| PfcpsmReqFlags::unmarshal(&ie.payload).ok())
                .is_some_and(|f| f.contains(PfcpsmReqFlags::SNDEM));
            // A downlink Update FAR either installs the gNB tunnel (Outer Header
            // Creation → activate) or DROPs downlink (AN release → deactivate). Selected
            // by **FAR id**: a message may carry updates for several FARs, and applying
            // whichever came first would silently retarget the downlink from an uplink
            // or branch update (design/134 §4). Updating those mid-session is a Phase 3
            // concern (dynamic ULCL insertion) — for now they are ignored, not misread.
            if let Some(uf) = msg
                .ies(IeType::UpdateFar)
                .filter_map(|ie| UpdateFar::unmarshal(&ie.payload).ok())
                .find(|uf| {
                    uf.far_id.value == DOWNLINK_FAR_ID
                        && (uf.update_forwarding_parameters.is_some() || uf.apply_action.is_some())
                })
            {
                let ohc = uf
                    .update_forwarding_parameters
                    .and_then(|ufp| ufp.outer_header_creation)
                    .and_then(|ohc| Some((u32::from(ohc.teid?), ohc.ipv4_address?)));
                match ohc {
                    Some((gnb_teid, gnb_ip)) => {
                        state.set_downlink(up_seid, gnb_teid, gnb_ip, send_end_marker);
                    }
                    // No OHC + a BUFF/DROP action → deactivate the downlink (AN
                    // release): start buffering downlink for the CM-IDLE UE.
                    None if uf.apply_action.is_some_and(|a| {
                        a.contains(ApplyAction::BUFF) || a.contains(ApplyAction::DROP)
                    }) =>
                    {
                        state.clear_downlink(up_seid);
                    }
                    None => {}
                }
            }
            // Per-flow QoS changes (order matters: remove → create → update, so a
            // re-provisioned QFI ends up as its new flow).
            for rq in msg
                .ies(IeType::RemoveQer)
                .filter_map(|ie| RemoveQer::unmarshal(&ie.payload).ok())
            {
                if rq.qer_id.value != AMBR_QER_ID {
                    state.remove_flow(up_seid, rq.qer_id.value.saturating_sub(PER_FLOW_QER_BASE) as u8);
                }
            }
            for f in parse_created_flows(msg.as_ref()) {
                state.add_flow(up_seid, f, now_nanos);
            }
            // Update QERs re-rate the session AMBR (id 1) or a per-flow MFBR.
            for uq in msg
                .ies(IeType::UpdateQer)
                .filter_map(|ie| UpdateQer::unmarshal(&ie.payload).ok())
            {
                let Some(mbr) = uq.mbr else { continue };
                if uq.qer_id.value == AMBR_QER_ID {
                    state.set_ambr(
                        up_seid,
                        SessionAmbr { uplink_bps: mbr.uplink, downlink_bps: mbr.downlink },
                        now_nanos,
                    );
                } else {
                    let qfi = uq.qer_id.value.saturating_sub(PER_FLOW_QER_BASE) as u8;
                    state.update_flow_rate(up_seid, qfi, mbr.downlink, mbr.uplink, now_nanos);
                }
            }
            Some(
                SessionModificationResponseBuilder::new(up_seid, seq)
                    .cause_accepted()
                    .build()
                    .marshal(),
            )
        }
        MsgType::SessionDeletionRequest => {
            let up_seid = u64::from(msg.seid()?);
            let usages = state.remove(up_seid);
            let cause = if usages.is_some() {
                CauseValue::RequestAccepted
            } else {
                CauseValue::SessionContextNotFound
            };
            let mut builder = SessionDeletionResponseBuilder::new(up_seid, seq).cause(cause);
            // Final URR usage reports: the session-level volume plus one report per
            // per-flow URR (each GBR flow's own usage — its charging rating group).
            // Triggered by the session termination (`0x20` = TERMR).
            if let Some(usages) = usages {
                let ies = usages
                    .iter()
                    .enumerate()
                    .map(|(i, u)| {
                        // The deletion response uses a dedicated usage-report IE type.
                        Ie::new(
                            IeType::UsageReportWithinSessionDeletionResponse,
                            usage_report_for(u, (i + 1) as u32, 0x20).marshal(),
                        )
                    })
                    .collect();
                builder = builder.ies(ies);
            }
            Some(builder.build().marshal())
        }
        // A response to a UPF-initiated Session Report Request (the SMF's ack) —
        // nothing to answer.
        MsgType::SessionReportResponse => None,
        _ => None,
    }
}

/// Build one URR usage report carrying a volume measurement (`trigger`: `0x20`
/// TERMR at deletion, `0x02` VOLTH at a threshold crossing).
fn usage_report_for(u: &UsageVolume, ur_seqn: u32, trigger: u8) -> UsageReport {
    let vm = VolumeMeasurement::new(
        0b0000_0111, // TOVOL | ULVOL | DLVOL present
        Some(u.total),
        Some(u.uplink),
        Some(u.downlink),
        None,
        None,
        None,
    );
    let mut report = UsageReport::new(
        UrrId::new(u.urr_id),
        SequenceNumber::new(ur_seqn),
        UsageReportTrigger::new(trigger),
    );
    report.volume_measurement = Some(vm);
    report
}

/// UPF: build a Session Report Request carrying a **Downlink Data Report**
/// (TS 29.244 §7.5.8) — downlink data arrived for a buffering (CM-IDLE) session,
/// so the SMF should page the UE. The header SEID is the **SMF's** F-SEID.
pub fn session_report_request_dldr(cp_seid: u64, seq: u32) -> Vec<u8> {
    let report_type = ReportType::new().with_downlink_data_report(true);
    SessionReportRequestBuilder::new(cp_seid, seq)
        .report_type(Ie::new(IeType::ReportType, report_type.marshal()))
        .build()
        .marshal()
}

/// SMF: whether a Session Report Request is a **Downlink Data Report** (the paging
/// trigger). Returns `(cp_seid, seq)`; `None` for other report types (e.g. usage).
pub fn parse_dl_data_report(data: &[u8]) -> Option<(u64, u32)> {
    let msg = rs_pfcp::message::parse(data).ok()?;
    if msg.msg_type() != MsgType::SessionReportRequest {
        return None;
    }
    let rt = msg.ies(IeType::ReportType).next()?;
    if !ReportType::unmarshal(&rt.payload).ok()?.is_downlink_data_report() {
        return None;
    }
    Some((u64::from(msg.seid()?), u32::from(msg.sequence())))
}

/// UPF: build a Session Report Request carrying a threshold-triggered usage report
/// (TS 29.244 §7.5.8). The header SEID is the **SMF's** F-SEID for the session.
pub fn session_report_request(due: &DueReport, seq: u32) -> Vec<u8> {
    let report_type = ReportType::new().with_usage_report(true);
    SessionReportRequestBuilder::new(due.cp_seid, seq)
        .report_type(Ie::new(IeType::ReportType, report_type.marshal()))
        .usage_reports(vec![UsageReportSrr::new(usage_report_for(&due.usage, 1, 0x02)).to_ie()])
        .build()
        .marshal()
}

/// SMF: parse a UPF-initiated Session Report Request → `(cp_seid, seq, usage)`.
/// `None` if the message is not a usage-carrying session report.
pub fn parse_session_report_request(data: &[u8]) -> Option<(u64, u32, UsageVolume)> {
    let msg = rs_pfcp::message::parse(data).ok()?;
    if msg.msg_type() != MsgType::SessionReportRequest {
        return None;
    }
    let cp_seid = u64::from(msg.seid()?);
    let ie = msg.ies(IeType::UsageReportWithinSessionReportRequest).next()?;
    let report = UsageReport::unmarshal(&ie.payload).ok()?;
    let vm = report.volume_measurement?;
    let usage = UsageVolume {
        urr_id: report.urr_id.id,
        total: vm.total_volume?,
        uplink: vm.uplink_volume?,
        downlink: vm.downlink_volume?,
    };
    Some((cp_seid, u32::from(msg.sequence()), usage))
}

/// SMF: build the accepted Session Report Response (the ack toward the UPF; its
/// header SEID is the **UPF's** SEID for the session).
pub fn session_report_response(up_seid: u64, seq: u32) -> Vec<u8> {
    SessionReportResponseBuilder::accepted(up_seid, seq)
        .build()
        .expect("build Session Report Response")
        .marshal()
}

/// Whether a datagram is a Session Report Response (the SMF's ack to a
/// UPF-initiated usage report) — so the UPF's N4 loop can tell it from an
/// unhandled message.
pub fn is_session_report_ack(data: &[u8]) -> bool {
    rs_pfcp::message::parse(data)
        .map(|m| m.msg_type() == MsgType::SessionReportResponse)
        .unwrap_or(false)
}

/// The outcome of a Session Establishment, as the SMF reads it from the UPF response.
pub struct EstablishedSession {
    /// UP-SEID — addresses this session in later Session Modification/Deletion.
    pub up_seid: u64,
    /// The UPF-allocated N3 F-TEID (carried to the gNB in the N2 SM info).
    pub n3_teid: u32,
    pub n3_addr: Ipv4Addr,
    /// The UPF-allocated **downlink N9 ingress** F-TEID, when the session asked for one
    /// (an intermediate UPF — design/134). The SMF gives it to the anchor as that
    /// session's downlink Outer Header Creation target, so downlink flows
    /// anchor → I-UPF → gNB.
    pub dl_ingress: Option<(u32, Ipv4Addr)>,
}

/// SMF: parse a Session Establishment Response — the UP F-SEID and the UPF-allocated
/// N3 F-TEID (the Created PDR).
pub fn parse_session_establishment_response(data: &[u8]) -> Option<EstablishedSession> {
    let msg = rs_pfcp::message::parse(data).ok()?;
    if msg.msg_type() != MsgType::SessionEstablishmentResponse {
        return None;
    }
    let up_seid = u64::from(
        msg.ies(IeType::Fseid)
            .next()
            .and_then(|ie| Fseid::unmarshal(&ie.payload).ok())?
            .seid,
    );
    // A chained (intermediate) UPF reports two Created PDRs: id 1 is the uplink ingress
    // the gNB sends to, id 2 the downlink N9 ingress the anchor sends back to.
    let created: Vec<CreatedPdr> = msg
        .ies(IeType::CreatedPdr)
        .filter_map(|ie| CreatedPdr::unmarshal(&ie.payload).ok())
        .collect();
    let f_teid = created
        .iter()
        .find(|p| p.pdr_id.value == 1)
        .or_else(|| created.first())?
        .f_teid
        .clone();
    let dl_ingress = created
        .iter()
        .find(|p| p.pdr_id.value == DOWNLINK_PDR_ID)
        .and_then(|p| Some((u32::from(p.f_teid.teid), p.f_teid.ipv4_address?)));
    Some(EstablishedSession {
        up_seid,
        n3_teid: u32::from(f_teid.teid),
        n3_addr: f_teid.ipv4_address?,
        dl_ingress,
    })
}

/// A PFCP message's sequence number (responses echo the request's), for correlating
/// a received response to the request that produced it.
pub fn sequence_of(data: &[u8]) -> Option<u32> {
    Some(u32::from(rs_pfcp::message::parse(data).ok()?.sequence()))
}

/// Whether a PFCP response carries an accepted Cause (value 1 = success, TS 29.244).
pub fn response_accepted(data: &[u8]) -> bool {
    rs_pfcp::message::parse(data)
        .ok()
        .and_then(|m| {
            m.ies(IeType::Cause)
                .next()
                .and_then(|ie| ie.payload.first().copied())
        })
        .map(|v| v == 1)
        .unwrap_or(false)
}

/// SMF: parse **all** final URR usage reports (volume) from a Session Deletion
/// Response — the session-level URR plus one per per-flow URR. Empty if none.
pub fn usages_from_deletion_response(data: &[u8]) -> Vec<UsageVolume> {
    let Ok(msg) = rs_pfcp::message::parse(data) else {
        return Vec::new();
    };
    msg.ies(IeType::UsageReportWithinSessionDeletionResponse)
        .filter_map(|ie| UsageReport::unmarshal(&ie.payload).ok())
        .filter_map(|report| {
            let vm = report.volume_measurement?;
            Some(UsageVolume {
                urr_id: report.urr_id.id,
                total: vm.total_volume?,
                uplink: vm.uplink_volume?,
                downlink: vm.downlink_volume?,
            })
        })
        .collect()
}

/// SMF: the **session-level** final usage from a Session Deletion Response:
/// `(total_bytes, uplink_bytes, downlink_bytes)`. `None` if the response carries none.
pub fn usage_from_deletion_response(data: &[u8]) -> Option<(u64, u64, u64)> {
    usages_from_deletion_response(data)
        .into_iter()
        .find(|u| u.urr_id == SESSION_URR_ID)
        .map(|u| (u.total, u.uplink, u.downlink))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UE_IP: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);

    #[test]
    fn session_establishment_allocates_and_tracks() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        let req = session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None);
        let resp = handle_n4(&req, node_ip, &mut state, 0).expect("session response");

        assert_eq!(state.session_count(), 1, "UPF tracks the session");
        // The UPF learned the UE IP from the establishment (for N6 downlink routing).
        assert_eq!(state.ue_ip_for_teid(1), Some(UE_IP), "UE IP bound to the session's N3 TEID");
        let parsed = rs_pfcp::message::parse(&resp).unwrap();
        assert_eq!(parsed.msg_type(), MsgType::SessionEstablishmentResponse);
        assert_eq!(parsed.ies(IeType::CreatedPdr).count(), 1, "Created PDR with allocated F-TEID");
        assert_eq!(parsed.ies(IeType::Fseid).count(), 1, "UP F-SEID returned");
    }

    /// An IPv6 (and IPv4v6) session's /64 prefix rides the PFCP PDI and drives the UPF's
    /// downlink routing + uplink anti-spoofing by prefix membership (design/131).
    #[test]
    fn session_tracks_ipv6_prefix_and_routes_by_it() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let gnb_ip = Ipv4Addr::new(10, 0, 0, 9);
        let prefix: Ipv6Addr = "2001:db8:a:1::".parse().unwrap();
        let ue_v6: Ipv6Addr = "2001:db8:a:1::1".parse().unwrap(); // prefix::iid, in the /64
        let stranger: Ipv6Addr = "2001:db8:a:2::1".parse().unwrap(); // a different /64

        // Pure-IPv6 session: the establishment carries only the /64 prefix.
        let mut state = UpfState::new();
        let ue = UeAddr { v4: None, v6: Some(prefix) };
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, ue, "internet", None, &[], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish v6");
        // The prefix round-tripped through the PFCP PDI marshal/unmarshal.
        assert_eq!(state.ue_ipv6_for_teid(1), Some(prefix), "the /64 prefix binds to the N3 TEID");
        assert_eq!(state.ue_ip_for_teid(1), None, "a pure-IPv6 session has no IPv4");
        // No downlink route until the gNB F-TEID is installed.
        assert_eq!(state.route_downlink_v6(ue_v6), None, "no downlink before modification");
        handle_n4(
            &session_modification_request(1, 2, 2, 0x5678, gnb_ip, "internet", false),
            node_ip,
            &mut state,
            0,
        )
        .expect("modify");
        assert_eq!(
            state.route_downlink_v6(ue_v6),
            Some((0x5678, gnb_ip)),
            "a downlink to any address in the /64 routes to the session's gNB"
        );
        assert_eq!(state.route_downlink_v6(stranger), None, "an address outside the /64 is unrouted");

        // Installing the downlink queued an unsolicited Router Advertisement for SLAAC
        // (design/131 Phase C), and an RS on the uplink TEID can be answered.
        assert_eq!(
            state.take_pending_ra(),
            vec![(0x5678, gnb_ip, prefix)],
            "installing a v6 downlink queues an unsolicited RA"
        );
        assert!(state.take_pending_ra().is_empty(), "the RA queue drains once");
        assert_eq!(
            state.ra_target_for_teid(1),
            Some((prefix, 0x5678, gnb_ip)),
            "an RS on the uplink TEID resolves to the /64 + gNB target"
        );
    }

    /// An **intermediate UPF** (design/134): the establishment's uplink FAR carries an
    /// Outer Header Creation, so the session's uplink leaves over N9 toward that peer
    /// rather than out to N6. Establishment-time FARs were previously never parsed at
    /// all — which also left indirect data forwarding (design/84) silently inert.
    #[test]
    fn establishment_far_sets_an_n9_uplink_egress() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let peer = Ipv4Addr::new(127, 0, 0, 2);

        // An anchor: no Outer Header Creation on the uplink FAR → out to N6.
        let mut anchor = UpfState::new();
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None),
            node_ip,
            &mut anchor,
            0,
        )
        .expect("establish anchor");
        assert_eq!(anchor.uplink_egress_for_teid(1), Some(Egress::ToN6), "an anchor egresses to N6");

        // An intermediate UPF: the uplink FAR points at the next UPF's N9 F-TEID.
        let mut iupf = UpfState::new();
        handle_n4(
            &session_establishment_request_via_peer(
                0xCAFE, 1, node_ip, UE_IP, "internet", 0x9001, peer, &[],
            ),
            node_ip,
            &mut iupf,
            0,
        )
        .expect("establish intermediate UPF");
        assert_eq!(
            iupf.uplink_egress_for_teid(1),
            Some(Egress::ToPeer { teid: 0x9001, addr: peer }),
            "the uplink FAR's Outer Header Creation seeded the N9 egress"
        );
        // It still allocates an N3 F-TEID for the gNB and learns the UE address.
        assert_eq!(iupf.ue_ip_for_teid(1), Some(UE_IP));
        assert_eq!(iupf.uplink_egress_for_teid(99), None, "unknown TEID");
    }

    #[test]
    fn session_deletion_removes_the_session() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        handle_n4(&session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None), node_ip, &mut state, 0)
            .expect("establish");
        let up_seid = 1; // first allocation
        assert_eq!(state.session_count(), 1);

        // SMF deletes the session — TEID and N6 route go with it.
        let resp = handle_n4(&session_deletion_request(up_seid, 2), node_ip, &mut state, 0)
            .expect("deletion response");
        assert!(response_accepted(&resp), "deletion accepted");
        assert_eq!(state.session_count(), 0, "session removed");
        assert!(!state.knows_teid(1), "TEID no longer routable");
        assert_eq!(state.route_downlink(UE_IP), None, "N6 route gone");

        // Deleting an unknown session answers, but not with 'accepted'.
        let resp = handle_n4(&session_deletion_request(99, 3), node_ip, &mut state, 0)
            .expect("response for unknown session");
        assert!(!response_accepted(&resp), "unknown session is not 'accepted'");
    }

    #[test]
    fn session_modification_installs_downlink() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        handle_n4(&session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None), node_ip, &mut state, 0)
            .expect("establish");
        let up_seid = 1; // first allocation
        assert_eq!(state.downlink_for(up_seid), None, "no downlink before modification");
        assert_eq!(state.route_downlink(UE_IP), None, "no N6 route before modification");

        // SMF installs the gNB's downlink F-TEID via Session Modification.
        let gnb_ip = Ipv4Addr::new(10, 0, 0, 9);
        let resp = handle_n4(
            &session_modification_request(up_seid, 2, DOWNLINK_FAR_ID, 0x5678, gnb_ip, "internet", false),
            node_ip,
            &mut state,
            0,
        )
        .expect("modification response");

        let parsed = rs_pfcp::message::parse(&resp).unwrap();
        assert_eq!(parsed.msg_type(), MsgType::SessionModificationResponse);
        assert_eq!(
            state.downlink_for(up_seid),
            Some((0x5678, gnb_ip)),
            "UPF now knows the gNB downlink target"
        );
        // A downlink packet destined to the UE IP now routes to the gNB tunnel.
        assert_eq!(
            state.route_downlink(UE_IP),
            Some((0x5678, gnb_ip)),
            "N6 downlink routes by UE IP to the gNB target"
        );
        assert_eq!(state.route_downlink(Ipv4Addr::new(10, 45, 0, 3)), None, "unknown UE IP: no route");

        // AN release: a deactivate modification DROPs downlink and clears the route.
        handle_n4(&session_deactivate_request(up_seid, 3, DOWNLINK_FAR_ID), node_ip, &mut state, 0)
            .expect("deactivate response");
        assert_eq!(state.downlink_for(up_seid), None, "downlink target cleared on deactivation");
        assert_eq!(state.route_downlink(UE_IP), None, "no N6 route while the UE is idle");

        // The session and its uplink TEID survive — a Service Request can re-activate.
        assert_eq!(state.session_count(), 1, "session retained across deactivation");
        let resp = handle_n4(
            &session_modification_request(up_seid, 4, DOWNLINK_FAR_ID, 0x9ABC, gnb_ip, "internet", false),
            node_ip,
            &mut state,
            0,
        )
        .expect("re-activation response");
        assert!(response_accepted(&resp));
        assert_eq!(
            state.route_downlink(UE_IP),
            Some((0x9ABC, gnb_ip)),
            "re-activation re-installs the downlink route to the new gNB tunnel"
        );
    }

    #[test]
    fn network_instance_carries_the_dnn() {
        use rs_pfcp::ie::create_far::CreateFar;
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);

        // Establishment: every Create FAR's forwarding parameters tag the session's
        // DNN as the Network Instance (TS 29.244 §8.2.4) — the DNN→VRF binding a
        // downstream controller (e.g. a MUP/SRv6 backhaul) reads to originate routes.
        let est = session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None);
        let msg = rs_pfcp::message::parse(&est).expect("parse establishment");
        let nis: Vec<String> = msg
            .ies(IeType::CreateFar)
            .filter_map(|ie| CreateFar::unmarshal(&ie.payload).ok())
            .filter_map(|far| Some(far.forwarding_parameters?.network_instance?.instance))
            .collect();
        assert_eq!(
            nis,
            vec!["internet".to_string(), "internet".to_string()],
            "both the uplink (Core) and downlink (Access) FAR carry Network Instance = DNN"
        );

        // The downlink re-point (Session Modification) re-sends the Network Instance
        // and destination interface alongside the gNB Outer Header Creation.
        let gnb_ip = Ipv4Addr::new(10, 0, 9, 1);
        let modr = session_modification_request(1, 2, 2, 0x5678, gnb_ip, "internet", false);
        let msg = rs_pfcp::message::parse(&modr).expect("parse modification");
        let ufp = msg
            .ies(IeType::UpdateFar)
            .filter_map(|ie| UpdateFar::unmarshal(&ie.payload).ok())
            .find_map(|uf| uf.update_forwarding_parameters)
            .expect("Update FAR forwarding parameters");
        assert_eq!(ufp.network_instance.map(|ni| ni.instance), Some("internet".to_string()));
        assert!(ufp.destination_interface.is_some(), "destination interface re-sent (Access)");
        assert!(ufp.outer_header_creation.is_some(), "OHC toward the gNB retained");
    }

    #[test]
    fn uplink_fteid_requests_upf_allocation() {
        use rs_pfcp::ie::create_pdr::CreatePdr;
        let smf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let est = session_establishment_request(0xCAFE, 1, smf_ip, UE_IP, "internet", None, &[], None);
        let msg = rs_pfcp::message::parse(&est).expect("parse establishment");

        // The uplink PDR (id 1) carries a CHOOSE F-TEID: the SMF signals the UPF to
        // allocate the N3 F-TEID (CH set, no SMF-assigned address) — the standard
        // "UPF-assigned" request (TS 29.244 §8.2.3), not a zero-address placeholder a
        // strict UPF would treat as SMF-assigned and decline to allocate.
        let ul = msg
            .ies(IeType::CreatePdr)
            .filter_map(|ie| CreatePdr::unmarshal(&ie.payload).ok())
            .find(|pdr| pdr.pdr_id.value == 1)
            .expect("uplink Create PDR");
        let fteid = ul.pdi.f_teid.expect("uplink PDI F-TEID");
        assert!(fteid.ch, "CHOOSE flag set — the UPF allocates the N3 F-TEID");
        assert!(fteid.v4, "IPv4 F-TEID requested");
        assert_eq!(fteid.ipv4_address, None, "no SMF-assigned address (the UPF chooses)");

        // End to end: the UPF still allocates and reports the F-TEID in the Created
        // PDR, and the SMF reads it back — the handshake is unchanged, now standardly
        // signalled.
        let node_ip = Ipv4Addr::new(10, 0, 0, 8);
        let mut state = UpfState::new();
        let resp = handle_n4(&est, node_ip, &mut state, 0).expect("establish");
        let session = parse_session_establishment_response(&resp).expect("parse response");
        assert_eq!(session.n3_addr, node_ip, "the UPF reported its chosen N3 address");
        assert_ne!(session.n3_teid, 0, "the UPF allocated a non-zero N3 TEID");
    }

    #[test]
    fn end_marker_requested_only_on_a_repoint() {
        let gnb_ip = Ipv4Addr::new(10, 0, 9, 1);

        // A plain downlink install (first activation / Service-Request resume) carries
        // no PFCPSMReq-Flags — no End Marker.
        let plain = session_modification_request(1, 2, 2, 0x5678, gnb_ip, "internet", false);
        let msg = rs_pfcp::message::parse(&plain).expect("parse plain modification");
        assert!(
            msg.ies(IeType::PfcpsmReqFlags).next().is_none(),
            "no End Marker requested on a plain downlink install"
        );

        // A handover / path-switch re-point requests a GTP-U End Marker via
        // PFCPSMReq-Flags SNDEM.
        let repoint = session_modification_request(1, 3, 2, 0x9ABC, gnb_ip, "internet", true);
        let msg = rs_pfcp::message::parse(&repoint).expect("parse re-point modification");
        let flags_ie =
            msg.ies(IeType::PfcpsmReqFlags).next().expect("PFCPSMReq-Flags IE present on a re-point");
        let flags = PfcpsmReqFlags::unmarshal(&flags_ie.payload).expect("parse PFCPSMReq-Flags");
        assert!(flags.contains(PfcpsmReqFlags::SNDEM), "SNDEM (Send End Marker) is set");
    }

    #[test]
    fn upf_emits_end_marker_only_on_a_path_switch() {
        let node_ip = Ipv4Addr::new(10, 0, 0, 8);
        let mut state = UpfState::new();
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");
        let up_seid = 1;
        let gnb_a = Ipv4Addr::new(10, 0, 9, 1);
        let gnb_b = Ipv4Addr::new(10, 0, 9, 2);

        // First downlink install (no old path) — even with SNDEM, nothing to flush.
        handle_n4(&session_modification_request(up_seid, 2, DOWNLINK_FAR_ID, 0x5678, gnb_a, "internet", true), node_ip, &mut state, 0)
            .expect("first install");
        assert!(state.take_end_markers().is_empty(), "no End Marker on the first downlink install");

        // A re-point WITHOUT SNDEM — no End Marker.
        handle_n4(&session_modification_request(up_seid, 3, DOWNLINK_FAR_ID, 0x9abc, gnb_b, "internet", false), node_ip, &mut state, 0)
            .expect("re-point without SNDEM");
        assert!(state.take_end_markers().is_empty(), "no End Marker when SNDEM is unset");

        // A genuine path switch (SNDEM + a different gNB) — an End Marker for the OLD
        // (gNB B) tunnel; consumed once.
        handle_n4(&session_modification_request(up_seid, 4, DOWNLINK_FAR_ID, 0x1234, gnb_a, "internet", true), node_ip, &mut state, 0)
            .expect("path switch");
        assert_eq!(
            state.take_end_markers(),
            vec![(0x9abc, gnb_b)],
            "End Marker on the old gNB tunnel the downlink left"
        );
        assert!(state.take_end_markers().is_empty(), "drained");
    }

    #[test]
    fn establishment_qer_sets_session_ambr_and_update_re_rates_it() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        let ambr = SessionAmbr { uplink_bps: 1_000_000_000, downlink_bps: 2_000_000_000 };
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", Some(ambr), &[], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");
        let up_seid = 1;
        assert_eq!(
            state.ambr_for(up_seid),
            Some(ambr),
            "UPF recorded the session AMBR from the Create QER"
        );

        // A mid-session Update QER re-rates it (a PCF-driven policy change).
        let new = SessionAmbr { uplink_bps: 50_000_000, downlink_bps: 100_000_000 };
        handle_n4(&session_qer_update_request(up_seid, 2, new), node_ip, &mut state, 0)
            .expect("qer update");
        assert_eq!(state.ambr_for(up_seid), Some(new), "Update QER re-rated the session AMBR");
    }

    /// A classification key for a packet to `dst` with the given transport tuple.
    fn key(protocol: u8, src_port: u16, dst_port: u16, dst: impl Into<IpAddr>) -> PacketKey {
        PacketKey { protocol, src_port, dst_port, dst: dst.into() }
    }

    #[test]
    fn flow_filter_matches_and_roundtrips() {
        let anywhere = Ipv4Addr::new(8, 8, 8, 8);
        let f = FlowFilter::transport(17, 5000, 5010);
        assert!(f.matches(&key(17, 40000, 5005, anywhere)), "UDP with dst port in range");
        assert!(f.matches(&key(17, 5001, 40000, anywhere)), "UDP with src port in range");
        assert!(!f.matches(&key(6, 5005, 5005, anywhere)), "wrong protocol");
        assert!(!f.matches(&key(17, 80, 443, anywhere)), "ports out of range");
        // The flow-description carried in the PDR SDF filter round-trips.
        assert_eq!(FlowFilter::from_flow_description(&f.to_flow_description()), Some(f));
    }

    /// The ULCL classifier: a destination-prefix filter steers by *where traffic is
    /// going*, independent of the transport tuple a QoS filter looks at.
    #[test]
    fn destination_prefix_filter_matches_and_roundtrips() {
        let anywhere = Ipv4Addr::new(8, 8, 8, 8);
        let edge = FlowFilter::to_prefix(IpPrefix::new(Ipv4Addr::new(10, 99, 0, 0), 16));
        assert!(edge.matches(&key(6, 1234, 80, Ipv4Addr::new(10, 99, 5, 7))), "in the prefix");
        assert!(!edge.matches(&key(6, 1234, 80, Ipv4Addr::new(10, 98, 5, 7))), "outside it");
        assert!(
            !edge.matches(&key(6, 1234, 80, "2001:db8::1".parse::<Ipv6Addr>().unwrap())),
            "a v6 destination never matches a v4 prefix"
        );
        assert_eq!(FlowFilter::from_flow_description(&edge.to_flow_description()), Some(edge));

        // A prefix that isn't byte-aligned, and the v6 family.
        let odd = IpPrefix::new(Ipv4Addr::new(10, 0, 128, 0), 17);
        assert!(odd.contains(Ipv4Addr::new(10, 0, 200, 1).into()));
        assert!(!odd.contains(Ipv4Addr::new(10, 0, 100, 1).into()));
        let v6 = FlowFilter::to_prefix(IpPrefix::new("2001:db8:a::".parse::<Ipv6Addr>().unwrap(), 48));
        assert!(v6.matches(&key(58, 0, 0, "2001:db8:a:1::9".parse::<Ipv6Addr>().unwrap())));
        assert!(!v6.matches(&key(58, 0, 0, "2001:db8:b::9".parse::<Ipv6Addr>().unwrap())));
        assert_eq!(FlowFilter::from_flow_description(&v6.to_flow_description()), Some(v6));

        // Components compose, and a filter with none of them matches everything.
        let combined = FlowFilter {
            protocol: Some(6),
            ports: Some((80, 80)),
            dst: Some(IpPrefix::new(Ipv4Addr::new(10, 99, 0, 0), 16)),
        };
        assert!(combined.matches(&key(6, 40000, 80, Ipv4Addr::new(10, 99, 1, 1))));
        assert!(!combined.matches(&key(6, 40000, 443, Ipv4Addr::new(10, 99, 1, 1))), "wrong port");
        assert!(!combined.matches(&key(6, 40000, 80, Ipv4Addr::new(1, 1, 1, 1))), "wrong prefix");
        assert_eq!(
            FlowFilter::from_flow_description(&combined.to_flow_description()),
            Some(combined)
        );
        let any = FlowFilter { protocol: None, ports: None, dst: None };
        assert!(any.matches(&key(17, 1, 2, anywhere)), "an empty filter matches everything");
        assert_eq!(FlowFilter::from_flow_description(""), Some(any));
    }

    /// A Session Modification is applied to the FAR it names. Before design/134 Phase 2
    /// the UPF took whichever Update FAR came first, so an update aimed at the uplink or
    /// a branch FAR would have silently retargeted the downlink.
    #[test]
    fn session_modification_applies_to_the_named_far() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");

        // An update for the *uplink* FAR must not install a downlink target.
        let gnb = Ipv4Addr::new(10, 0, 0, 9);
        let wrong = session_modification_request(1, 2, UPLINK_FAR_ID, 0x5678, gnb, "internet", false);
        assert!(response_accepted(&handle_n4(&wrong, node_ip, &mut state, 0).expect("accepted")));
        assert_eq!(state.downlink_for(1), None, "an uplink-FAR update leaves the downlink alone");

        // The same message against the downlink FAR does install it.
        let right =
            session_modification_request(1, 3, DOWNLINK_FAR_ID, 0x5678, gnb, "internet", false);
        assert!(response_accepted(&handle_n4(&right, node_ip, &mut state, 0).expect("accepted")));
        assert_eq!(state.downlink_for(1), Some((0x5678, gnb)));
    }

    /// The classifier reads the destination out of both IP families.
    #[test]
    fn packet_key_reads_both_families() {
        let v4 = udp_packet(1111, 2222, 40);
        let k = packet_key(&v4).expect("v4 key");
        assert_eq!((k.protocol, k.src_port, k.dst_port), (17, 1111, 2222));
        assert_eq!(k.dst, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));

        let mut v6 = vec![0u8; 48];
        v6[0] = 0x60; // IPv6
        v6[6] = 17; // next header = UDP
        v6[24..40].copy_from_slice(&"2001:db8:a::9".parse::<Ipv6Addr>().unwrap().octets());
        v6[40..42].copy_from_slice(&3333u16.to_be_bytes());
        v6[42..44].copy_from_slice(&4444u16.to_be_bytes());
        let k = packet_key(&v6).expect("v6 key");
        assert_eq!((k.protocol, k.src_port, k.dst_port), (17, 3333, 4444));
        assert_eq!(k.dst, IpAddr::V6("2001:db8:a::9".parse().unwrap()));

        assert!(packet_key(&[0u8; 8]).is_none(), "truncated / non-IP");
    }

    /// A UDP packet from `src_port` to `dst_port`, padded to `total_len` bytes.
    fn udp_packet(src_port: u16, dst_port: u16, total_len: usize) -> Vec<u8> {
        udp_packet_to(Ipv4Addr::new(203, 0, 113, 5), src_port, dst_port, total_len)
    }

    /// As [`udp_packet`] but addressed to `dst` — for classifying on destination.
    fn udp_packet_to(dst: Ipv4Addr, src_port: u16, dst_port: u16, total_len: usize) -> Vec<u8> {
        let mut p = vec![0u8; total_len.max(28)];
        p[0] = 0x45; // IPv4, IHL 5
        p[9] = 17; // UDP
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&src_port.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    #[test]
    fn per_flow_qer_polices_matched_flow_independently() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        // Big session AMBR (1/2 Gbps) + a small per-flow GBR QER (80 kbps, UDP 5000–5010).
        let ambr = SessionAmbr { uplink_bps: 1_000_000_000, downlink_bps: 2_000_000_000 };
        let flow = FlowQer {
            qfi: 2,
            filter: FlowFilter::transport(17, 5000, 5010),
            mfbr_dl_bps: 80_000,
            mfbr_ul_bps: 80_000,
        };
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", Some(ambr), &[flow], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");
        let up_seid = 1;
        let teid = 1;
        assert_eq!(state.flow_qfis(up_seid), vec![2], "the per-flow QER is installed");

        // Traffic matching the flow (UDP :5005) is policed by the 80 kbps MFBR: a
        // 10-packet burst (1000 bytes each = 80_000 bits) then throttle.
        let matched = udp_packet(40000, 5005, 1000);
        for i in 0..10 {
            assert!(state.admit_uplink(teid, 0, &matched), "matched packet {i} within MFBR burst");
        }
        assert_eq!(state.admit_uplink(teid, 0, &matched), false, "per-flow MFBR exhausted");

        // Non-matching traffic (UDP :9999) rides the session AMBR — unaffected by the
        // exhausted per-flow bucket.
        let other = udp_packet(40000, 9999, 1000);
        assert!(state.admit_uplink(teid, 0, &other), "non-GBR traffic still admitted on the session AMBR");
    }

    #[test]
    fn indirect_forwarding_session_allocates_an_ingress_fteid() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        // The SMF sets up a forwarding tunnel toward the target gNB's DL
        // forwarding F-TEID (0x99 @ 10.0.9.6); the UPF allocates the ingress F-TEID
        // the source will forward to, and returns it in the establishment response.
        let target = Ipv4Addr::new(10, 0, 9, 6);
        let resp = handle_n4(
            &session_establishment_request_indirect_forwarding(0xF00D, 7, node_ip, 0x99, target),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish forwarding");
        let session = parse_session_establishment_response(&resp).expect("response parses");
        assert_ne!(session.n3_teid, 0, "the UPF allocated an ingress F-TEID");
        assert_eq!(session.n3_addr, node_ip);
        // The forwarding session tears down like any other (Session Deletion).
        let del = session_deletion_request(session.up_seid, 8);
        let del_resp = handle_n4(&del, node_ip, &mut state, 0).expect("delete forwarding");
        assert!(response_accepted(&del_resp));
    }

    #[test]
    fn mid_session_per_flow_create_update_remove() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        let (up_seid, teid) = (1u64, 1u32);
        // Establish with one GBR flow (QFI 2, UDP 5000–5010, 80 kbps).
        let f2 = FlowQer {
            qfi: 2,
            filter: FlowFilter::transport(17, 5000, 5010),
            mfbr_dl_bps: 80_000,
            mfbr_ul_bps: 80_000,
        };
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[f2], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");
        assert_eq!(state.flow_qfis(up_seid), vec![2]);

        // Mid-session: add QFI 3 and re-rate QFI 2 up to 800 kbps.
        let f3 = FlowQer {
            qfi: 3,
            filter: FlowFilter::transport(17, 6000, 6010),
            mfbr_dl_bps: 160_000,
            mfbr_ul_bps: 160_000,
        };
        let f2_fast = FlowQer { mfbr_dl_bps: 800_000, mfbr_ul_bps: 800_000, ..f2 };
        handle_n4(
            &session_flow_modification_request(up_seid, 2, &[f3], &[f2_fast], &[]),
            node_ip,
            &mut state,
            0,
        )
        .expect("modify");
        let mut qfis = state.flow_qfis(up_seid);
        qfis.sort();
        assert_eq!(qfis, vec![2, 3], "QFI 3 added");

        // QFI 2 now polices at 800 kbps: at t=1s a 50-packet (400_000-bit) burst
        // passes — impossible under the old 80 kbps rate (≤10 packets).
        let p2 = udp_packet(40000, 5005, 1000);
        let now = 1_000_000_000;
        for i in 0..50 {
            assert!(state.admit_uplink(teid, now, &p2), "re-rated flow admits packet {i}");
        }

        // Remove QFI 3; its traffic then falls through to the (unset) session AMBR.
        handle_n4(
            &session_flow_modification_request(up_seid, 3, &[], &[], &[3]),
            node_ip,
            &mut state,
            0,
        )
        .expect("remove");
        assert_eq!(state.flow_qfis(up_seid), vec![2], "QFI 3 removed");
        let p3 = udp_packet(40000, 6005, 1000);
        assert!(state.admit_uplink(teid, now, &p3), "removed flow's traffic no longer policed per-flow");
    }

    #[test]
    fn urr_measures_volume_and_reports_at_deletion() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");
        let (up_seid, teid) = (1u64, 1u32);

        // Forward 3×1000-byte uplink + 2×500-byte downlink (no AMBR → all admitted).
        for _ in 0..3 {
            assert!(state.admit_uplink(teid, 0, &udp_packet(1, 2, 1000)));
        }
        for _ in 0..2 {
            assert!(state.admit_downlink(UE_IP, 0, &udp_packet(1, 2, 500)));
        }

        // Deletion returns the final volume usage report.
        let resp = handle_n4(&session_deletion_request(up_seid, 2), node_ip, &mut state, 0)
            .expect("delete");
        assert!(response_accepted(&resp));
        assert_eq!(
            usage_from_deletion_response(&resp),
            Some((4000, 3000, 1000)),
            "(total, uplink, downlink) bytes"
        );
    }

    #[test]
    fn an_release_buffers_downlink_reports_and_flushes_on_resume() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        handle_n4(&session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], None), node_ip, &mut state, 0)
            .expect("establish");
        let up_seid = 1u64;
        let gnb = Ipv4Addr::new(10, 0, 0, 9);
        handle_n4(&session_modification_request(up_seid, 2, DOWNLINK_FAR_ID, 0x5678, gnb, "internet", false), node_ip, &mut state, 0)
            .expect("activate downlink");

        // AN release → the session buffers downlink (not drops).
        handle_n4(&session_deactivate_request(up_seid, 3, DOWNLINK_FAR_ID), node_ip, &mut state, 0).expect("deactivate");
        assert!(state.is_buffering(UE_IP), "session buffering while CM-IDLE");
        assert_eq!(state.route_downlink(UE_IP), None, "no tunnel while idle");

        // Two downlink packets arrive → buffered; the first raises one DL data report.
        assert!(state.buffer_downlink(UE_IP, &[1u8; 40]));
        assert!(state.buffer_downlink(UE_IP, &[2u8; 40]));
        assert_eq!(state.take_dl_data_report(), Some(0xCAFE), "report addressed by the SMF F-SEID");
        assert_eq!(state.take_dl_data_report(), None, "only one report per idle period");
        assert!(state.take_flush().is_empty(), "nothing to flush while still idle");
        // A packet for an unknown UE isn't buffered.
        assert!(!state.buffer_downlink(Ipv4Addr::new(10, 45, 0, 9), &[0u8; 40]));

        // Service Request resume: re-installing the downlink flushes the buffer to
        // the new gNB tunnel.
        handle_n4(&session_modification_request(up_seid, 4, DOWNLINK_FAR_ID, 0x9ABC, gnb, "internet", false), node_ip, &mut state, 0)
            .expect("re-activate");
        assert!(!state.is_buffering(UE_IP), "no longer buffering after resume");
        let flushed = state.take_flush();
        assert_eq!(flushed.len(), 2, "both buffered packets flushed");
        assert!(flushed.iter().all(|(teid, ip, _)| *teid == 0x9ABC && *ip == gnb), "to the new tunnel");
    }

    #[test]
    fn dl_data_report_wire_round_trips() {
        let req = session_report_request_dldr(0xBEEF, 9);
        assert_eq!(parse_dl_data_report(&req), Some((0xBEEF, 9)));
        // A usage report is NOT a downlink data report, and vice versa.
        let usage = session_report_request(
            &DueReport { cp_seid: 0xBEEF, usage: UsageVolume { urr_id: 1, total: 10, uplink: 10, downlink: 0 } },
            9,
        );
        assert_eq!(parse_dl_data_report(&usage), None);
        assert!(parse_session_report_request(&req).is_none());
    }

    #[test]
    fn per_flow_urrs_measure_and_report_at_deletion() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        // One GBR flow (QFI 2, UDP 5000–5010) with an MFBR far above the traffic.
        let f2 = FlowQer {
            qfi: 2,
            filter: FlowFilter::transport(17, 5000, 5010),
            mfbr_dl_bps: 100_000_000,
            mfbr_ul_bps: 100_000_000,
        };
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[f2], None),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");
        let (up_seid, teid) = (1u64, 1u32);

        // 2×1000 bytes on the GBR flow (UDP :5005) + 3×500 bytes off-flow uplink.
        for _ in 0..2 {
            assert!(state.admit_uplink(teid, 0, &udp_packet(40000, 5005, 1000)));
        }
        for _ in 0..3 {
            assert!(state.admit_uplink(teid, 0, &udp_packet(40000, 9999, 500)));
        }

        // Deletion reports both URRs; each byte is counted under exactly ONE of
        // them (the rating groups partition the traffic — summing them never
        // double-bills).
        let resp = handle_n4(&session_deletion_request(up_seid, 2), node_ip, &mut state, 0)
            .expect("delete");
        let mut usages = usages_from_deletion_response(&resp);
        usages.sort_by_key(|u| u.urr_id);
        assert_eq!(
            usages,
            vec![
                UsageVolume { urr_id: SESSION_URR_ID, total: 1500, uplink: 1500, downlink: 0 },
                UsageVolume { urr_id: PER_FLOW_URR_BASE + 2, total: 2000, uplink: 2000, downlink: 0 },
            ],
            "the flow URR counts its matched traffic; the session URR the rest"
        );
    }

    #[test]
    fn volume_threshold_triggers_a_session_report() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        // Session URR with a 2500-byte volume threshold (VOLTH reporting).
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, "internet", None, &[], Some(2500)),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");
        let teid = 1u32;

        // 2×1000 bytes — under the threshold, nothing due yet.
        for _ in 0..2 {
            assert!(state.admit_uplink(teid, 0, &udp_packet(1, 2, 1000)));
        }
        assert!(state.take_due_report().is_none(), "2000 < 2500 — no report yet");

        // The 3rd packet crosses the threshold → one report, carrying the delta.
        assert!(state.admit_uplink(teid, 0, &udp_packet(1, 2, 1000)));
        let due = state.take_due_report().expect("threshold crossed");
        assert_eq!(due.cp_seid, 0xCAFE, "addressed by the SMF's F-SEID");
        assert_eq!(
            due.usage,
            UsageVolume { urr_id: SESSION_URR_ID, total: 3000, uplink: 3000, downlink: 0 }
        );
        assert!(state.take_due_report().is_none(), "taking the report clears it");

        // The wire round-trip: UPF builds the Session Report Request, the SMF parses
        // it and acks with an accepted Session Report Response.
        let req = session_report_request(&due, 7);
        let (cp_seid, seq, usage) = parse_session_report_request(&req).expect("parse report");
        assert_eq!((cp_seid, seq), (0xCAFE, 7));
        assert_eq!(usage, due.usage);
        assert!(response_accepted(&session_report_response(1, seq)));

        // The next threshold crossing reports a fresh delta (not cumulative).
        for _ in 0..3 {
            assert!(state.admit_uplink(teid, 0, &udp_packet(1, 2, 1000)));
        }
        let again = state.take_due_report().expect("second crossing");
        assert_eq!(again.usage.total, 3000, "delta since the previous report");
    }

    #[test]
    fn token_bucket_admits_burst_then_throttles_then_refills() {
        let mut b = TokenBucket::new(80_000, 0); // 80 kbps → 80_000-bit burst
        assert!(b.poll(0, 10_000), "10_000 bytes = 80_000 bits = the full burst");
        assert!(!b.poll(0, 1), "bucket now empty");
        // 100 ms later, 8_000 bits (1000 bytes) refill.
        assert!(b.poll(100_000_000, 1000));
        assert!(!b.poll(100_000_000, 1), "and no more");
        // rate 0 means unlimited.
        let mut u = TokenBucket::new(0, 0);
        assert!(u.poll(0, 1_000_000));
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
                if let Some(resp) = handle_n4(&buf[..n], upf_ip, &mut state, 0) {
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
            round_trip(&smf, &mut buf, session_establishment_request(0x1234, 3, upf_ip, UE_IP, "internet", None, &[], None)).await,
            MsgType::SessionEstablishmentResponse
        );
    }
}
