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
use rs_pfcp::ie::create_pdr::{CreatePdr, CreatePdrBuilder};
use rs_pfcp::ie::created_pdr::CreatedPdr;
use rs_pfcp::ie::destination_interface::Interface;
use rs_pfcp::ie::f_teid::Fteid;
use rs_pfcp::ie::far_id::FarId;
use rs_pfcp::ie::fseid::Fseid;
use rs_pfcp::ie::pdi::{Pdi, PdiBuilder};
use rs_pfcp::ie::pdr_id::PdrId;
use rs_pfcp::ie::precedence::Precedence;
use rs_pfcp::ie::ue_ip_address::UeIpAddress;
use rs_pfcp::ie::apply_action::ApplyAction;
use rs_pfcp::ie::create_qer::CreateQer;
use rs_pfcp::ie::mbr::Mbr;
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
use rs_pfcp::message::Message;

/// Default N4 PFCP UDP port (TS 29.244).
pub const N4_PORT: u16 = 8805;

/// The QER id the session-AMBR QER carries (one session-level QER per session).
const AMBR_QER_ID: u32 = 1;
/// A GBR flow's per-flow QER id is `PER_FLOW_QER_BASE + qfi` (distinct from the
/// session-AMBR QER), and its classifier PDR id is `PER_FLOW_PDR_BASE + index`.
const PER_FLOW_QER_BASE: u32 = 1000;
const PER_FLOW_PDR_BASE: u16 = 100;

/// A compact packet classifier for a QoS flow: transport protocol + a port range,
/// matched against **either** endpoint — a greenfield stand-in for a full TS 29.244
/// SDF filter (a production UPF parses IPFilterRule syntax). Carried in the PDR's
/// SDF filter field as a self-described `flow_description`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowFilter {
    pub protocol: u8,
    pub port_low: u16,
    pub port_high: u16,
}

impl FlowFilter {
    /// Whether a packet with transport `(protocol, src_port, dst_port)` matches.
    fn matches(&self, protocol: u8, src_port: u16, dst_port: u16) -> bool {
        protocol == self.protocol
            && ((self.port_low..=self.port_high).contains(&src_port)
                || (self.port_low..=self.port_high).contains(&dst_port))
    }

    /// Encode as the PDR SDF filter's flow-description string.
    fn to_flow_description(self) -> String {
        format!("proto={};ports={}-{}", self.protocol, self.port_low, self.port_high)
    }

    /// Parse a flow-description written by [`to_flow_description`].
    fn from_flow_description(s: &str) -> Option<Self> {
        let (mut protocol, mut ports) = (None, None);
        for part in s.split(';') {
            let (k, v) = part.split_once('=')?;
            match k {
                "proto" => protocol = v.parse().ok(),
                "ports" => {
                    let (lo, hi) = v.split_once('-')?;
                    ports = Some((lo.parse().ok()?, hi.parse().ok()?));
                }
                _ => {}
            }
        }
        let (port_low, port_high) = ports?;
        Some(FlowFilter { protocol: protocol?, port_low, port_high })
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

/// A per-flow policer at the UPF: the classifier + its MFBR token buckets.
struct FlowEnforcer {
    #[allow(dead_code)] // retained for tracing/inspection
    qfi: u8,
    filter: FlowFilter,
    ul_bucket: TokenBucket,
    dl_bucket: TokenBucket,
}

/// Extract `(protocol, src_port, dst_port)` from a bare IPv4 packet for flow
/// classification. Ports are 0 for protocols that don't carry them. `None` if the
/// packet is not IPv4 or is truncated.
fn transport_key(pkt: &[u8]) -> Option<(u8, u16, u16)> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let protocol = pkt[9];
    // TCP (6), UDP (17), SCTP (132) carry ports in the first 4 L4-header bytes.
    let (src_port, dst_port) = match protocol {
        6 | 17 | 132 if pkt.len() >= ihl + 4 => (
            u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
            u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
        ),
        _ => (0, 0),
    };
    Some((protocol, src_port, dst_port))
}

/// The Create QER + classifier Create PDR (SDF filter) IEs for one per-flow QER —
/// used at establishment and in a mid-session flow modification. The QER id is
/// `PER_FLOW_QER_BASE + qfi` and the PDR id `PER_FLOW_PDR_BASE + qfi` (both stable
/// per QFI, so a later modification can update or remove them).
fn flow_create_ies(f: &FlowQer) -> (Ie, Ie) {
    let flow_qer_id = QerId::new(PER_FLOW_QER_BASE + u32::from(f.qfi));
    let qer = CreateQer::builder(flow_qer_id)
        .rate_limit(f.mfbr_ul_bps, f.mfbr_dl_bps)
        .build()
        .expect("build per-flow Create QER");
    let flow_pdi = PdiBuilder::uplink_access()
        .sdf_filter(SdfFilter::new(&f.filter.to_flow_description()))
        .build()
        .expect("build per-flow PDI");
    let pdr = CreatePdrBuilder::new(PdrId::new(PER_FLOW_PDR_BASE + u16::from(f.qfi)))
        .precedence(Precedence::new(50)) // higher precedence than the match-all PDRs
        .pdi(flow_pdi)
        .far_id(FarId::new(1))
        .qer_id(flow_qer_id)
        .build()
        .expect("build per-flow Create PDR");
    (qer.to_ie(), pdr.to_ie())
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
    ue_ip: Option<Ipv4Addr>,
    downlink: Option<(u32, Ipv4Addr)>,
    /// Session AMBR (from a Create/Update QER), when provisioned.
    ambr: Option<SessionAmbr>,
    /// Per-direction AMBR policers. `None` ⇒ that direction is unlimited.
    ul_bucket: Option<TokenBucket>,
    dl_bucket: Option<TokenBucket>,
    /// Per-GBR-flow policers (MFBR), checked by classifier before the session AMBR.
    flow_qers: Vec<FlowEnforcer>,
}

impl Session {
    /// Admit `pkt` in the given direction: classify it to a GBR flow and police it
    /// against that flow's MFBR, else against the session AMBR. `true` = forward.
    fn admit(&mut self, uplink: bool, now_nanos: u64, pkt: &[u8]) -> bool {
        let bytes = pkt.len();
        let flow_idx = transport_key(pkt)
            .and_then(|(p, s, d)| self.flow_qers.iter().position(|f| f.filter.matches(p, s, d)));
        let bucket: Option<&mut TokenBucket> = match flow_idx {
            Some(i) if uplink => Some(&mut self.flow_qers[i].ul_bucket),
            Some(i) => Some(&mut self.flow_qers[i].dl_bucket),
            None if uplink => self.ul_bucket.as_mut(),
            None => self.dl_bucket.as_mut(),
        };
        bucket.is_none_or(|b| b.poll(now_nanos, bytes))
    }
}

/// Minimal UPF state: the N3 F-TEID and UP-SEID allocators plus a session table
/// (UP-SEID → [`Session`]).
pub struct UpfState {
    next_teid: u32,
    next_seid: u64,
    sessions: HashMap<u64, Session>,
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

    /// Whether any session owns this N3 TEID (used by the GTP-U datapath to route
    /// an uplink G-PDU to a known session).
    pub fn knows_teid(&self, teid: u32) -> bool {
        self.sessions.values().any(|s| s.n3_teid == teid)
    }

    /// The gNB downlink target `(TEID, IP)` for a session, once a Session Modification
    /// has installed it. The GTP-U datapath uses it to encapsulate downlink packets.
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

    /// The UE IP assigned to the session owning this uplink N3 TEID — the uplink datapath
    /// uses it to verify a decapsulated packet's source is the UE it claims to be (a basic
    /// anti-spoofing guard). `None` if the TEID is unknown or no UE IP was assigned.
    pub fn ue_ip_for_teid(&self, teid: u32) -> Option<Ipv4Addr> {
        self.sessions
            .values()
            .find(|s| s.n3_teid == teid)
            .and_then(|s| s.ue_ip)
    }

    /// Allocate a UP-SEID + N3 TEID for a new session and record it (with the
    /// SMF-allocated UE IP, if the establishment carried one).
    /// Remove a session (PFCP Session Deletion) — its TEID and UE-IP routes go
    /// with it. Returns whether the session existed.
    fn remove(&mut self, up_seid: u64) -> bool {
        self.sessions.remove(&up_seid).is_some()
    }

    fn establish(
        &mut self,
        ue_ip: Option<Ipv4Addr>,
        ambr: Option<SessionAmbr>,
        flows: &[FlowQer],
        now_nanos: u64,
    ) -> (u64, u32) {
        let up_seid = self.next_seid;
        let teid = self.next_teid;
        self.next_seid += 1;
        self.next_teid += 1;
        let ul_bucket = ambr.map(|a| TokenBucket::new(a.uplink_bps, now_nanos));
        let dl_bucket = ambr.map(|a| TokenBucket::new(a.downlink_bps, now_nanos));
        let flow_qers = flows
            .iter()
            .map(|f| FlowEnforcer {
                qfi: f.qfi,
                filter: f.filter,
                ul_bucket: TokenBucket::new(f.mfbr_ul_bps, now_nanos),
                dl_bucket: TokenBucket::new(f.mfbr_dl_bps, now_nanos),
            })
            .collect();
        self.sessions.insert(
            up_seid,
            Session { n3_teid: teid, ue_ip, downlink: None, ambr, ul_bucket, dl_bucket, flow_qers },
        );
        (up_seid, teid)
    }

    /// Install the gNB downlink target for a session (from a Session Modification).
    fn set_downlink(&mut self, up_seid: u64, gnb_teid: u32, gnb_ip: Ipv4Addr) -> bool {
        match self.sessions.get_mut(&up_seid) {
            Some(s) => {
                s.downlink = Some((gnb_teid, gnb_ip));
                true
            }
            None => false,
        }
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

/// SMF: build a PFCP Session Establishment Request for a basic PDU session. Provisions
/// two rules: an **uplink** PDR (access → forward to core) whose N3 F-TEID the UPF
/// allocates, and a **downlink** PDR matching the SMF-allocated `ue_ip` (core → forward
/// to access) whose FAR the later Session Modification points at the gNB. Carrying the
/// UE IP here is what lets the UPF route a downlink packet from N6 back to this session.
pub fn session_establishment_request(
    cp_seid: u64,
    seq: u32,
    smf_ip: Ipv4Addr,
    ue_ip: Ipv4Addr,
    ambr: Option<SessionAmbr>,
    flows: &[FlowQer],
) -> Vec<u8> {
    // When a session AMBR is authorized, provision a session-level QER (open gate +
    // MBR) and bind both PDRs to it, so the UPF polices the aggregate rate.
    let qer_id = ambr.map(|_| QerId::new(AMBR_QER_ID));

    let ul_pdi = PdiBuilder::uplink_access()
        .f_teid(Fteid::ipv4(0, smf_ip)) // placeholder; the UPF allocates the real N3 F-TEID
        .build()
        .expect("build uplink PDI");
    let mut ul_pdr = CreatePdrBuilder::new(PdrId::new(1))
        .precedence(Precedence::new(100))
        .pdi(ul_pdi)
        .far_id(FarId::new(1));
    if let Some(q) = qer_id {
        ul_pdr = ul_pdr.qer_id(q);
    }
    let ul_pdr = ul_pdr.build().expect("build uplink Create PDR");
    let ul_far = CreateFar::builder(FarId::new(1))
        .forward_to(Interface::Core)
        .build()
        .expect("build uplink Create FAR");

    // Downlink: match packets destined to the UE's IP; its FAR (id 2) is where the
    // Session Modification installs Outer Header Creation toward the gNB.
    let dl_pdi = Pdi::downlink_core_with_ue_ip(UeIpAddress::new(Some(ue_ip), None));
    let mut dl_pdr = CreatePdrBuilder::new(PdrId::new(2))
        .precedence(Precedence::new(200))
        .pdi(dl_pdi)
        .far_id(FarId::new(2));
    if let Some(q) = qer_id {
        dl_pdr = dl_pdr.qer_id(q);
    }
    let dl_pdr = dl_pdr.build().expect("build downlink Create PDR");
    let dl_far = CreateFar::builder(FarId::new(2))
        .forward_to(Interface::Access)
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
    // Per-GBR-flow QoS: a Create QER (MFBR) + a classifier PDR (SDF filter) per flow.
    // The UPF links them by QER id and polices matched packets against the flow MFBR.
    for f in flows {
        let (qer, pdr) = flow_create_ies(f);
        create_qers.push(qer);
        create_pdrs.push(pdr);
    }

    let mut builder = SessionEstablishmentRequestBuilder::new(0u64, seq) // header SEID 0 — UPF has none yet
        .node_id(smf_ip)
        .fseid(cp_seid, smf_ip) // CP F-SEID
        .create_pdrs(create_pdrs)
        .create_fars(vec![ul_far.to_ie(), dl_far.to_ie()]);
    if !create_qers.is_empty() {
        builder = builder.create_qers(create_qers);
    }
    builder.build().expect("build Session Establishment Request").marshal()
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
        let (mut qers, mut pdrs) = (Vec::new(), Vec::new());
        for f in create {
            let (qer, pdr) = flow_create_ies(f);
            qers.push(qer);
            pdrs.push(pdr);
        }
        builder = builder.create_qers(qers).create_pdrs(pdrs);
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

/// SMF: build a PFCP Session Modification Request that installs the downlink path —
/// an Update FAR carrying Outer Header Creation (GTP-U/IPv4) to the gNB's N3 F-TEID
/// (learned from the N2 PDU Session Resource Setup Response). Addressed by UP-SEID.
pub fn session_modification_request(
    up_seid: u64,
    seq: u32,
    far_id: u32,
    gnb_teid: u32,
    gnb_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut params = UpdateForwardingParameters::new();
    params.outer_header_creation = Some(OuterHeaderCreation::gtpu_ipv4(gnb_teid, gnb_ip));
    let update_far = UpdateFar::builder(FarId::new(far_id))
        .apply_action(ApplyAction::FORW)
        .update_forwarding_parameters(params)
        .build()
        .expect("build Update FAR");

    SessionModificationRequestBuilder::new(up_seid, seq)
        .update_fars(vec![update_far.to_ie()])
        .build()
        .marshal()
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
            // The SMF-allocated UE IP rides in a downlink PDR's PDI (UE IP Address IE);
            // the UPF records it to route N6 downlink traffic back to this session.
            let ue_ip = msg
                .ies(IeType::CreatePdr)
                .filter_map(|ie| CreatePdr::unmarshal(&ie.payload).ok())
                .find_map(|pdr| pdr.pdi.ue_ip_address.and_then(|u| u.ipv4_address));
            // The session-AMBR Create QER carries the aggregate MBR the UPF polices.
            let ambr = msg
                .ies(IeType::CreateQer)
                .filter_map(|ie| CreateQer::unmarshal(&ie.payload).ok())
                .find(|q| q.qer_id.value == AMBR_QER_ID)
                .and_then(|q| q.mbr)
                .map(|m| SessionAmbr { uplink_bps: m.uplink, downlink_bps: m.downlink });
            // Per-flow policers: a classifier PDR (SDF filter) linked by QER id to its MFBR.
            let flows = parse_created_flows(msg.as_ref());
            let (up_seid, teid) = state.establish(ue_ip, ambr, &flows, now_nanos);
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
        MsgType::SessionModificationRequest => {
            // Addressed by UP-SEID (the header SEID the UPF handed out at establishment).
            let up_seid = u64::from(msg.seid()?);
            // Install the gNB downlink target from the Update FAR's Outer Header Creation.
            if let Some((gnb_teid, gnb_ip)) = msg
                .ies(IeType::UpdateFar)
                .next()
                .and_then(|ie| UpdateFar::unmarshal(&ie.payload).ok())
                .and_then(|uf| uf.update_forwarding_parameters)
                .and_then(|ufp| ufp.outer_header_creation)
                .and_then(|ohc| Some((u32::from(ohc.teid?), ohc.ipv4_address?)))
            {
                state.set_downlink(up_seid, gnb_teid, gnb_ip);
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
            let cause = if state.remove(up_seid) {
                CauseValue::RequestAccepted
            } else {
                CauseValue::SessionContextNotFound
            };
            Some(
                SessionDeletionResponseBuilder::new(up_seid, seq)
                    .cause(cause)
                    .build()
                    .marshal(),
            )
        }
        _ => None,
    }
}

/// The outcome of a Session Establishment, as the SMF reads it from the UPF response.
pub struct EstablishedSession {
    /// UP-SEID — addresses this session in later Session Modification/Deletion.
    pub up_seid: u64,
    /// The UPF-allocated N3 F-TEID (carried to the gNB in the N2 SM info).
    pub n3_teid: u32,
    pub n3_addr: Ipv4Addr,
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
    let f_teid = msg
        .ies(IeType::CreatedPdr)
        .next()
        .and_then(|ie| CreatedPdr::unmarshal(&ie.payload).ok())?
        .f_teid;
    Some(EstablishedSession {
        up_seid,
        n3_teid: u32::from(f_teid.teid),
        n3_addr: f_teid.ipv4_address?,
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

#[cfg(test)]
mod tests {
    use super::*;

    const UE_IP: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);

    #[test]
    fn session_establishment_allocates_and_tracks() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        let req = session_establishment_request(0xCAFE, 1, node_ip, UE_IP, None, &[]);
        let resp = handle_n4(&req, node_ip, &mut state, 0).expect("session response");

        assert_eq!(state.session_count(), 1, "UPF tracks the session");
        // The UPF learned the UE IP from the establishment (for N6 downlink routing).
        assert_eq!(state.ue_ip_for_teid(1), Some(UE_IP), "UE IP bound to the session's N3 TEID");
        let parsed = rs_pfcp::message::parse(&resp).unwrap();
        assert_eq!(parsed.msg_type(), MsgType::SessionEstablishmentResponse);
        assert_eq!(parsed.ies(IeType::CreatedPdr).count(), 1, "Created PDR with allocated F-TEID");
        assert_eq!(parsed.ies(IeType::Fseid).count(), 1, "UP F-SEID returned");
    }

    #[test]
    fn session_deletion_removes_the_session() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        handle_n4(&session_establishment_request(0xCAFE, 1, node_ip, UE_IP, None, &[]), node_ip, &mut state, 0)
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
        handle_n4(&session_establishment_request(0xCAFE, 1, node_ip, UE_IP, None, &[]), node_ip, &mut state, 0)
            .expect("establish");
        let up_seid = 1; // first allocation
        assert_eq!(state.downlink_for(up_seid), None, "no downlink before modification");
        assert_eq!(state.route_downlink(UE_IP), None, "no N6 route before modification");

        // SMF installs the gNB's downlink F-TEID via Session Modification.
        let gnb_ip = Ipv4Addr::new(10, 0, 0, 9);
        let resp = handle_n4(
            &session_modification_request(up_seid, 2, 1, 0x5678, gnb_ip),
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
    }

    #[test]
    fn establishment_qer_sets_session_ambr_and_update_re_rates_it() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        let ambr = SessionAmbr { uplink_bps: 1_000_000_000, downlink_bps: 2_000_000_000 };
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, Some(ambr), &[]),
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

    #[test]
    fn flow_filter_matches_and_roundtrips() {
        let f = FlowFilter { protocol: 17, port_low: 5000, port_high: 5010 };
        assert!(f.matches(17, 40000, 5005), "UDP with dst port in range");
        assert!(f.matches(17, 5001, 40000), "UDP with src port in range");
        assert!(!f.matches(6, 5005, 5005), "wrong protocol");
        assert!(!f.matches(17, 80, 443), "ports out of range");
        // The flow-description carried in the PDR SDF filter round-trips.
        assert_eq!(FlowFilter::from_flow_description(&f.to_flow_description()), Some(f));
    }

    /// A UDP packet from `src_port` to `dst_port`, padded to `total_len` bytes.
    fn udp_packet(src_port: u16, dst_port: u16, total_len: usize) -> Vec<u8> {
        let mut p = vec![0u8; total_len.max(28)];
        p[0] = 0x45; // IPv4, IHL 5
        p[9] = 17; // UDP
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
            filter: FlowFilter { protocol: 17, port_low: 5000, port_high: 5010 },
            mfbr_dl_bps: 80_000,
            mfbr_ul_bps: 80_000,
        };
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, Some(ambr), &[flow]),
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
    fn mid_session_per_flow_create_update_remove() {
        let node_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mut state = UpfState::new();
        let (up_seid, teid) = (1u64, 1u32);
        // Establish with one GBR flow (QFI 2, UDP 5000–5010, 80 kbps).
        let f2 = FlowQer {
            qfi: 2,
            filter: FlowFilter { protocol: 17, port_low: 5000, port_high: 5010 },
            mfbr_dl_bps: 80_000,
            mfbr_ul_bps: 80_000,
        };
        handle_n4(
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, None, &[f2]),
            node_ip,
            &mut state,
            0,
        )
        .expect("establish");
        assert_eq!(state.flow_qfis(up_seid), vec![2]);

        // Mid-session: add QFI 3 and re-rate QFI 2 up to 800 kbps.
        let f3 = FlowQer {
            qfi: 3,
            filter: FlowFilter { protocol: 17, port_low: 6000, port_high: 6010 },
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
            round_trip(&smf, &mut buf, session_establishment_request(0x1234, 3, upf_ip, UE_IP, None, &[])).await,
            MsgType::SessionEstablishmentResponse
        );
    }
}
