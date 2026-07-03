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
use rs_pfcp::ie::update_far::UpdateFar;
use rs_pfcp::ie::update_forwarding_parameters::UpdateForwardingParameters;
use rs_pfcp::ie::update_qer::UpdateQer;
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
        now_nanos: u64,
    ) -> (u64, u32) {
        let up_seid = self.next_seid;
        let teid = self.next_teid;
        self.next_seid += 1;
        self.next_teid += 1;
        let ul_bucket = ambr.map(|a| TokenBucket::new(a.uplink_bps, now_nanos));
        let dl_bucket = ambr.map(|a| TokenBucket::new(a.downlink_bps, now_nanos));
        self.sessions
            .insert(up_seid, Session { n3_teid: teid, ue_ip, downlink: None, ambr, ul_bucket, dl_bucket });
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

    /// The session AMBR the UPF is enforcing for `up_seid`, if any.
    pub fn ambr_for(&self, up_seid: u64) -> Option<SessionAmbr> {
        self.sessions.get(&up_seid).and_then(|s| s.ambr)
    }

    /// Admit an uplink packet of `bytes` on `teid` against the session's uplink
    /// AMBR policer. `true` (admit) when the TEID is unknown here (the caller's
    /// TEID check handles that) or the direction is unlimited.
    pub fn admit_uplink(&mut self, teid: u32, now_nanos: u64, bytes: usize) -> bool {
        match self.sessions.values_mut().find(|s| s.n3_teid == teid) {
            Some(s) => s.ul_bucket.as_mut().is_none_or(|b| b.poll(now_nanos, bytes)),
            None => true,
        }
    }

    /// Admit a downlink packet of `bytes` destined to UE IP `dst` against the
    /// session's downlink AMBR policer.
    pub fn admit_downlink(&mut self, dst: Ipv4Addr, now_nanos: u64, bytes: usize) -> bool {
        match self.sessions.values_mut().find(|s| s.ue_ip == Some(dst)) {
            Some(s) => s.dl_bucket.as_mut().is_none_or(|b| b.poll(now_nanos, bytes)),
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

    let mut builder = SessionEstablishmentRequestBuilder::new(0u64, seq) // header SEID 0 — UPF has none yet
        .node_id(smf_ip)
        .fseid(cp_seid, smf_ip) // CP F-SEID
        .create_pdrs(vec![ul_pdr.to_ie(), dl_pdr.to_ie()])
        .create_fars(vec![ul_far.to_ie(), dl_far.to_ie()]);
    if let Some(a) = ambr {
        let qer = CreateQer::builder(QerId::new(AMBR_QER_ID))
            .rate_limit(a.uplink_bps, a.downlink_bps)
            .build()
            .expect("build session-AMBR Create QER");
        builder = builder.create_qers(vec![qer.to_ie()]);
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
            // A session-AMBR Create QER (if any) carries the MBR the UPF polices.
            let ambr = msg
                .ies(IeType::CreateQer)
                .filter_map(|ie| CreateQer::unmarshal(&ie.payload).ok())
                .find_map(|q| q.mbr)
                .map(|m| SessionAmbr { uplink_bps: m.uplink, downlink_bps: m.downlink });
            let (up_seid, teid) = state.establish(ue_ip, ambr, now_nanos);
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
            // Re-rate the session-AMBR policer from an Update QER's MBR (a
            // mid-session policy change from the SMF).
            if let Some(mbr) = msg
                .ies(IeType::UpdateQer)
                .next()
                .and_then(|ie| UpdateQer::unmarshal(&ie.payload).ok())
                .and_then(|uq| uq.mbr)
            {
                state.set_ambr(
                    up_seid,
                    SessionAmbr { uplink_bps: mbr.uplink, downlink_bps: mbr.downlink },
                    now_nanos,
                );
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
        let req = session_establishment_request(0xCAFE, 1, node_ip, UE_IP, None);
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
        handle_n4(&session_establishment_request(0xCAFE, 1, node_ip, UE_IP, None), node_ip, &mut state, 0)
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
        handle_n4(&session_establishment_request(0xCAFE, 1, node_ip, UE_IP, None), node_ip, &mut state, 0)
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
            &session_establishment_request(0xCAFE, 1, node_ip, UE_IP, Some(ambr)),
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
            round_trip(&smf, &mut buf, session_establishment_request(0x1234, 3, upf_ip, UE_IP, None)).await,
            MsgType::SessionEstablishmentResponse
        );
    }
}
