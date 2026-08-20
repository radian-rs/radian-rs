//! `Nsmf_PDUSession` (TS 29.502) over the N4 (PFCP) datapath.
//!
//! The SMF is an SBI **server** (the AMF calls it) and a PFCP **client** (it drives
//! the UPF). On `CreateSMContext` it runs an N4 Session Establishment and returns the
//! UPF-allocated N3 F-TEID (which the AMF puts in the N2 SM info for the gNB); on
//! `UpdateSMContext` — after the gNB's F-TEID comes back in the N2 PDU Session Resource
//! Setup Response — it runs an N4 Session Modification to install the downlink path.
//!
//! Request/response bodies are simplified: TS 29.502 uses multipart with binary N1/N2
//! SM containers, which arrive with the NAS-SM and N2-SM-info slices.

use sbi_core::otel::Traced;
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::topology::{NodeKind, Topology};

/// FAR id the downlink Update FAR targets. Establishment provisions FAR 2 (downlink,
/// forward to Access); the Session Modification points it at the gNB with Outer Header
/// Creation. (FAR 1 is the uplink FAR, forward to Core.)
const FAR_ID: u32 = 2;

/// The SMF allocates UE IPv4 addresses from this /16. `.1` is the UPF's N6 gateway
/// (see nf-upf), so UEs start at `.2`. In a real deployment this is DNN/slice-scoped and
/// coordinated with the UPF's N6 subnet; here one pool suffices.
const UE_IP_POOL_START: u32 = 0x0A2D_0002; // 10.45.0.2
/// Exclusive upper bound of the IPv4 pool: `10.45.0.0/16` ends at the broadcast
/// `10.45.255.255` (`0x0A2D_FFFF`), so the last usable address is `10.45.255.254`.
const UE_IP_POOL_END: u32 = 0x0A2D_FFFF;

/// The SMF hands each IPv6/IPv4v6 PDU session a unique **/64** from `2001:db8::/32`
/// (the /64 index is the full per-session `u32` counter in the 3rd+4th hextets, so the
/// space matches the IPv4 pool and can't truncate) plus an interface identifier.
/// TS 23.501 §5.8.2.2 (one /64 per PDU session). The UPF's N6 gateway covers this /32.
const UE_IPV6_PREFIX_32: [u8; 4] = [0x20, 0x01, 0x0d, 0xb8];

/// A lazy-reuse allocator over a contiguous `[start, end)` range of `u32`s
/// (design/137 G6, mirroring free5gc's `lazyReusePool`). Allocation prefers a
/// previously returned value, so a long-lived SMF **reuses** freed addresses
/// instead of leaking the range; otherwise it takes the next never-used value
/// until the range is exhausted, when it returns `None` (→ the session is refused
/// for insufficient resources). `freed` is a set, so a double-release is a no-op
/// and the same address can never be handed to two live sessions.
struct U32Pool {
    /// The lowest never-yet-allocated value (the high-water mark).
    next: u32,
    /// Exclusive upper bound of the range.
    end: u32,
    /// Returned values, reused before the high-water mark advances.
    freed: std::collections::BTreeSet<u32>,
}

impl U32Pool {
    fn new(start: u32, end: u32) -> Self {
        Self { next: start, end, freed: std::collections::BTreeSet::new() }
    }

    /// The next free value: a returned one (lowest first) if any, else a fresh one
    /// from the high-water mark. `None` when the range is exhausted.
    fn alloc(&mut self) -> Option<u32> {
        if let Some(v) = self.freed.pop_first() {
            return Some(v);
        }
        (self.next < self.end).then(|| {
            let v = self.next;
            self.next += 1;
            v
        })
    }

    /// Return `v` to the pool. Ignored unless it was actually allocated (`v < next`);
    /// the set membership makes a repeated release idempotent.
    fn release(&mut self, v: u32) {
        if v < self.next {
            self.freed.insert(v);
        }
    }
}

/// This SMF's stable NF instance id — the `smfInstanceId` in every UECM
/// smf-registration.
static SMF_INSTANCE_ID: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(sbi_core::new_nf_instance_id);

/// The **intermediate-UPF leg** of a chained session (design/134): a second N4
/// session, on the I-UPF, that sits between the RAN and the anchor.
#[derive(Clone, Copy, Debug)]
struct ChainedLeg {
    /// UP-SEID of the I-UPF's N4 session — addresses it on modification/deletion.
    up_seid: u64,
    /// The I-UPF's **N9 downlink ingress** — the anchor's downlink egress target, so
    /// downlink runs anchor → I-UPF. Re-installed on every re-activation, since an AN
    /// release parks the anchor's downlink in BUFF.
    dl_ingress: (u32, Ipv4Addr),
    /// The **breakout anchor**'s N4 session, when the I-UPF is classifying a prefix off
    /// to a second PSA (design/134 Phase 2). It shares `dl_ingress` with the default
    /// anchor — one return path serves both.
    breakout_seid: Option<u64>,
}

/// Per-PDU-session SMF state.
struct SmContext {
    /// UP-SEID — addresses the session toward the **anchor** UPF.
    up_seid: u64,
    /// CP F-SEID — how a UPF-initiated Session Report Request addresses this
    /// session back to us.
    cp_seid: u64,
    /// UPF-allocated uplink N3 F-TEID + its node address — carried to the gNB in the
    /// N2 SM info at establishment and again on a Service Request re-activation. This
    /// is the **RAN-facing** node: the I-UPF's ingress when the session is chained.
    n3_teid: u32,
    n3_addr: Ipv4Addr,
    /// The intermediate-UPF leg when the session is chained (design/134); `None` for a
    /// single-UPF session. When set, the downlink FAR the gNB target goes into lives on
    /// *this* leg, not on `up_seid`.
    chain: Option<ChainedLeg>,
    /// The UP path this session was established on (design/134 Phase 3b): the anchor peer,
    /// plus the intermediate and breakout peers when chained. Resolved once from the DNN
    /// at establishment and held here so modification/deletion address the very UPFs the
    /// session was built on, not an SMF-global default — which is what makes per-DNN path
    /// selection work.
    path: SessionPath,
    /// The UE's assigned IPv4 address (its PDU session address). Present for IPv4 /
    /// IPv4v6 sessions; `None` for a pure-IPv6 session (design/131).
    ue_ip: Option<Ipv4Addr>,
    /// The selected PDU session type — echoed on a Service Request resume.
    pdu_type: nas::PduSessionType,
    /// The assigned IPv6 `(/64 prefix, interface identifier)` for IPv6 / IPv4v6
    /// sessions (design/131). `None` for IPv4-only.
    ue_ipv6: Option<(std::net::Ipv6Addr, [u8; 8])>,
    /// The DNN this session is for — carried as the PFCP **Network Instance** on the
    /// forwarding rules (establishment + every downlink re-point), the name an
    /// operator binds to a VRF.
    dnn: String,
    /// The slice serving this session — re-sent in the activate response.
    snssai: Snssai,
    /// gNB downlink target, once `UpdateSMContext` installs it. Cleared on AN
    /// release (deactivation).
    gnb: Option<(u32, Ipv4Addr)>,
    /// An **indirect data forwarding** tunnel's UP-SEID, set up for an N2 handover
    /// (source → UPF → target). `None` when no forwarding is in place; released
    /// when the handover completes or fails.
    indirect_fwd: Option<u64>,
    /// Subscriber + session identity, for the UECM smf-registration teardown.
    supi: String,
    pdu_session_id: u8,
    /// The PCF SM policy association `(pcf_base, policy_id)`, when a PCF drove the
    /// policy — deleted at release (Npcf_SMPolicyControl_Delete), re-authorized on
    /// refresh (Npcf_SMPolicyControl_Update). `None` when the session used the
    /// sm-data fallback.
    sm_policy: Option<(String, String)>,
    /// The current authorized QoS (session AMBR + flows) — the sm-context's policy
    /// record, refreshed by an Update.
    policy: sbi_core::npcf::SmPolicyDecision,
    /// GFBR `(downlink, uplink)` bits/sec this session reserved (GFBR admission) —
    /// released at teardown, adjusted on a mid-session policy change.
    reserved_gfbr: (u64, u64),
    /// Whether the session's live breakout was installed by the **SM policy** (an AF
    /// influence, design/135 Phase 2). Only such a breakout is reconciled away when the
    /// influence disappears — a breakout inserted directly (OAM / a NEF without a PCF) is
    /// not in the policy, so a refresh must not tear it down.
    policy_breakout: bool,
    /// The Nchf charging data session `(chf_base, charging_ref)`, when a CHF was
    /// discovered at establishment — updated with each relayed usage report,
    /// released with the final usage at teardown. `None` ⇒ no charging.
    charging: Option<(String, String)>,
}

/// One **N4 association**: its own socket, sequence space and pending-transaction map.
/// Two UPFs cannot share these — their PFCP sequence numbers would collide in a single
/// pending map — which is why multi-UPF is a peer refactor rather than a parameter
/// (design/134).
struct N4Peer {
    sock: Arc<UdpSocket>,
    /// In-flight transactions on *this* association: sequence number → the waiting
    /// response channel (shared with the reader task).
    pending: Arc<Mutex<HashMap<u32, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    seq: AtomicU32,
    /// The UPF's last-known **recovery timestamp** (its start time), learned from the
    /// Association Setup / Heartbeat response. A heartbeat reporting a *newer* value
    /// means the UPF restarted and lost every session (design/137 G4).
    recovery: Mutex<Option<SystemTime>>,
}

/// What a UPF's just-reported recovery timestamp means relative to what we knew.
#[derive(Debug, PartialEq, Eq)]
enum Recovery {
    /// First timestamp learned (association), or unchanged since — nothing to do.
    Unchanged,
    /// A newer timestamp than before — the UPF restarted since we last heard from it.
    Restarted,
}

impl N4Peer {
    /// Bind a client socket connected to `upf_n4` and spawn its reader task: responses
    /// are correlated to their transaction by sequence number; UPF-initiated Session
    /// Reports go to `reports_tx` when the caller wants them. Only the anchor is
    /// provisioned with URRs, so only the anchor reports — an intermediate UPF is
    /// connected with `None`.
    async fn connect(
        upf_n4: SocketAddr,
        reports_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    ) -> std::io::Result<Arc<Self>> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(upf_n4).await?;
        let sock = Arc::new(sock);
        let pending: Arc<Mutex<HashMap<u32, tokio::sync::oneshot::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        {
            let (sock, pending) = (sock.clone(), pending.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let Ok(n) = sock.recv(&mut buf).await else { break };
                    let datagram = buf[..n].to_vec();
                    // A UPF-initiated Session Report (usage threshold or downlink
                    // data) — hand it to the report handler.
                    if pfcp::parse_session_report_request(&datagram).is_some()
                        || pfcp::parse_dl_data_report(&datagram).is_some()
                    {
                        match &reports_tx {
                            Some(tx) => {
                                if tx.send(datagram).is_err() {
                                    break;
                                }
                            }
                            // An intermediate UPF carries no URRs, so a report from one
                            // is unexpected — drop it rather than answer it on the wrong
                            // association.
                            None => tracing::warn!("N4 report from a peer with no URRs — dropped"),
                        }
                        continue;
                    }
                    // Otherwise a response: wake the transaction waiting on its seq.
                    // (A stale response — e.g. to a timed-out request — is dropped.)
                    if let Some(seq) = pfcp::sequence_of(&datagram)
                        && let Some(tx) = pending.lock().unwrap().remove(&seq)
                    {
                        let _ = tx.send(datagram);
                    }
                }
            });
        }
        Ok(Arc::new(Self { sock, pending, seq: AtomicU32::new(1), recovery: Mutex::new(None) }))
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Record a recovery timestamp reported by the UPF and classify it: the first one
    /// (or an equal/older one, which a well-behaved UPF never sends) is [`Recovery::Unchanged`];
    /// a strictly newer one is [`Recovery::Restarted`] — the UPF came back up and its
    /// session state is gone (design/137 G4).
    fn note_recovery(&self, reported: SystemTime) -> Recovery {
        let mut known = self.recovery.lock().unwrap();
        let restarted = matches!(*known, Some(prev) if reported > prev);
        // Always advance to the latest we've seen.
        if known.is_none_or(|prev| reported >= prev) {
            *known = Some(reported);
        }
        if restarted {
            Recovery::Restarted
        } else {
            Recovery::Unchanged
        }
    }

    /// Send one PFCP request on this association and await *its* response — correlated
    /// by sequence number. 2s overall; on timeout the pending entry is withdrawn.
    async fn transact(&self, req: &[u8], expect_seq: u32) -> Option<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().unwrap().insert(expect_seq, tx);
        if self.sock.send(req).await.is_err() {
            self.pending.lock().unwrap().remove(&expect_seq);
            return None;
        }
        match tokio::time::timeout(Duration::from_secs(2), rx).await {
            Ok(Ok(resp)) => Some(resp),
            _ => {
                self.pending.lock().unwrap().remove(&expect_seq);
                None
            }
        }
    }

    /// PFCP Association Setup toward this UPF — required before any session. Records
    /// the UPF's recovery timestamp as the baseline for later restart detection.
    async fn associate(&self, smf_ip: Ipv4Addr) -> anyhow::Result<()> {
        let seq = self.next_seq();
        let req = pfcp::association_setup_request(smf_ip, seq);
        let resp = self
            .transact(&req, seq)
            .await
            .ok_or_else(|| anyhow::anyhow!("no PFCP association response from UPF"))?;
        anyhow::ensure!(pfcp::response_accepted(&resp), "UPF rejected PFCP association");
        if let Some(ts) = pfcp::parse_recovery_timestamp(&resp) {
            self.note_recovery(ts);
        }
        Ok(())
    }

    /// Send one PFCP Heartbeat Request and classify the UPF's reported recovery
    /// timestamp (design/137 G4). `None` if the UPF didn't answer (a lost heartbeat
    /// isn't itself treated as a restart — the next one will catch a real one).
    async fn heartbeat(&self) -> Option<Recovery> {
        let seq = self.next_seq();
        let resp = self.transact(&pfcp::heartbeat_request(seq), seq).await?;
        let ts = pfcp::parse_recovery_timestamp(&resp)?;
        Some(self.note_recovery(ts))
    }
}

/// The user-plane topology this SMF drives (design/134). Assembled from environment
/// variables today; Phase 3 replaces that with a real `upNodes`/`links` config.
#[derive(Debug, Clone, Copy)]
pub struct UserPlane {
    /// The **anchor** (PSA) every session terminates on by default.
    pub anchor: SocketAddr,
    /// An **intermediate** UPF in front of the anchor: every session is then chained
    /// gNB → I-UPF → N9 → anchor → N6.
    pub intermediate: Option<SocketAddr>,
    /// A **second anchor** and the destination prefix steered to it — the uplink
    /// classifier (Phase 2). Requires `intermediate`: the ULCL is the node the RAN
    /// tunnels to, so it is the only one that sees uplink before it has been committed
    /// to an anchor. Ignored without one.
    pub breakout: Option<(SocketAddr, pfcp::IpPrefix)>,
}

impl UserPlane {
    /// One anchor; the gNB tunnels straight to it.
    pub fn single(anchor: SocketAddr) -> Self {
        Self { anchor, intermediate: None, breakout: None }
    }

    /// An intermediate UPF chained in front of the anchor over N9.
    pub fn chained(anchor: SocketAddr, intermediate: SocketAddr) -> Self {
        Self { anchor, intermediate: Some(intermediate), breakout: None }
    }

    /// Steer `prefix` to a second anchor, making the intermediate UPF a ULCL.
    pub fn with_breakout(mut self, psa2: SocketAddr, prefix: pfcp::IpPrefix) -> Self {
        self.breakout = Some((psa2, prefix));
        self
    }
}

/// The user-plane path a session runs on — the peers it addresses across its lifetime.
/// Resolved once from the DNN at establishment (see [`SmfState::resolve_path`]) and held
/// on the [`SmContext`], so every later operation reaches the very UPFs the session was
/// built on rather than an SMF-global default (design/134 Phase 3b).
#[derive(Clone)]
struct SessionPath {
    /// The anchor (PSA): terminates N6, carries the URRs, so it is the node that reports
    /// usage and can be paged. Its socket also acks that session's Session Reports.
    anchor: Arc<N4Peer>,
    /// An intermediate UPF (I-UPF) chained in front of the anchor over N9, when the path
    /// has one; `None` for a single-UPF session.
    intermediate: Option<Arc<N4Peer>>,
    /// A breakout anchor + the destination prefix the classifier steers to it (Phase 2).
    breakout: Option<(Arc<N4Peer>, pfcp::IpPrefix)>,
}

impl SessionPath {
    /// Whether this path runs on `peer` (as anchor, intermediate, or breakout) —
    /// used to find the sessions a restarted UPF stranded (design/137 G4).
    fn uses(&self, peer: &Arc<N4Peer>) -> bool {
        Arc::ptr_eq(&self.anchor, peer)
            || self.intermediate.as_ref().is_some_and(|p| Arc::ptr_eq(p, peer))
            || self.breakout.as_ref().is_some_and(|(p, _)| Arc::ptr_eq(p, peer))
    }
}

/// How the SMF turns a DNN into a [`SessionPath`].
enum Routing {
    /// Env-var topology (design/134 Phases 1–2): every session takes the same path,
    /// regardless of DNN. The strings key into [`SmfState::peers`].
    Fixed { anchor: String, intermediate: Option<String>, breakout: Option<(String, pfcp::IpPrefix)> },
    /// A config-file UP topology (Phase 3b): the path — anchor, and any intermediate — is
    /// selected per DNN by walking the graph. Breakout is not yet expressed in config, so
    /// a graph-routed session has none.
    Graph(Topology),
}

/// SMF runtime: PFCP client(s) toward the user plane plus the SM-context table.
pub struct SmfState {
    smf_ip: Ipv4Addr,
    /// NRF base URL — used to discover the UDM for Nudm_SDM subscription fetches.
    nrf_base: String,
    /// Every UPF the topology names, keyed by node name → its N4 association. In env-var
    /// mode the names are synthetic (`anchor`/`intermediate`/`breakout`); in config mode
    /// they are the `upNodes` keys. [`Routing`] turns a DNN into a subset of these.
    peers: BTreeMap<String, Arc<N4Peer>>,
    /// How a DNN maps to a [`SessionPath`] over `peers` — fixed (env vars) or graph-walked
    /// (config, design/134 Phase 3b).
    routing: Routing,
    /// UPF-initiated Session Report Requests, consumed by
    /// [`handle_usage_reports`].
    reports_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    cp_seid: AtomicU64,
    next_ref: AtomicU64,
    /// UE IPv4 address pool (`10.45.0.2 ..= 10.45.255.254`), lazily reused so a
    /// released session's address is handed back out rather than leaked (design/137 G6).
    ue_ipv4_pool: Mutex<U32Pool>,
    /// UE IPv6 /64-index pool (the index seeds both the /64 prefix and the interface
    /// identifier). Starts at 1 so no session gets the `::0` identifier; reused on release.
    ue_ipv6_pool: Mutex<U32Pool>,
    contexts: Mutex<HashMap<String, SmContext>>,
    /// GFBR admission control: the guaranteed-bit-rate budget `(downlink, uplink)`
    /// in bits/sec and the currently reserved total. A session whose GBR flows'
    /// aggregate GFBR would exceed the remaining budget is refused (5GSM #26).
    gfbr_budget_bps: (u64, u64),
    reserved_gfbr_bps: Mutex<(u64, u64)>,
    /// Usage-reporting volume threshold (bytes): provisioned on each session's URR
    /// so the UPF reports mid-session usage (VOLTH) — the charging trigger.
    /// `None` ⇒ usage is only reported at session deletion.
    usage_threshold_bytes: Option<u64>,
    /// How other NFs reach this SMF's SBI surface — baked into the SM policy
    /// `notificationUri` so a PCF-initiated re-authorization (an AF influence landing,
    /// design/135 Phase 2b) finds its way back to the right SM context.
    callback_base: String,
}

impl SmfState {
    /// Bind an N4 client socket to each node of `up` — the anchor, plus an intermediate
    /// UPF and/or a second anchor when the topology has them (design/134). Every session
    /// then takes this same fixed path, regardless of DNN.
    ///
    /// Each peer gets its own socket, sequence space and pending map; only the anchor
    /// carries URRs, so only its reader forwards Session Reports.
    pub async fn connect(
        up: UserPlane,
        smf_ip: Ipv4Addr,
        nrf_base: impl Into<String>,
    ) -> std::io::Result<Self> {
        let (reports_tx, reports_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut peers = BTreeMap::new();
        peers.insert("anchor".to_string(), N4Peer::connect(up.anchor, Some(reports_tx)).await?);
        let intermediate = match up.intermediate {
            Some(addr) => {
                peers.insert("intermediate".to_string(), N4Peer::connect(addr, None).await?);
                Some("intermediate".to_string())
            }
            None => None,
        };
        // A breakout anchor is only reachable *through* the classifier, so it is
        // meaningless without an intermediate UPF to host it.
        let breakout = match (&intermediate, up.breakout) {
            (Some(_), Some((addr, prefix))) => {
                peers.insert("breakout".to_string(), N4Peer::connect(addr, None).await?);
                Some(("breakout".to_string(), prefix))
            }
            (None, Some(_)) => {
                tracing::warn!("a breakout anchor needs an intermediate UPF — ignoring it");
                None
            }
            _ => None,
        };
        let routing = Routing::Fixed { anchor: "anchor".to_string(), intermediate, breakout };
        Ok(Self::with_peers(peers, routing, reports_rx, smf_ip, nrf_base.into()))
    }

    /// Bind an N4 client socket to every UPF in a config-file topology (design/134
    /// Phase 3b). Anchors — UPFs that serve a DNN — carry URRs, so their readers forward
    /// Session Reports; pure intermediates connect with none. The DNN → path mapping is
    /// then graph-walked per session.
    pub async fn connect_with_topology(
        topo: Topology,
        smf_ip: Ipv4Addr,
        nrf_base: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let (reports_tx, reports_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut peers = BTreeMap::new();
        for (name, node) in &topo.up_nodes {
            if node.kind != NodeKind::Upf {
                continue; // the AN is a BFS source only, not an N4 peer
            }
            let n4 = node
                .n4
                .ok_or_else(|| anyhow::anyhow!("UPF node {name:?} has no n4 address"))?;
            // Only anchors report; an intermediate (no DNNs) gets no reports channel.
            let reports = (!node.dnns.is_empty()).then(|| reports_tx.clone());
            let peer = N4Peer::connect(n4, reports)
                .await
                .map_err(|e| anyhow::anyhow!("N4 connect to UPF {name:?} ({n4}): {e}"))?;
            peers.insert(name.clone(), peer);
        }
        Ok(Self::with_peers(peers, Routing::Graph(topo), reports_rx, smf_ip, nrf_base.into()))
    }

    /// Assemble the runtime around an already-connected peer set — the tail both
    /// constructors share.
    fn with_peers(
        peers: BTreeMap<String, Arc<N4Peer>>,
        routing: Routing,
        reports_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        smf_ip: Ipv4Addr,
        nrf_base: String,
    ) -> Self {
        Self {
            smf_ip,
            nrf_base,
            peers,
            routing,
            reports_rx: tokio::sync::Mutex::new(reports_rx),
            cp_seid: AtomicU64::new(1),
            next_ref: AtomicU64::new(1),
            ue_ipv4_pool: Mutex::new(U32Pool::new(UE_IP_POOL_START, UE_IP_POOL_END)),
            // The /64 index rides the 3rd+4th hextets, so the whole u32 space is available.
            ue_ipv6_pool: Mutex::new(U32Pool::new(1, u32::MAX)),
            contexts: Mutex::new(HashMap::new()),
            // Generous default so plain operation isn't gated; override for admission
            // control (config / tests).
            gfbr_budget_bps: (u64::MAX, u64::MAX),
            reserved_gfbr_bps: Mutex::new((0, 0)),
            usage_threshold_bytes: None,
            callback_base: DEFAULT_CALLBACK_BASE.to_string(),
        }
    }

    /// Set the base URL other NFs use to reach this SMF (the SM policy `notificationUri`).
    pub fn with_callback_base(mut self, base: impl Into<String>) -> Self {
        self.callback_base = base.into();
        self
    }

    /// Resolve the [`SessionPath`] a session on `dnn` runs — the peers its whole lifetime
    /// addresses. Fixed routing returns the same path for every DNN; graph routing walks
    /// the topology to the anchor serving `dnn`. radian supports at most one intermediate,
    /// so a deeper graph path is rejected here rather than silently truncated.
    fn resolve_path(&self, dnn: &str) -> anyhow::Result<SessionPath> {
        let peer = |name: &str| {
            self.peers
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("UP node {name:?} is not connected"))
        };
        match &self.routing {
            Routing::Fixed { anchor, intermediate, breakout } => Ok(SessionPath {
                anchor: peer(anchor)?,
                intermediate: intermediate.as_deref().map(peer).transpose()?,
                breakout: match breakout {
                    Some((name, prefix)) => Some((peer(name)?, *prefix)),
                    None => None,
                },
            }),
            Routing::Graph(topo) => {
                let path = topo
                    .path_for_dnn(dnn)
                    .ok_or_else(|| anyhow::anyhow!("no UP path for DNN {dnn:?}"))?;
                let (anchor, intermediate) = match path.nodes.as_slice() {
                    [a] => (a.as_str(), None),
                    [i, a] => (a.as_str(), Some(i.as_str())),
                    _ => anyhow::bail!("UP path for DNN {dnn:?} has more than one intermediate"),
                };
                // A breakout route steers a prefix to a second anchor. The classifier that
                // does the steering is the DNN's intermediate UPF, so a route on a DNN with
                // no intermediate is a config error rather than a silently dropped rule.
                let breakout = match topo.breakout_for_dnn(dnn) {
                    Some(route) => {
                        anyhow::ensure!(
                            intermediate.is_some(),
                            "DNN {dnn:?} has a breakout route but no intermediate UPF to classify at"
                        );
                        let prefix: pfcp::IpPrefix = route.prefix.parse().map_err(|_| {
                            anyhow::anyhow!("breakout prefix {:?} is not a CIDR", route.prefix)
                        })?;
                        Some((peer(&route.via)?, prefix))
                    }
                    None => None,
                };
                Ok(SessionPath {
                    anchor: peer(anchor)?,
                    intermediate: intermediate.map(peer).transpose()?,
                    breakout,
                })
            }
        }
    }

    /// Set the GFBR admission-control budget `(downlink_bps, uplink_bps)`.
    pub fn with_gfbr_budget(mut self, downlink_bps: u64, uplink_bps: u64) -> Self {
        self.gfbr_budget_bps = (downlink_bps, uplink_bps);
        self
    }

    /// Provision a volume threshold (bytes) on every session's URR: the UPF then
    /// reports usage mid-session whenever the threshold is crossed (the charging
    /// trigger toward the CHF).
    pub fn with_usage_threshold(mut self, bytes: u64) -> Self {
        self.usage_threshold_bytes = Some(bytes);
        self
    }

    /// Try to reserve `(dl, ul)` bits/sec of GFBR against the budget. Returns `false`
    /// (and reserves nothing) if either direction would exceed it.
    fn try_reserve_gfbr(&self, (dl, ul): (u64, u64)) -> bool {
        let mut r = self.reserved_gfbr_bps.lock().unwrap();
        if r.0.saturating_add(dl) > self.gfbr_budget_bps.0
            || r.1.saturating_add(ul) > self.gfbr_budget_bps.1
        {
            return false;
        }
        r.0 += dl;
        r.1 += ul;
        true
    }

    /// Release a session's GFBR reservation.
    fn release_gfbr(&self, (dl, ul): (u64, u64)) {
        let mut r = self.reserved_gfbr_bps.lock().unwrap();
        r.0 = r.0.saturating_sub(dl);
        r.1 = r.1.saturating_sub(ul);
    }

    /// Atomically swap a session's GFBR reservation from `old` to `new` (a
    /// mid-session policy change; not admission-checked — the PCF authorized it).
    fn adjust_gfbr(&self, old: (u64, u64), new: (u64, u64)) {
        let mut r = self.reserved_gfbr_bps.lock().unwrap();
        r.0 = r.0.saturating_sub(old.0).saturating_add(new.0);
        r.1 = r.1.saturating_sub(old.1).saturating_add(new.1);
    }

    /// Allocate a UE IPv4 address from the pool. `None` when the pool is exhausted
    /// (the establishment is then refused for insufficient resources, design/137 G6).
    fn alloc_ue_ip(&self) -> Option<Ipv4Addr> {
        self.ue_ipv4_pool.lock().unwrap().alloc().map(Ipv4Addr::from)
    }

    /// Return a UE IPv4 address to the pool (on session release, or an aborted
    /// establishment) so it can be handed out again.
    fn release_ue_ip(&self, addr: Ipv4Addr) {
        self.ue_ipv4_pool.lock().unwrap().release(u32::from(addr));
    }

    /// Allocate a unique **/64** prefix (`2001:db8:H:L::/64`, where `HL` is the full
    /// `u32` pool index) and an interface identifier (`::n`) for an IPv6/IPv4v6 PDU
    /// session (TS 23.501 §5.8.2.2 — one /64 per session). The UE forms its global
    /// address `prefix ‖ iid` via SLAAC once the Router Advertisement lands (design/131
    /// Phase C). The index starts at 1, so no session gets the `::0` identifier and
    /// the interface identifier `::n` sits within the session's own /64. `None` when
    /// the pool is exhausted.
    fn alloc_ue_ipv6(&self) -> Option<(std::net::Ipv6Addr, [u8; 8])> {
        let n = self.ue_ipv6_pool.lock().unwrap().alloc()?;
        let mut seg = [0u8; 16];
        seg[..4].copy_from_slice(&UE_IPV6_PREFIX_32);
        seg[4..8].copy_from_slice(&n.to_be_bytes()); // /64 index → full u32 (3rd+4th hextets)
        let prefix = std::net::Ipv6Addr::from(seg);
        let mut iid = [0u8; 8];
        iid[4..8].copy_from_slice(&n.to_be_bytes()); // interface identifier ::n
        Some((prefix, iid))
    }

    /// Return a UE IPv6 /64 to the pool, recovering the pool index from the 3rd+4th
    /// hextets of `prefix` (where [`alloc_ue_ipv6`](Self::alloc_ue_ipv6) put it).
    fn release_ue_ipv6(&self, prefix: std::net::Ipv6Addr) {
        let o = prefix.octets();
        let n = u32::from_be_bytes([o[4], o[5], o[6], o[7]]);
        self.ue_ipv6_pool.lock().unwrap().release(n);
    }

    /// A connected UP peer by node name — used to reach a breakout anchor named by an OAM
    /// ULCL-insertion request (design/134 Phase 3e).
    fn peer_by_name(&self, name: &str) -> Option<Arc<N4Peer>> {
        self.peers.get(name).cloned()
    }

    /// Resolve a **DNAI** to a UP-node name via the topology — how a NEF's AF traffic
    /// influence picks a breakout anchor (design/135). `None` in env-var (fixed) mode,
    /// which has no topology to name DNAIs in.
    fn node_for_dnai(&self, dnai: &str) -> Option<String> {
        match &self.routing {
            Routing::Graph(topo) => topo.node_for_dnai(dnai).map(String::from),
            Routing::Fixed { .. } => None,
        }
    }

    /// Whether the topology declares a static breakout route for `dnn` — that breakout is
    /// config-owned, so AF-influenced policy must not reconcile it away (design/135 Phase 2).
    fn dnn_has_config_route(&self, dnn: &str) -> bool {
        matches!(&self.routing, Routing::Graph(topo) if topo.breakout_for_dnn(dnn).is_some())
    }

    /// PFCP Association Setup toward every UPF in the topology — required before any
    /// session.
    pub async fn associate(&self) -> anyhow::Result<()> {
        for (name, peer) in &self.peers {
            peer.associate(self.smf_ip)
                .await
                .map_err(|e| anyhow::anyhow!("association with UP node {name:?}: {e}"))?;
        }
        Ok(())
    }

    /// One heartbeat round across every UP peer (design/137 G4): a peer that reports a
    /// newer recovery timestamp restarted, so recover it. The [`run_heartbeats`] loop
    /// calls this on a timer; tests call it directly.
    async fn heartbeat_round(&self) {
        // The peer set is fixed after `connect`; clone the handles so no map borrow is
        // held across the awaits below.
        let peers: Vec<Arc<N4Peer>> = self.peers.values().cloned().collect();
        for peer in &peers {
            match peer.heartbeat().await {
                Some(Recovery::Restarted) => self.recover_from_upf_restart(peer).await,
                Some(Recovery::Unchanged) => {}
                // A single missed heartbeat isn't a restart; the next round re-checks.
                None => tracing::debug!("no PFCP heartbeat response from a UP peer"),
            }
        }
    }

    /// A UPF reported a **restart** — its PDR/FAR/URR state is gone, so every session
    /// on it is stranded. Re-associate it (so it accepts new sessions), then drop each
    /// affected SM context, returning its UE address(es) and GFBR reservation to the
    /// pools and purging its serving-SMF registration. The UE re-establishes on its
    /// next activity. Mirrors free5gc's `releaseAllResourcesOfUPF` (design/137 G4).
    ///
    /// PCF policy / CHF charging teardown for the dropped sessions is left to the
    /// normal release path when the AMF eventually releases the context; here we only
    /// reclaim the SMF-local resources that would otherwise leak.
    async fn recover_from_upf_restart(&self, peer: &Arc<N4Peer>) {
        if let Err(e) = peer.associate(self.smf_ip).await {
            tracing::warn!("re-association after UPF restart failed: {e}");
        }
        // Remove the affected contexts under the lock, then clean up off it.
        let dropped: Vec<SmContext> = {
            let mut ctxs = self.contexts.lock().unwrap();
            let refs: Vec<String> =
                ctxs.iter().filter(|(_, c)| c.path.uses(peer)).map(|(r, _)| r.clone()).collect();
            refs.iter().filter_map(|r| ctxs.remove(r)).collect()
        };
        if dropped.is_empty() {
            return;
        }
        for c in &dropped {
            if let Some(v4) = c.ue_ip {
                self.release_ue_ip(v4);
            }
            if let Some((prefix, _)) = c.ue_ipv6 {
                self.release_ue_ipv6(prefix);
            }
            self.release_gfbr(c.reserved_gfbr);
            spawn_uecm_purge(self.nrf_base.clone(), c.supi.clone(), c.pdu_session_id);
        }
        tracing::warn!(
            dropped = dropped.len(),
            "UPF restarted (new recovery timestamp) — released the stranded SM contexts"
        );
    }
}

/// Periodically heartbeat the user plane and recover any UPF that restarted
/// (design/137 G4). Spawned once at startup; runs for the life of the SMF.
pub async fn run_heartbeats(smf: Arc<SmfState>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        smf.heartbeat_round().await;
    }
}

#[derive(Serialize, Deserialize)]
struct PlmnId {
    mcc: String,
    mnc: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextCreateData {
    supi: String,
    pdu_session_id: u8,
    #[serde(default)]
    dnn: String,
    /// The serving PLMN (TS 29.502) — selects which provisioned dataset applies.
    serving_network: Option<PlmnId>,
    /// The UE's requested slice (TS 29.502 `sNssai`). Absent → the subscribed
    /// slice serving the DNN is used.
    s_nssai: Option<Snssai>,
    /// The UE's requested PDU session type ("IPV4" | "IPV6" | "IPV4V6"). Absent →
    /// the DNN's default; the SMF negotiates the selected type against the
    /// subscription's allowed set (design/131).
    #[serde(default)]
    pdu_session_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snssai {
    sst: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    sd: Option<String>,
}

impl Snssai {
    /// The `subscribedSnssaiInfos` map key this stack provisions: `sst` or `sst-sd`.
    fn key(&self) -> String {
        match &self.sd {
            Some(sd) => format!("{}-{}", self.sst, sd.to_lowercase()),
            None => self.sst.to_string(),
        }
    }

    /// Slice equality with case-insensitive SD (SDs are hex strings).
    fn matches(&self, other: &Snssai) -> bool {
        self.sst == other.sst
            && match (&self.sd, &other.sd) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                (None, None) => true,
                _ => false,
            }
    }
}

// The session AMBR and authorized QoS-flow shapes are shared with the PCF
// (`sbi_core::npcf`): a PCF `SmPolicyDecision` and the SMF's own sm-data fallback
// build the same types, so either drops straight into the CreateSMContext response.
use sbi_core::npcf::{QosFlowPolicy, SessionAmbrPolicy};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextCreatedData {
    sm_context_ref: String,
    /// The UPF's N3 F-TEID — carried to the gNB in the N2 SM info.
    up_n3_teid: String,
    up_n3_addr: Ipv4Addr,
    /// The selected PDU session type ("IPV4" | "IPV6" | "IPV4V6"), negotiated from the
    /// UE's request and the subscription (design/131). The AMF encodes it in the N1
    /// accept + the N2 PDU Session Type IE.
    selected_pdu_session_type: String,
    /// The UE's assigned IPv4 address (its PDU session address). Present for IPv4 /
    /// IPv4v6 only. Delivered to the UE in the NAS PDU Session Establishment Accept;
    /// the UPF routes downlink traffic to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    ue_ipv4_addr: Option<Ipv4Addr>,
    /// The UE's assigned IPv6 /64 prefix (`2001:db8:a:n::/64`) — present for IPv6 /
    /// IPv4v6. The UE forms its global address from this via SLAAC (design/131 RA is
    /// Phase C); carried for the AMF/UPF, not the NAS accept.
    #[serde(skip_serializing_if = "Option::is_none")]
    ue_ipv6_prefix: Option<String>,
    /// The IPv6 interface identifier (hex, 8 bytes) — present for IPv6 / IPv4v6. The
    /// AMF puts this in the N1 accept's PDU Address IE.
    #[serde(skip_serializing_if = "Option::is_none")]
    ue_ipv6_iid: Option<String>,
    /// A 5GSM cause set on a PDU-session-type downgrade (#50 IPv4-only / #51
    /// IPv6-only) — the AMF carries it in the N1 accept.
    #[serde(skip_serializing_if = "Option::is_none")]
    cause5gsm: Option<u8>,
    /// The IPv6 DNS server for this DNN, returned to the UE in the accept's ePCO when
    /// it requested DNS via PCO (design/131 Phase D).
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_ipv6: Option<String>,
    /// The subscribed slice serving this DNN (from the UDR sm-data) — the AMF puts it
    /// in the N1 accept.
    s_nssai: Snssai,
    /// The authorized session AMBR for this DNN (TS 29.571 BitRate strings), if any
    /// — from the PCF's SM policy, else the subscribed sm-data. For the N1 accept.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_ambr: Option<SessionAmbrPolicy>,
    /// The authorized QoS flows (default + any GBR flows) — the AMF puts them in
    /// the N2 setup transfer and the N1 accept's QoS flow descriptions.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    qos_flows: Vec<QosFlowPolicy>,
}

/// What the SMF needs out of the subscriber's session-management subscription
/// (the sm-data fallback when no PCF is available).
struct SessionSubscription {
    snssai: Snssai,
    ambr: Option<SessionAmbrPolicy>,
    qos_flows: Vec<QosFlowPolicy>,
    /// The DNN's allowed PDU session types (from sm-data `pduSessionTypes`), as
    /// (allows-IPv4, allows-IPv6), plus the default — the SMF negotiates the
    /// selected type against these (design/131).
    allow_v4: bool,
    allow_v6: bool,
    default_type: nas::PduSessionType,
    /// The DNN's IPv6 DNS server (sm-data `dnnConfigurations[dnn].dns.ipv6`), returned
    /// to the UE in the accept's ePCO when it requests DNS (design/131 Phase D).
    dns_ipv6: Option<std::net::Ipv6Addr>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextUpdateData {
    /// The gNB's N3 F-TEID from the N2 PDU Session Resource Setup Response (hex).
    /// Present on an **activation** (downlink install / Service Request resume).
    #[serde(default)]
    gnb_n3_teid: Option<String>,
    #[serde(default)]
    gnb_n3_addr: Option<Ipv4Addr>,
    /// User-plane connection state (TS 29.502): `DEACTIVATED` on AN release tears
    /// the downlink tunnel down; `ACTIVATING` (with the gNB F-TEID) re-installs it.
    #[serde(default)]
    up_cnx_state: Option<String>,
}

/// The `Nsmf_PDUSession` router.
pub fn router(state: Arc<SmfState>) -> Router {
    Router::new()
        .route("/nsmf-pdusession/v1/sm-contexts", post(create_sm_context))
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            post(update_sm_context),
        )
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/release",
            post(release_sm_context),
        )
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/refresh-policy",
            post(refresh_sm_policy),
        )
        // The PCF's policy-update notification target (the `notificationUri` this SMF
        // registered at policy create): a PCF-initiated re-authorization, e.g. after an AF
        // influence landed (design/135 Phase 2b). Same work as a refresh — re-pull the
        // decision and reconcile — so it shares the handler.
        .route(
            "/nsmf-callback/v1/sm-policies/{sm_ref}/update",
            post(refresh_sm_policy),
        )
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/indirect-forwarding",
            post(indirect_forwarding),
        )
        // OAM: insert/remove an uplink-classifier breakout on a live session (design/134
        // Phase 3e). A stand-in trigger — in production this is driven by NEF/AF traffic
        // influence (design/130 P2-5) — but the mechanism it exercises is the same.
        .route("/oam/v1/breakout", post(oam_breakout))
        .with_state(state)
}

/// An SBI error response: status + RFC 7807 ProblemDetails with a TS 29.502-style
/// application cause (e.g. `DNN_DENIED`, `SNSSAI_DENIED`).
type SbiProblem = (StatusCode, Json<sbi_core::ProblemDetails>);

fn problem(status: StatusCode, cause: &str, detail: &str) -> SbiProblem {
    (
        status,
        Json(sbi_core::ProblemDetails {
            status: Some(status.as_u16()),
            cause: Some(cause.to_string()),
            detail: Some(detail.to_string()),
            ..Default::default()
        }),
    )
}

/// Frees the leased UE IP(s) back to the SMF's pools on drop unless [`commit`](IpLease::commit)ed
/// — so any early return between address allocation and storing the SM context releases
/// them, and only a persisted context keeps them (design/137 G6). This makes the
/// establishment's several failure paths leak-free without threading a release into each.
struct IpLease<'a> {
    smf: &'a SmfState,
    v4: Option<Ipv4Addr>,
    v6: Option<std::net::Ipv6Addr>,
    committed: bool,
}

impl<'a> IpLease<'a> {
    fn new(smf: &'a SmfState) -> Self {
        Self { smf, v4: None, v6: None, committed: false }
    }

    /// The context now owns the addresses — don't release them on drop.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for IpLease<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(v4) = self.v4 {
            self.smf.release_ue_ip(v4);
        }
        if let Some(v6) = self.v6 {
            self.smf.release_ue_ipv6(v6);
        }
    }
}

/// `Nsmf_PDUSession_CreateSMContext`: authorize the (requested S-NSSAI, DNN) pair
/// against the subscriber's UDR-provisioned data (via Nudm_SDM), establish the N4
/// session, and return the UPF N3 F-TEID plus the serving S-NSSAI / session AMBR.
async fn create_sm_context(
    State(smf): State<Arc<SmfState>>,
    Json(req): Json<SmContextCreateData>,
) -> Result<(StatusCode, Json<SmContextCreatedData>), SbiProblem> {
    if req.dnn.is_empty() {
        return Err(problem(StatusCode::BAD_REQUEST, "MANDATORY_IE_MISSING", "dnn is required"));
    }
    let plmn = req
        .serving_network
        .as_ref()
        .map(|p| format!("{}{}", p.mcc, p.mnc))
        .ok_or_else(|| {
            problem(StatusCode::BAD_REQUEST, "MANDATORY_IE_MISSING", "servingNetwork is required")
        })?;
    // Subscription check BEFORE touching the UPF: a denied (slice, DNN) → 403, no N4 state.
    let sub = fetch_session_subscription(
        &smf.nrf_base,
        &req.supi,
        &plmn,
        &req.dnn,
        req.s_nssai.as_ref(),
    )
    .await?;

    // Negotiate the PDU session type (design/131): the UE's requested type against the
    // DNN's allowed families. A downgrade (e.g. IPv4v6 requested, only IPv4 allowed)
    // carries a 5GSM cause (#50/#51) in the Establishment Accept.
    let requested_type = req
        .pdu_session_type
        .as_deref()
        .and_then(nas::PduSessionType::from_name)
        .unwrap_or(sub.default_type);
    let (selected_type, cause5gsm) = negotiate_pdu_type(requested_type, sub.allow_v4, sub.allow_v6);

    // Ask the PCF for the SM policy (authorized session AMBR + QoS flows). When a
    // PCF is registered it is authoritative (TS 23.503 §6.1.3.5); otherwise fall
    // back to the sm-data policy fetched above. Done before the N4 establishment so
    // the authorized flows are known when the context is built.
    // The SM-context reference is allocated up front so it can ride in the policy
    // `notificationUri`: a PCF-initiated re-authorization (an AF influence landing) then
    // addresses this exact context without the PCF knowing anything about SMF internals.
    let sm_ref = smf.next_ref.fetch_add(1, Ordering::Relaxed).to_string();
    let policy_ctx = sbi_core::npcf::SmPolicyContextData {
        supi: req.supi.clone(),
        pdu_session_id: req.pdu_session_id,
        dnn: req.dnn.clone(),
        snssai_sst: Some(sub.snssai.sst),
        snssai_sd: sub.snssai.sd.clone(),
        notification_uri: Some(format!(
            "{}/nsmf-callback/v1/sm-policies/{sm_ref}/update",
            smf.callback_base
        )),
    };
    let (decision, sm_policy) = match fetch_sm_policy(&smf.nrf_base, &policy_ctx).await {
        Some((pcf_base, created)) => {
            tracing::info!(
                policy_id = %created.policy_id,
                flows = created.decision.pcc_rules.len(),
                "SM policy from PCF"
            );
            (created.decision, Some((pcf_base, created.policy_id)))
        }
        None => {
            // The sm-data fallback: no PCF, so build PCC rules + QoS decisions from the
            // subscribed flat flows (and no charging decisions).
            let mut decision = sbi_core::npcf::SmPolicyDecision {
                session_rules: sbi_core::npcf::SmPolicyDecision::session_rules_for(sub.ambr),
                ..Default::default()
            };
            decision.set_flows(sub.qos_flows);
            (decision, None)
        }
    };

    // GFBR admission control (before any N4 state): reserve the session's aggregate
    // guaranteed bit rate against the budget, refusing it (503 → 5GSM #26) if the
    // network can't guarantee it.
    let reserved_gfbr = decision_gfbr(&decision);
    if !smf.try_reserve_gfbr(reserved_gfbr) {
        tracing::warn!(
            supi = %masked_supi(&req.supi),
            dnn = %req.dnn,
            gfbr_dl = reserved_gfbr.0, gfbr_ul = reserved_gfbr.1,
            "PDU session refused: GFBR admission control (insufficient resources)"
        );
        return Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "INSUFFICIENT_RESOURCES",
            "GFBR cannot be guaranteed",
        ));
    }

    // Select the UP path for this DNN (design/134 Phase 3b). In env-var mode it is the
    // one fixed path; in config mode the topology graph is walked. An unroutable DNN
    // fails the establishment before any UPF state is created.
    let path = match smf.resolve_path(&req.dnn) {
        Ok(p) => p,
        Err(e) => {
            smf.release_gfbr(reserved_gfbr);
            tracing::warn!(dnn = %req.dnn, "no UP path for DNN: {e}");
            return Err(problem(StatusCode::BAD_GATEWAY, "DNN_DENIED", "no user-plane path for the DNN"));
        }
    };
    let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
    let seq = path.anchor.next_seq();
    // The SMF owns UE address allocation; the address(es) ride into the UPF's downlink
    // PDR so it can route N6 traffic back to this session (design/131). An IPv4 address
    // is allocated when the selected type includes IPv4; an IPv6 /64 + interface
    // identifier when it includes IPv6 — a pure-IPv6 session carries no v4.
    // The lease frees the allocated address(es) back to the pool on any early return
    // before the SM context is stored; only a persisted context keeps them (design/137 G6).
    let mut lease = IpLease::new(&smf);
    let ue_ip = if selected_type.has_ipv4() {
        match smf.alloc_ue_ip() {
            Some(ip) => {
                lease.v4 = Some(ip);
                Some(ip)
            }
            None => {
                smf.release_gfbr(reserved_gfbr);
                tracing::warn!(dnn = %req.dnn, "PDU session refused: IPv4 address pool exhausted");
                return Err(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "INSUFFICIENT_RESOURCES",
                    "no UE IPv4 address available",
                ));
            }
        }
    } else {
        None
    };
    let ue_ipv6 = if selected_type.has_ipv6() {
        match smf.alloc_ue_ipv6() {
            Some(v6) => {
                lease.v6 = Some(v6.0);
                Some(v6)
            }
            None => {
                smf.release_gfbr(reserved_gfbr);
                tracing::warn!(dnn = %req.dnn, "PDU session refused: IPv6 prefix pool exhausted");
                return Err(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "INSUFFICIENT_RESOURCES",
                    "no UE IPv6 prefix available",
                ));
            }
        }
    } else {
        None
    };
    // Install the authorized session AMBR (a QER for the aggregate rate) plus a
    // per-flow QER + classifier for each GBR flow, so the UPF polices them.
    let ambr = ambr_bps(&decision);
    let flows = flow_qers(&decision);
    let ue_addr = pfcp::UeAddr { v4: ue_ip, v6: ue_ipv6.map(|(prefix, _)| prefix) };
    let est_req = pfcp::session_establishment_request(
        cp_seid,
        seq,
        smf.smf_ip,
        ue_addr,
        &req.dnn,
        ambr,
        &flows,
        smf.usage_threshold_bytes,
    );
    // Release the GFBR reservation if the N4 establishment doesn't complete.
    let resp = match path.anchor.transact(&est_req, seq).await {
        Some(r) => r,
        None => {
            smf.release_gfbr(reserved_gfbr);
            return Err(problem(
                StatusCode::BAD_GATEWAY,
                "UPF_NOT_RESPONDING",
                "no PFCP response from the UPF",
            ));
        }
    };
    let mut est = match pfcp::parse_session_establishment_response(&resp) {
        Some(e) => e,
        None => {
            smf.release_gfbr(reserved_gfbr);
            return Err(problem(
                StatusCode::BAD_GATEWAY,
                "UPF_NOT_RESPONDING",
                "PFCP establishment rejected",
            ));
        }
    };

    // Chained deployment (design/134): with an intermediate UPF configured, build the
    // session's second half on it and splice the two together. The anchor is
    // established first precisely so its N3 ingress can be the I-UPF's uplink egress.
    let mut chain = None;
    if path.intermediate.is_some() {
        match establish_chain(&smf, &path, &est, ue_addr, &req.dnn).await {
            Ok((leg, an_teid, an_addr)) => {
                chain = Some(leg);
                // The RAN must tunnel to the I-UPF, not the anchor.
                est.n3_teid = an_teid;
                est.n3_addr = an_addr;
            }
            Err(e) => {
                // Don't leave a half-built chain behind: tear the anchor session down
                // and fail the establishment.
                tracing::warn!("chained N4 setup failed, rolling back the anchor: {e}");
                let seq = path.anchor.next_seq();
                let del = pfcp::session_deletion_request(est.up_seid, seq);
                let _ = path.anchor.transact(&del, seq).await;
                smf.release_gfbr(reserved_gfbr);
                return Err(problem(
                    StatusCode::BAD_GATEWAY,
                    "UPF_NOT_RESPONDING",
                    "intermediate UPF did not accept the N4 session",
                ));
            }
        }
    }

    // Open an Nchf charging data session at the NRF-discovered CHF (the SMF acting
    // as CTF, TS 32.290). Best-effort: no CHF (or a failed create) ⇒ the session
    // runs unbilled, mirroring the PCF fallback.
    let charging = match discover_endpoint(&smf.nrf_base, "CHF").await {
        Ok(chf_base) => {
            let create = sbi_core::nchf::ChargingDataRequest {
                subscriber_identifier: req.supi.clone(),
                pdu_session_charging_information: Some(
                    sbi_core::nchf::PduSessionChargingInformation {
                        pdu_session_id: req.pdu_session_id,
                        dnn: req.dnn.clone(),
                    },
                ),
                used_unit_containers: vec![],
            };
            match chf_client(&smf.nrf_base, chf_base.clone()).create(&create).await {
                Ok(charging_ref) => {
                    tracing::info!(charging_ref = %charging_ref, "charging session opened at the CHF");
                    Some((chf_base, charging_ref))
                }
                Err(e) => {
                    tracing::warn!("Nchf create failed (session runs unbilled): {e}");
                    None
                }
            }
        }
        Err(e) => {
            tracing::debug!("no CHF discovered (session runs unbilled): {e}");
            None
        }
    };

    smf.contexts.lock().unwrap().insert(
        sm_ref.clone(),
        SmContext {
            up_seid: est.up_seid,
            cp_seid,
            n3_teid: est.n3_teid,
            n3_addr: est.n3_addr,
            chain,
            path,
            ue_ip,
            pdu_type: selected_type,
            ue_ipv6,
            dnn: req.dnn.clone(),
            snssai: sub.snssai.clone(),
            gnb: None,
            indirect_fwd: None,
            supi: req.supi.clone(),
            pdu_session_id: req.pdu_session_id,
            sm_policy,
            policy: decision.clone(),
            reserved_gfbr,
            policy_breakout: false,
            charging,
        },
    );
    // The stored context now owns the UE address(es); keep them out of the pool.
    lease.commit();
    // An AF influence already in this session's policy — a group / any-UE influence the
    // PCF read from the UDR — applies from the start: splice its breakout now, before the
    // session ever carries traffic (design/135 Phase 3).
    reconcile_influence_breakout(&smf, &sm_ref).await;
    // Record this SMF as the serving SMF for the session (Nudm_UECM). Best-effort,
    // off the establishment path — the session is up regardless.
    spawn_uecm_register(
        smf.nrf_base.clone(),
        req.supi.clone(),
        req.pdu_session_id,
        req.dnn.clone(),
    );
    // SUPI is a permanent subscriber identifier (PII): log only a masked form.
    tracing::info!(
        supi = %masked_supi(&req.supi),
        pdu_session_id = req.pdu_session_id,
        dnn = %req.dnn,
        snssai = ?sub.snssai,
        up_seid = est.up_seid,
        n3_teid = est.n3_teid,
        ue_ip = ?ue_ip,
        ue_ipv6 = ?ue_ipv6.map(|(p, _)| p),
        chained = chain.is_some(),
        "created SM context; N4 session established"
    );
    Ok((
        StatusCode::CREATED,
        Json(SmContextCreatedData {
            sm_context_ref: sm_ref,
            up_n3_teid: format!("{:08x}", est.n3_teid),
            up_n3_addr: est.n3_addr,
            selected_pdu_session_type: selected_type.as_str().to_string(),
            dns_ipv6: sub.dns_ipv6.map(|a| a.to_string()),
            ue_ipv4_addr: ue_ip,
            ue_ipv6_prefix: ue_ipv6.map(|(p, _)| format!("{p}/64")),
            ue_ipv6_iid: ue_ipv6.map(|(_, iid)| hex::encode(iid)),
            cause5gsm,
            s_nssai: sub.snssai,
            session_ambr: decision.session_ambr().cloned(),
            qos_flows: decision.qos_flows(),
        }),
    ))
}

/// Build the **intermediate-UPF half** of a chained session and splice it to the
/// already-established anchor in both directions (design/134):
///
/// * uplink — the I-UPF's egress FAR gets Outer Header Creation toward the anchor's N3
///   ingress, set at establishment (hence anchor-first ordering);
/// * downlink — the anchor's downlink FAR is re-pointed at the I-UPF's N9 ingress by a
///   follow-up Session Modification. That is the same operation as pointing it at a
///   gNB: a UPF's downlink egress is just a GTP-U `(TEID, address)`.
///
/// With a breakout configured the I-UPF also becomes an **uplink classifier**: a second
/// anchor is established first and a branch rule steers its prefix there, so one PDU
/// session — one UE address — reaches two data networks (Phase 2).
///
/// Returns the leg plus the I-UPF's **gNB-facing** N3 F-TEID, which replaces the
/// anchor's in everything handed to the RAN.
async fn establish_chain(
    smf: &SmfState,
    path: &SessionPath,
    anchor: &pfcp::EstablishedSession,
    ue: pfcp::UeAddr,
    dnn: &str,
) -> anyhow::Result<(ChainedLeg, u32, Ipv4Addr)> {
    let iupf =
        path.intermediate.as_ref().ok_or_else(|| anyhow::anyhow!("chain without an intermediate"))?;
    // The breakout anchor, if any, goes up first: the classifier's branch FAR points at
    // its N3 ingress and — like the default anchor — that is set at establishment.
    let breakout = match &path.breakout {
        Some((psa2, prefix)) => {
            let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
            let seq = psa2.next_seq();
            let req = pfcp::session_establishment_request(
                cp_seid,
                seq,
                smf.smf_ip,
                ue,
                dnn,
                None, // policed once, on the default anchor
                &[],
                None, // and metered there too — this leg carries no URRs
            );
            let resp = psa2
                .transact(&req, seq)
                .await
                .ok_or_else(|| anyhow::anyhow!("no PFCP response from the breakout anchor"))?;
            let est = pfcp::parse_session_establishment_response(&resp)
                .ok_or_else(|| anyhow::anyhow!("breakout anchor rejected the N4 establishment"))?;
            Some((est, *prefix))
        }
        None => None,
    };
    let branches: Vec<_> = breakout
        .iter()
        .map(|(est, prefix)| {
            (
                pfcp::FlowFilter::to_prefix(*prefix),
                pfcp::Egress::ToPeer { teid: est.n3_teid, addr: est.n3_addr },
            )
        })
        .collect();

    let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
    let seq = iupf.next_seq();
    let est_req = pfcp::session_establishment_request_via_peer(
        cp_seid,
        seq,
        smf.smf_ip,
        ue,
        dnn,
        anchor.n3_teid,
        anchor.n3_addr,
        &branches,
    );
    let resp = iupf
        .transact(&est_req, seq)
        .await
        .ok_or_else(|| anyhow::anyhow!("no PFCP response from the intermediate UPF"))?;
    let est = pfcp::parse_session_establishment_response(&resp)
        .ok_or_else(|| anyhow::anyhow!("intermediate UPF rejected the N4 establishment"))?;
    let dl_ingress = est
        .dl_ingress
        .ok_or_else(|| anyhow::anyhow!("intermediate UPF allocated no N9 downlink ingress"))?;

    // Both anchors send downlink back to the *same* I-UPF ingress — it is the node that
    // holds the gNB tunnel, so one return path serves however many anchors the uplink
    // fans out to. That symmetry is why a breakout needs no second downlink ingress.
    point_downlink_at(&path.anchor, anchor.up_seid, dl_ingress, dnn)
        .await
        .map_err(|e| anyhow::anyhow!("anchor UPF: {e}"))?;
    if let (Some((psa2, _)), Some((est2, _))) = (&path.breakout, &breakout) {
        point_downlink_at(psa2, est2.up_seid, dl_ingress, dnn)
            .await
            .map_err(|e| anyhow::anyhow!("breakout anchor: {e}"))?;
    }
    tracing::info!(
        anchor_seid = anchor.up_seid,
        iupf_seid = est.up_seid,
        breakout_seid = ?breakout.as_ref().map(|(e, _)| e.up_seid),
        breakout_prefix = ?breakout.as_ref().map(|(_, p)| p.to_string()),
        n9_uplink_teid = anchor.n3_teid,
        n9_downlink_teid = dl_ingress.0,
        ran_teid = est.n3_teid,
        "chained the session through an intermediate UPF"
    );
    Ok((
        ChainedLeg {
            up_seid: est.up_seid,
            dl_ingress,
            breakout_seid: breakout.map(|(e, _)| e.up_seid),
        },
        est.n3_teid,
        est.n3_addr,
    ))
}

/// Point one UPF session's downlink FAR at a GTP-U `(TEID, address)` — a gNB tunnel or,
/// on an anchor sitting behind a chain, the intermediate UPF's N9 ingress. The two are
/// the same PFCP operation.
async fn point_downlink_at(
    peer: &N4Peer,
    up_seid: u64,
    target: (u32, Ipv4Addr),
    dnn: &str,
) -> Result<(), &'static str> {
    let seq = peer.next_seq();
    let req =
        pfcp::session_modification_request(up_seid, seq, FAR_ID, target.0, target.1, dnn, false);
    let resp = peer.transact(&req, seq).await.ok_or("no PFCP response")?;
    if pfcp::response_accepted(&resp) { Ok(()) } else { Err("refused the downlink target") }
}

/// Whether one smf-select `subscribedSnssaiInfos` entry's `dnnInfos` contains `dnn`.
fn dnn_in_info(info: &serde_json::Value, dnn: &str) -> bool {
    info.get("dnnInfos")
        .and_then(|v| v.as_array())
        .is_some_and(|dnns| dnns.iter().any(|d| d.get("dnn").and_then(|v| v.as_str()) == Some(dnn)))
}

/// The DNN's allowed PDU session types from sm-data `pduSessionTypes`: the
/// `defaultSessionType` plus any `allowedSessionTypes`. Returns
/// `(allows-IPv4, allows-IPv6, default)`, defaulting to IPv4-only when unset.
fn parse_pdu_session_types(dnn_config: &serde_json::Value) -> (bool, bool, nas::PduSessionType) {
    let pt = dnn_config.get("pduSessionTypes");
    let default_type = pt
        .and_then(|p| p.get("defaultSessionType"))
        .and_then(|v| v.as_str())
        .and_then(nas::PduSessionType::from_name)
        .unwrap_or(nas::PduSessionType::Ipv4);
    let mut allow_v4 = default_type.has_ipv4();
    let mut allow_v6 = default_type.has_ipv6();
    if let Some(arr) = pt.and_then(|p| p.get("allowedSessionTypes")).and_then(|v| v.as_array()) {
        for t in arr.iter().filter_map(|v| v.as_str()).filter_map(nas::PduSessionType::from_name) {
            allow_v4 |= t.has_ipv4();
            allow_v6 |= t.has_ipv6();
        }
    }
    (allow_v4, allow_v6, default_type)
}

/// Negotiate the selected PDU session type from the UE's requested type and the DNN's
/// allowed families (TS 24.501; mirrors free5gc's `IsAllowedPDUSessionType`). Returns
/// the selected type and, on a downgrade, the 5GSM cause (#50 IPv4-only / #51
/// IPv6-only) the Establishment Accept carries.
fn negotiate_pdu_type(
    requested: nas::PduSessionType,
    allow_v4: bool,
    allow_v6: bool,
) -> (nas::PduSessionType, Option<u8>) {
    use nas::PduSessionType::{Ipv4, Ipv4v6, Ipv6};
    use nas::sm_cause::{
        PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED as V4_ONLY, PDU_SESSION_TYPE_IPV6_ONLY_ALLOWED as V6_ONLY,
    };
    match requested {
        Ipv4v6 => match (allow_v4, allow_v6) {
            (true, true) => (Ipv4v6, None),
            (true, false) => (Ipv4, Some(V4_ONLY)),
            (false, true) => (Ipv6, Some(V6_ONLY)),
            (false, false) => (Ipv4, Some(V4_ONLY)), // nothing allowed — default to IPv4
        },
        Ipv4 if allow_v4 => (Ipv4, None),
        Ipv4 => (Ipv6, Some(V6_ONLY)),
        Ipv6 if allow_v6 => (Ipv6, None),
        Ipv6 => (Ipv4, Some(V4_ONLY)),
    }
}

/// Fetch and authorize the session-management subscription for (`supi`, `plmn`,
/// `dnn`, optionally the UE's `requested` S-NSSAI) via the NRF-discovered UDM
/// (Nudm_SDM):
/// - `smf-select-data` must allow the pair: with a requested slice, that slice's
///   entry must exist (else `403 SNSSAI_DENIED`) and list the DNN (else
///   `403 DNN_DENIED`); without one, any subscribed slice listing the DNN counts.
/// - `sm-data` supplies the serving S-NSSAI and session AMBR: with a requested
///   slice, its own entry is used; without one, the first entry configuring the DNN.
///
/// Fails closed: a missing subscription is `403`, an unreachable NRF/UDM is `502`.
async fn fetch_session_subscription(
    nrf_base: &str,
    supi: &str,
    plmn: &str,
    dnn: &str,
    requested: Option<&Snssai>,
) -> Result<SessionSubscription, SbiProblem> {
    let udm = discover_udm(nrf_base).await.map_err(|e| {
        tracing::warn!("UDM discovery failed: {e}");
        problem(StatusCode::BAD_GATEWAY, "UDM_UNREACHABLE", "UDM discovery failed")
    })?;
    let sdm = udm_client(nrf_base, udm);

    let gateway = |e| {
        tracing::warn!("Nudm_SDM fetch failed: {e}");
        problem(StatusCode::BAD_GATEWAY, "UDM_UNREACHABLE", "Nudm_SDM fetch failed")
    };
    let denied = |cause: &str, why: &str| {
        tracing::warn!(supi = %masked_supi(supi), %dnn, snssai = ?requested, "PDU session rejected ({cause}): {why}");
        problem(StatusCode::FORBIDDEN, cause, why)
    };

    // SMF-selection data: which DNNs this subscriber may use, per subscribed S-NSSAI.
    let select = sdm
        .get_smf_select_data(supi, plmn)
        .await
        .map_err(gateway)?
        .ok_or_else(|| denied("DNN_DENIED", "no smf-selection subscription data"))?;
    let infos = select.get("subscribedSnssaiInfos").and_then(|v| v.as_object());
    match requested {
        Some(slice) => {
            let info = infos
                .and_then(|m| m.get(&slice.key()))
                .ok_or_else(|| denied("SNSSAI_DENIED", "requested S-NSSAI is not subscribed"))?;
            if !dnn_in_info(info, dnn) {
                return Err(denied("DNN_DENIED", "DNN not allowed in the requested slice"));
            }
        }
        None => {
            let allowed = infos.is_some_and(|m| m.values().any(|info| dnn_in_info(info, dnn)));
            if !allowed {
                return Err(denied("DNN_DENIED", "DNN not in smf-selection subscription data"));
            }
        }
    }

    // SM data: session parameters (S-NSSAI, AMBR) for the slice's DNN configuration.
    let sm_data = sdm
        .get_sm_data(supi, plmn)
        .await
        .map_err(gateway)?
        .ok_or_else(|| denied("DNN_DENIED", "no session-management subscription data"))?;
    let entry_snssai = |e: &serde_json::Value| {
        e.get("singleNssai").and_then(|v| serde_json::from_value::<Snssai>(v.clone()).ok())
    };
    let entry = match requested {
        Some(slice) => sm_data
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| entry_snssai(e).is_some_and(|s| s.matches(slice)))
            .ok_or_else(|| denied("SNSSAI_DENIED", "requested S-NSSAI has no sm-data"))?,
        None => sm_data
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| {
                e.get("dnnConfigurations")
                    .and_then(|v| v.as_object())
                    .is_some_and(|c| c.contains_key(dnn))
            })
            .ok_or_else(|| denied("DNN_DENIED", "DNN has no configuration in sm-data"))?,
    };
    let dnn_config = entry
        .get("dnnConfigurations")
        .and_then(|c| c.get(dnn))
        .ok_or_else(|| denied("DNN_DENIED", "DNN has no configuration in the serving slice"))?;

    let snssai = entry_snssai(entry)
        .ok_or_else(|| denied("DNN_DENIED", "sm-data entry has no singleNssai"))?;
    let ambr = dnn_config
        .get("sessionAmbr")
        .and_then(|v| serde_json::from_value::<SessionAmbrPolicy>(v.clone()).ok());

    // Default QoS flow (QFI 1) from the DNN's 5gQosProfile — 5QI 9 / ARP 8 when
    // absent. Additional (e.g. GBR) flows come from the demo `qosFlows` array.
    // This is the fallback when no PCF is registered; with a PCF, its decision
    // replaces these (TS: QoS flows are PCF-driven — see `fetch_sm_policy`).
    let default_5qi = dnn_config.pointer("/5gQosProfile/5qi").and_then(|v| v.as_u64());
    let default_arp = dnn_config
        .pointer("/5gQosProfile/arp/priorityLevel")
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(8);
    let mut qos_flows = vec![QosFlowPolicy {
        qfi: 1,
        five_qi: default_5qi.and_then(|v| u8::try_from(v).ok()).unwrap_or(9),
        arp_priority: default_arp,
        pre_empt_cap: false,
        pre_empt_vuln: false,
        gbr: None,
        filter: None,
        ref_chg_data: None,
        flow_status: sbi_core::npcf::FlowStatus::Enabled,
    }];
    if let Some(extra) = dnn_config.get("qosFlows").and_then(|v| v.as_array()) {
        qos_flows.extend(
            extra.iter().filter_map(|f| serde_json::from_value::<QosFlowPolicy>(f.clone()).ok()),
        );
    }
    let (allow_v4, allow_v6, default_type) = parse_pdu_session_types(dnn_config);
    // The DNN's IPv6 DNS server, if provisioned (returned in the accept's ePCO).
    let dns_ipv6 = dnn_config
        .pointer("/dns/ipv6")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok());
    Ok(SessionSubscription { snssai, ambr, qos_flows, allow_v4, allow_v6, default_type, dns_ipv6 })
}

/// Discover the base URL of the first registered NF of `nf_type` via the NRF.
async fn discover_endpoint(nrf_base: &str, nf_type: &str) -> Result<String, String> {
    let profile = sbi_core::nnrf::NrfClient::new(nrf_base.to_string())
        .discover(nf_type, "SMF")
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no {nf_type} registered with the NRF"))?;
    // Dial the peer on the transport it advertises (`https` under mTLS).
    profile.service_base().ok_or_else(|| format!("{nf_type} profile has no service endpoint"))
}

/// Discover the UDM's Nudm service endpoint via the NRF.
async fn discover_udm(nrf_base: &str) -> Result<String, String> {
    discover_endpoint(nrf_base, "UDM").await
}

/// A Nudm client for `udm_base` that attaches an NRF-issued `UDM` access token when SBI
/// security is on (design/137 F3), else calls the UDM openly. The SMF's UDM calls are
/// infrequent, so the token source is built per call (fetching from `nrf_base` as this
/// SMF's registered instance id).
fn udm_client(nrf_base: &str, udm_base: impl Into<String>) -> sbi_core::nudm::NudmClient {
    if sbi_core::oauth::client_tokens_enabled() {
        let tokens = std::sync::Arc::new(sbi_core::oauth::TokenSource::new(
            nrf_base.to_string(),
            SMF_INSTANCE_ID.clone(),
        ));
        sbi_core::nudm::NudmClient::with_tokens(udm_base, tokens)
    } else {
        sbi_core::nudm::NudmClient::new(udm_base)
    }
}

/// This SMF's shared token source for the protected producers it consumes (PCF, CHF),
/// built per call from `nrf_base` — mirrors [`udm_client`]. `None` unless SBI security
/// is on. One source caches a separate token per (target NF, scope).
fn smf_tokens(nrf_base: &str) -> Option<std::sync::Arc<sbi_core::oauth::TokenSource>> {
    sbi_core::oauth::client_tokens_enabled().then(|| {
        std::sync::Arc::new(sbi_core::oauth::TokenSource::new(
            nrf_base.to_string(),
            SMF_INSTANCE_ID.clone(),
        ))
    })
}

/// An Npcf SM-policy client for `pcf_base` that attaches an NRF-issued `PCF` access
/// token when SBI security is on (design/149 G1), else calls the PCF openly.
fn pcf_client(nrf_base: &str, pcf_base: impl Into<String>) -> sbi_core::npcf::PcfClient {
    match smf_tokens(nrf_base) {
        Some(t) => sbi_core::npcf::PcfClient::with_tokens(pcf_base, t),
        None => sbi_core::npcf::PcfClient::new(pcf_base),
    }
}

/// An Nchf client for `chf_base` that attaches an NRF-issued `CHF` access token when
/// SBI security is on (design/149 G1), else calls the CHF openly.
fn chf_client(nrf_base: &str, chf_base: impl Into<String>) -> sbi_core::nchf::ChfClient {
    match smf_tokens(nrf_base) {
        Some(t) => sbi_core::nchf::ChfClient::with_tokens(chf_base, t),
        None => sbi_core::nchf::ChfClient::new(chf_base),
    }
}

/// Try to obtain the SM policy from a PCF (Npcf_SMPolicyControl). Returns the PCF
/// base + the created decision on success; `None` when no PCF is registered or the
/// call fails — the caller then uses the sm-data policy instead.
async fn fetch_sm_policy(
    nrf_base: &str,
    ctx: &sbi_core::npcf::SmPolicyContextData,
) -> Option<(String, sbi_core::npcf::SmPolicyCreated)> {
    let pcf_base = match discover_endpoint(nrf_base, "PCF").await {
        Ok(base) => base,
        Err(e) => {
            tracing::debug!("no PCF for SM policy ({e}); using sm-data policy");
            return None;
        }
    };
    match pcf_client(nrf_base, pcf_base.clone()).create_sm_policy(ctx).await {
        Ok(created) => Some((pcf_base, created)),
        Err(e) => {
            tracing::warn!("PCF SM policy create failed ({e}); using sm-data policy");
            None
        }
    }
}

/// `Nsmf_PDUSession_UpdateSMContext`: install the downlink path with the gNB's
/// F-TEID (activation), deactivate the UP (AN release), or return the N2 info to
/// re-activate on a Service Request (`upCnxState=ACTIVATING`).
async fn update_sm_context(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
    Json(req): Json<SmContextUpdateData>,
) -> axum::response::Response {
    // AN release (TS 23.502 §4.2.6): deactivate the downlink user-plane connection
    // — the UPF drops downlink toward the released gNB tunnel; the session persists.
    if req.up_cnx_state.as_deref() == Some("DEACTIVATED") {
        return deactivate_up(&smf, &sm_ref).await.into_response();
    }
    // Service Request resume (TS 23.502 §4.2.3.2): return the session's N2 info (the
    // retained UPF N3 F-TEID + current QoS) so the AMF rebuilds the N2 setup. The N4
    // downlink is re-installed by the follow-up activation (gNB F-TEID) below.
    if req.up_cnx_state.as_deref() == Some("ACTIVATING") {
        return match smf.contexts.lock().unwrap().get(&sm_ref) {
            Some(c) => (
                StatusCode::OK,
                Json(SmContextCreatedData {
                    sm_context_ref: sm_ref.clone(),
                    up_n3_teid: format!("{:08x}", c.n3_teid),
                    up_n3_addr: c.n3_addr,
                    selected_pdu_session_type: c.pdu_type.as_str().to_string(),
                    ue_ipv4_addr: c.ue_ip,
                    ue_ipv6_prefix: c.ue_ipv6.map(|(p, _)| format!("{p}/64")),
                    ue_ipv6_iid: c.ue_ipv6.map(|(_, iid)| hex::encode(iid)),
                    cause5gsm: None,
                    dns_ipv6: None, // DNS is only returned in the initial accept
                    s_nssai: c.snssai.clone(),
                    session_ambr: c.policy.session_ambr().cloned(),
                    qos_flows: c.policy.qos_flows(),
                }),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let Some(teid_hex) = req.gnb_n3_teid else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(gnb_addr) = req.gnb_n3_addr else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let gnb_teid = match u32::from_str_radix(teid_hex.trim_start_matches("0x"), 16) {
        Ok(t) => t,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    // Defense-in-depth on the downlink sink: reject an obviously bogus gNB target. The
    // real protection is SBI authorization (only the AMF may call Nsmf) — OAuth2 is
    // deferred (TS 33.501), same posture as the rest of SBI; the gNB F-TEID legitimately
    // comes from the AMF (which learned it from the N2 PDU Session Resource Setup).
    if !valid_gnb_target(gnb_teid, gnb_addr) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (up_seid, dnn, old_gnb, chain, path) = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => (c.up_seid, c.dnn.clone(), c.gnb, c.chain, c.path.clone()),
            None => return StatusCode::NOT_FOUND.into_response(),
        }
    };
    // A handover / path switch (the downlink is re-pointed from an existing gNB
    // tunnel to a *different* one) asks the UPF for a GTP-U End Marker on the old
    // path. A first activation or a Service-Request re-activation (no prior gNB, or
    // the same one) does not.
    let send_end_marker = old_gnb.is_some_and(|g| g != (gnb_teid, gnb_addr));
    if send_end_marker {
        tracing::info!(%sm_ref, "downlink re-point across a handover — requesting a GTP-U End Marker");
    }

    // Chained (design/134): the downlink FAR that faces the RAN lives on the I-UPF, so
    // the gNB target goes there. Order matters — install the RAN-facing hop first, then
    // re-open the anchor's downlink toward it, so anything the anchor buffered during an
    // AN release flushes onto a path that is already complete.
    if let Some(leg) = chain {
        let iupf = match &path.intermediate {
            Some(p) => p,
            // A context can only carry a leg if an I-UPF was on its path; a restart with
            // the chaining config removed would strand it.
            None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let seq = iupf.next_seq();
        let req = pfcp::session_modification_request(
            leg.up_seid, seq, FAR_ID, gnb_teid, gnb_addr, &dnn, send_end_marker,
        );
        match iupf.transact(&req, seq).await {
            Some(r) if pfcp::response_accepted(&r) => {}
            _ => return StatusCode::BAD_GATEWAY.into_response(),
        }
    }

    // The anchor's downlink: at the I-UPF's N9 ingress when chained, else at the gNB.
    let (dl_teid, dl_addr) = match chain {
        Some(leg) => leg.dl_ingress,
        None => (gnb_teid, gnb_addr),
    };
    let seq = path.anchor.next_seq();
    let mod_req = pfcp::session_modification_request(
        up_seid,
        seq,
        FAR_ID,
        dl_teid,
        dl_addr,
        &dnn,
        // The End Marker belongs on the tunnel that actually moved; when chained the
        // anchor's N9 path is unchanged across the handover.
        send_end_marker && chain.is_none(),
    );
    let resp = match path.anchor.transact(&mod_req, seq).await {
        Some(r) => r,
        None => return StatusCode::BAD_GATEWAY.into_response(),
    };
    if !pfcp::response_accepted(&resp) {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    // The breakout anchor's downlink was parked alongside the default one on AN release,
    // so it needs re-opening onto the same shared N9 ingress (design/134 Phase 2).
    if let Some(leg) = chain
        && let (Some(seid), Some((psa2, _))) = (leg.breakout_seid, &path.breakout)
        && let Err(e) = point_downlink_at(psa2, seid, leg.dl_ingress, &dnn).await
    {
        tracing::warn!(%sm_ref, "breakout anchor downlink not restored: {e}");
        return StatusCode::BAD_GATEWAY.into_response();
    }

    if let Some(c) = smf.contexts.lock().unwrap().get_mut(&sm_ref) {
        c.gnb = Some((gnb_teid, gnb_addr));
        tracing::info!(
            %sm_ref,
            ue_ip = ?c.ue_ip,
            uplink_teid = c.n3_teid,
            gnb_teid,
            "updated SM context; N4 downlink installed"
        );
    }
    StatusCode::OK.into_response()
}

/// Deactivate a session's downlink user-plane connection (AN release): an N4
/// Session Modification that DROPs downlink at the UPF and clears the stored gNB
/// target. The session and its uplink path persist for a later Service Request.
async fn deactivate_up(smf: &Arc<SmfState>, sm_ref: &str) -> StatusCode {
    let (up_seid, chain, path) = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(sm_ref) {
            Some(c) => (c.up_seid, c.chain, c.path.clone()),
            None => return StatusCode::NOT_FOUND,
        }
    };
    let seq = path.anchor.next_seq();
    let req = pfcp::session_deactivate_request(up_seid, seq, FAR_ID);
    let resp = match path.anchor.transact(&req, seq).await {
        Some(r) => r,
        None => return StatusCode::BAD_GATEWAY,
    };
    if !pfcp::response_accepted(&resp) {
        return StatusCode::BAD_GATEWAY;
    }
    // Park the breakout anchor's downlink too, or it would keep forwarding to an I-UPF
    // still pointed at the released gNB tunnel. It drops rather than buffers: only the
    // default anchor carries the URRs that turn a buffered packet into a paging request,
    // so downlink arriving for an idle UE *on the breakout DN* is lost (design/134 §4).
    if let (Some(leg), Some((psa2, _))) = (chain, &path.breakout)
        && let Some(seid) = leg.breakout_seid
    {
        let seq = psa2.next_seq();
        let req = pfcp::session_deactivate_request(seid, seq, FAR_ID);
        match psa2.transact(&req, seq).await {
            Some(r) if pfcp::response_accepted(&r) => {}
            _ => tracing::warn!(%sm_ref, "breakout anchor did not accept the deactivation"),
        }
    }
    if let Some(c) = smf.contexts.lock().unwrap().get_mut(sm_ref) {
        c.gnb = None;
        tracing::info!(%sm_ref, up_seid, "deactivated UP connection (AN release); downlink buffered at the UPF");
    }
    StatusCode::OK
}

/// Set up (or release) an **indirect data forwarding** tunnel for an N2 handover
/// (TS 23.502 §4.9.1.3.3). With `release`, the forwarding session is deleted;
/// otherwise the SMF establishes a UPF forwarding session toward the target gNB's
/// DL forwarding F-TEID and returns the UPF-allocated ingress F-TEID the source
/// gNB forwards to.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndirectForwardingReq {
    #[serde(default)]
    target_n3_teid: Option<String>,
    #[serde(default)]
    target_n3_addr: Option<Ipv4Addr>,
    #[serde(default)]
    release: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct IndirectForwardingRsp {
    fwd_n3_teid: String,
    fwd_n3_addr: Ipv4Addr,
}

async fn indirect_forwarding(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
    Json(req): Json<IndirectForwardingReq>,
) -> axum::response::Response {
    if req.release {
        // Tear the forwarding session down (idempotent: no tunnel → 204). The forwarding
        // session lives on the session's anchor, so it is deleted there.
        let taken = {
            let mut ctxs = smf.contexts.lock().unwrap();
            ctxs.get_mut(&sm_ref)
                .and_then(|c| c.indirect_fwd.take().map(|seid| (seid, c.path.anchor.clone())))
        };
        let Some((fwd_seid, anchor)) = taken else {
            return StatusCode::NO_CONTENT.into_response();
        };
        let seq = anchor.next_seq();
        match anchor.transact(&pfcp::session_deletion_request(fwd_seid, seq), seq).await {
            Some(r) if pfcp::response_accepted(&r) => {
                tracing::info!(%sm_ref, "released the indirect forwarding tunnel");
                return StatusCode::NO_CONTENT.into_response();
            }
            _ => return StatusCode::BAD_GATEWAY.into_response(),
        }
    }
    // Set up: needs the target gNB's DL forwarding F-TEID.
    let (Some(teid_hex), Some(target_addr)) = (req.target_n3_teid, req.target_n3_addr) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(target_teid) = u32::from_str_radix(teid_hex.trim_start_matches("0x"), 16) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // The forwarding session is established on the session's own anchor.
    let anchor = match smf.contexts.lock().unwrap().get(&sm_ref) {
        Some(c) => c.path.anchor.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
    let seq = anchor.next_seq();
    let est = pfcp::session_establishment_request_indirect_forwarding(
        cp_seid,
        seq,
        smf.smf_ip,
        target_teid,
        target_addr,
    );
    let resp = match anchor.transact(&est, seq).await {
        Some(r) => r,
        None => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let Some(session) = pfcp::parse_session_establishment_response(&resp) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if let Some(c) = smf.contexts.lock().unwrap().get_mut(&sm_ref) {
        c.indirect_fwd = Some(session.up_seid);
    }
    tracing::info!(
        %sm_ref,
        ingress_teid = format!("{:08x}", session.n3_teid),
        target_teid = format!("{target_teid:08x}"),
        "indirect forwarding tunnel up (source → UPF → target)"
    );
    (
        StatusCode::OK,
        Json(IndirectForwardingRsp {
            fwd_n3_teid: format!("{:08x}", session.n3_teid),
            fwd_n3_addr: session.n3_addr,
        }),
    )
        .into_response()
}

/// The PDR/FAR index a mid-session breakout occupies on the classifier. A live session
/// chained without a breakout carries no establishment-time branches, so index 0 is free;
/// the SMF inserts and removes exactly this one branch (design/134 Phase 3e).
const MID_SESSION_BREAKOUT_INDEX: usize = 0;

/// Default base other NFs use to reach this SMF's SBI (overridable — see
/// [`SmfState::with_callback_base`]).
const DEFAULT_CALLBACK_BASE: &str = "http://127.0.0.1:8002";

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BreakoutReq {
    supi: String,
    /// Identify the session by PDU-session id (the OAM/Phase-3e path) …
    #[serde(default)]
    pdu_session_id: Option<u8>,
    /// … or by DNN (the AF/NEF path — an AF targets a DN, not a specific session,
    /// design/135). At least one selector is required; both narrow the match.
    #[serde(default)]
    dnn: Option<String>,
    /// The destination prefix to steer (CIDR). Required on insert, ignored on remove.
    #[serde(default)]
    prefix: Option<String>,
    /// The breakout anchor's UP-node name — or, from a NEF, resolved from `dnai`. Required
    /// (directly or via `dnai`) on insert, ignored on remove.
    #[serde(default)]
    via: Option<String>,
    /// A **DNAI** to resolve to a breakout node via the topology (the AF/NEF names a DNAI,
    /// not a UP node, design/135). Used when `via` is absent.
    #[serde(default)]
    dnai: Option<String>,
    /// Remove the breakout instead of inserting one.
    #[serde(default)]
    remove: bool,
}

/// OAM / Nnef: insert or remove an **uplink-classifier breakout** on a live PDU session
/// (design/134 Phase 3e). The session must be **chained** (its classifier is the
/// intermediate UPF, the only node that sees uplink before it is committed to an anchor).
/// This is the N4 mechanism behind AF traffic influence (design/135): a NEF resolves an AF
/// request to `(supi, dnn, prefix, dnai)` and posts it here; the raw OAM caller may address
/// by `(supi, pduSessionId, prefix, via)` instead.
async fn oam_breakout(
    State(smf): State<Arc<SmfState>>,
    Json(req): Json<BreakoutReq>,
) -> axum::response::Response {
    if req.pdu_session_id.is_none() && req.dnn.is_none() {
        return (StatusCode::BAD_REQUEST, "supply pduSessionId or dnn").into_response();
    }
    // Find the session by (SUPI [+ PDU-session id] [+ DNN]) — an AF targets a UE on a DNN,
    // the OAM caller a specific session; either narrows the same scan.
    let found = {
        let ctxs = smf.contexts.lock().unwrap();
        ctxs.iter()
            .find(|(_, c)| {
                c.supi == req.supi
                    && req.pdu_session_id.is_none_or(|psi| c.pdu_session_id == psi)
                    && req.dnn.as_deref().is_none_or(|d| c.dnn == d)
            })
            .map(|(r, c)| {
                (r.clone(), c.chain, c.dnn.clone(), c.path.clone(), c.ue_ip, c.ue_ipv6)
            })
    };
    let Some((sm_ref, chain, dnn, path, ue_ip, ue_ipv6)) = found else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // A breakout needs a classifier, which is the session's intermediate UPF.
    let (Some(leg), Some(iupf)) = (chain, path.intermediate.clone()) else {
        return (StatusCode::CONFLICT, "session is not chained; no classifier to branch at")
            .into_response();
    };

    if req.remove {
        remove_breakout(&smf, &sm_ref, &leg, &iupf, &path).await
    } else {
        // The breakout target: an explicit UP-node name, or a DNAI resolved via the topology.
        let via = req.via.clone().or_else(|| req.dnai.as_deref().and_then(|d| smf.node_for_dnai(d)));
        let (Some(prefix), Some(via)) = (req.prefix, via) else {
            return (StatusCode::BAD_REQUEST, "supply prefix and via/dnai").into_response();
        };
        let ue = pfcp::UeAddr { v4: ue_ip, v6: ue_ipv6.map(|(p, _)| p) };
        insert_breakout(&smf, &sm_ref, &leg, &iupf, ue, &dnn, &prefix, &via).await
    }
}

/// Splice a breakout anchor into a live chained session: establish its N4 session, point
/// its downlink back at the classifier's shared N9 ingress, then add a branch on the
/// classifier steering `prefix` to it — the mid-session build of Phase 2's two-anchor split.
#[allow(clippy::too_many_arguments)]
async fn insert_breakout(
    smf: &Arc<SmfState>,
    sm_ref: &str,
    leg: &ChainedLeg,
    iupf: &N4Peer,
    ue: pfcp::UeAddr,
    dnn: &str,
    prefix: &str,
    via: &str,
) -> axum::response::Response {
    if leg.breakout_seid.is_some() {
        return (StatusCode::CONFLICT, "the session already has a breakout").into_response();
    }
    let Ok(prefix) = prefix.parse::<pfcp::IpPrefix>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(psa2) = smf.peer_by_name(via) else {
        return (StatusCode::NOT_FOUND, "unknown breakout UP node").into_response();
    };

    // 1. Establish the breakout anchor's session (no URRs — only the default anchor meters).
    let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
    let seq = psa2.next_seq();
    let req = pfcp::session_establishment_request(cp_seid, seq, smf.smf_ip, ue, dnn, None, &[], None);
    let est = match psa2.transact(&req, seq).await.and_then(|r| pfcp::parse_session_establishment_response(&r)) {
        Some(e) => e,
        None => return StatusCode::BAD_GATEWAY.into_response(),
    };
    // 2. Point its downlink at the classifier's N9 ingress — the shared return path.
    if point_downlink_at(&psa2, est.up_seid, leg.dl_ingress, dnn).await.is_err() {
        let seq = psa2.next_seq();
        let _ = psa2.transact(&pfcp::session_deletion_request(est.up_seid, seq), seq).await;
        return StatusCode::BAD_GATEWAY.into_response();
    }
    // 3. Add the classifier branch steering the prefix to the breakout anchor.
    let seq = iupf.next_seq();
    let egress = pfcp::Egress::ToPeer { teid: est.n3_teid, addr: est.n3_addr };
    let filter = pfcp::FlowFilter::to_prefix(prefix);
    let add =
        pfcp::session_modification_add_branch(leg.up_seid, seq, MID_SESSION_BREAKOUT_INDEX, filter, egress, dnn);
    match iupf.transact(&add, seq).await {
        Some(r) if pfcp::response_accepted(&r) => {}
        _ => {
            let seq = psa2.next_seq();
            let _ = psa2.transact(&pfcp::session_deletion_request(est.up_seid, seq), seq).await;
            return StatusCode::BAD_GATEWAY.into_response();
        }
    }
    // 4. Record the breakout on the context so re-activation / release address it.
    if let Some(c) = smf.contexts.lock().unwrap().get_mut(sm_ref) {
        if let Some(leg) = &mut c.chain {
            leg.breakout_seid = Some(est.up_seid);
        }
        c.path.breakout = Some((psa2, prefix));
    }
    tracing::info!(%sm_ref, %prefix, breakout_seid = est.up_seid, "inserted a mid-session ULCL breakout");
    StatusCode::OK.into_response()
}

/// Undo [`insert_breakout`]: remove the classifier branch and delete the breakout anchor's
/// N4 session.
async fn remove_breakout(
    smf: &Arc<SmfState>,
    sm_ref: &str,
    leg: &ChainedLeg,
    iupf: &N4Peer,
    path: &SessionPath,
) -> axum::response::Response {
    let (Some(breakout_seid), Some((psa2, _))) = (leg.breakout_seid, &path.breakout) else {
        return (StatusCode::CONFLICT, "the session has no breakout").into_response();
    };
    // 1. Remove the classifier branch — the prefix falls back to the default anchor.
    let seq = iupf.next_seq();
    let remove = pfcp::session_modification_remove_branch(leg.up_seid, seq, MID_SESSION_BREAKOUT_INDEX);
    match iupf.transact(&remove, seq).await {
        Some(r) if pfcp::response_accepted(&r) => {}
        _ => return StatusCode::BAD_GATEWAY.into_response(),
    }
    // 2. Delete the breakout anchor's session.
    let seq = psa2.next_seq();
    match psa2.transact(&pfcp::session_deletion_request(breakout_seid, seq), seq).await {
        Some(r) if pfcp::response_accepted(&r) => {}
        _ => tracing::warn!(%sm_ref, breakout_seid, "breakout anchor did not accept the deletion"),
    }
    // 3. Clear the breakout from the context.
    if let Some(c) = smf.contexts.lock().unwrap().get_mut(sm_ref) {
        if let Some(leg) = &mut c.chain {
            leg.breakout_seid = None;
        }
        c.path.breakout = None;
    }
    tracing::info!(%sm_ref, breakout_seid, "removed the mid-session ULCL breakout");
    StatusCode::OK.into_response()
}

/// `Nsmf_PDUSession_ReleaseSMContext` (TS 29.502 §5.2.2.4): tear the N4 session
/// down at the UPF and drop the SM context. Driven by the AMF on deregistration.
async fn release_sm_context(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
) -> Result<StatusCode, SbiProblem> {
    let (up_seid, chain, path, supi, psi, sm_policy, reserved_gfbr, charging, policy, ue_ip, ue_ipv6) = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => (
                c.up_seid,
                c.chain,
                c.path.clone(),
                c.supi.clone(),
                c.pdu_session_id,
                c.sm_policy.clone(),
                c.reserved_gfbr,
                c.charging.clone(),
                c.policy.clone(),
                c.ue_ip,
                c.ue_ipv6,
            ),
            None => {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "CONTEXT_NOT_FOUND",
                    "unknown SM context",
                ))
            }
        }
    };
    let seq = path.anchor.next_seq();
    let del = pfcp::session_deletion_request(up_seid, seq);
    // Keep the context if the UPF is unreachable (the AMF may retry); a non-accepted
    // answer means the UPF already lost the session — drop our side anyway.
    let resp = path.anchor.transact(&del, seq).await.ok_or_else(|| {
        problem(StatusCode::BAD_GATEWAY, "UPF_NOT_RESPONDING", "no PFCP deletion response")
    })?;
    if !pfcp::response_accepted(&resp) {
        tracing::warn!(%sm_ref, up_seid, "UPF did not accept the N4 deletion (already gone?)");
    }
    // Tear the other legs down too. The default anchor carries the URRs, so its deletion
    // response above is the one that bears the usage — the others' are discarded.
    if let (Some(leg), Some(iupf)) = (chain, &path.intermediate) {
        let seq = iupf.next_seq();
        let del = pfcp::session_deletion_request(leg.up_seid, seq);
        match iupf.transact(&del, seq).await {
            Some(r) if pfcp::response_accepted(&r) => {}
            _ => tracing::warn!(%sm_ref, iupf_seid = leg.up_seid, "intermediate UPF did not accept the N4 deletion"),
        }
        if let (Some(seid), Some((psa2, _))) = (leg.breakout_seid, &path.breakout) {
            let seq = psa2.next_seq();
            let del = pfcp::session_deletion_request(seid, seq);
            match psa2.transact(&del, seq).await {
                Some(r) if pfcp::response_accepted(&r) => {}
                _ => tracing::warn!(%sm_ref, breakout_seid = seid, "breakout anchor did not accept the N4 deletion"),
            }
        }
    }
    // Final usage reports: the session URR plus each per-flow URR. Logged, and —
    // when the session has a charging session — released toward the CHF with the
    // final used-unit containers (best-effort, off the path).
    let usages = pfcp::usages_from_deletion_response(&resp);
    if let Some((total, ul, dl)) = pfcp::usage_from_deletion_response(&resp) {
        tracing::info!(%sm_ref, up_seid, total_bytes = total, uplink_bytes = ul, downlink_bytes = dl, urrs = usages.len(), "session usage report");
    }
    if let Some((chf_base, charging_ref)) = charging {
        let release = sbi_core::nchf::ChargingDataRequest {
            subscriber_identifier: supi.clone(),
            pdu_session_charging_information: None,
            used_unit_containers: usages.iter().map(|u| container_for(u, &policy)).collect(),
        };
        let chf = chf_client(&smf.nrf_base, chf_base);
        tokio::spawn(async move {
            match chf.release(&charging_ref, &release).await {
                Ok(()) => tracing::info!(charging_ref = %charging_ref, "charging session released at the CHF"),
                Err(e) => tracing::warn!("Nchf release failed: {e}"),
            }
        });
    }
    smf.contexts.lock().unwrap().remove(&sm_ref);
    // Return the UE address(es) to the pool so they can be re-allocated (design/137 G6).
    if let Some(v4) = ue_ip {
        smf.release_ue_ip(v4);
    }
    if let Some((prefix, _)) = ue_ipv6 {
        smf.release_ue_ipv6(prefix);
    }
    // Free the GFBR admission reservation.
    smf.release_gfbr(reserved_gfbr);
    // Purge the serving-SMF registration (Nudm_UECM). Best-effort, off the path.
    spawn_uecm_purge(smf.nrf_base.clone(), supi, psi);
    // Delete the PCF SM policy association (Npcf_SMPolicyControl_Delete), if the
    // session had one. Best-effort, off the path.
    if let Some((pcf_base, policy_id)) = sm_policy {
        spawn_sm_policy_delete(smf.nrf_base.clone(), pcf_base, policy_id);
    }
    tracing::info!(%sm_ref, up_seid, "released SM context; N4 session deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// Map one URR usage volume to an Nchf used-unit container. The session-level URR is
/// rating group `0`; a per-flow URR (`PER_FLOW_URR_BASE + qfi`) is charged under the
/// rating group of its flow's PCF charging decision (`QosFlowPolicy.ref_chg_data` →
/// `SmPolicyDecision.charging_descs`), falling back to the legacy
/// rating-group-equals-QFI convention when the flow has no charging decision.
fn container_for(
    u: &pfcp::UsageVolume,
    decision: &sbi_core::npcf::SmPolicyDecision,
) -> sbi_core::nchf::UsedUnitContainer {
    let rating_group = match u.urr_id.checked_sub(pfcp::PER_FLOW_URR_BASE) {
        Some(qfi) => decision.rating_group_for(qfi as u8).unwrap_or(qfi),
        None => 0, // the session-level URR
    };
    sbi_core::nchf::UsedUnitContainer {
        rating_group,
        uplink_volume: u.uplink,
        downlink_volume: u.downlink,
        total_volume: u.total,
    }
}

/// Consume **UPF-initiated Session Report Requests** (volume-threshold usage
/// reports, design/59): ack each toward the UPF and relay the usage to the CHF as
/// an Nchf update (the mid-session charging trigger). Spawned once alongside the
/// SBI server; ends if the N4 reader closes.
pub async fn handle_usage_reports(smf: Arc<SmfState>) {
    loop {
        let report = { smf.reports_rx.lock().await.recv().await };
        let Some(report) = report else { break };
        // A Downlink Data Report: downlink data arrived for a CM-IDLE UE — ack it
        // and ask the AMF to page the UE (TS 23.502 §4.2.3.3).
        if let Some((cp_seid, seq)) = pfcp::parse_dl_data_report(&report) {
            handle_dl_data_report(&smf, cp_seid, seq).await;
            continue;
        }
        let Some((cp_seid, seq, usage)) = pfcp::parse_session_report_request(&report) else {
            continue;
        };
        // The report addresses the session by OUR (CP) F-SEID.
        let ctx = {
            let ctxs = smf.contexts.lock().unwrap();
            ctxs.values().find(|c| c.cp_seid == cp_seid).map(|c| {
                (c.up_seid, c.supi.clone(), c.charging.clone(), c.policy.clone(), c.path.anchor.clone())
            })
        };
        let Some((up_seid, supi, charging, policy, anchor)) = ctx else {
            tracing::warn!(cp_seid, "usage report for an unknown session — dropped");
            continue;
        };
        // Ack on the session's own anchor socket (only anchors carry URRs, so that is the
        // association the report arrived on). The usage stands measured either way.
        if let Err(e) = anchor.sock.send(&pfcp::session_report_response(up_seid, seq)).await {
            tracing::warn!("session report ack send error: {e}");
        }
        tracing::info!(
            up_seid,
            total_bytes = usage.total,
            uplink_bytes = usage.uplink,
            downlink_bytes = usage.downlink,
            "usage threshold report from the UPF"
        );
        // Relay to the CHF (Nchf update) when the session is billed.
        if let Some((chf_base, charging_ref)) = charging {
            let update = sbi_core::nchf::ChargingDataRequest {
                subscriber_identifier: supi,
                pdu_session_charging_information: None,
                used_unit_containers: vec![container_for(&usage, &policy)],
            };
            match chf_client(&smf.nrf_base, chf_base).update(&charging_ref, &update).await {
                Ok(()) => tracing::info!(charging_ref = %charging_ref, "usage relayed to the CHF"),
                Err(e) => tracing::warn!("Nchf update failed: {e}"),
            }
        }
    }
}

/// Downlink Data Report handling: ack the UPF, then ask the serving AMF to page
/// the CM-IDLE UE (Namf_Communication_N1N2MessageTransfer). The UE answers with a
/// Service Request, which re-activates the session — and the UPF flushes the
/// buffered downlink onto the restored tunnel.
async fn handle_dl_data_report(smf: &Arc<SmfState>, cp_seid: u64, seq: u32) {
    let ctx = {
        let ctxs = smf.contexts.lock().unwrap();
        ctxs.values()
            .find(|c| c.cp_seid == cp_seid)
            .map(|c| (c.up_seid, c.supi.clone(), c.path.anchor.clone()))
    };
    let Some((up_seid, supi, anchor)) = ctx else {
        tracing::warn!(cp_seid, "downlink data report for an unknown session — dropped");
        return;
    };
    if let Err(e) = anchor.sock.send(&pfcp::session_report_response(up_seid, seq)).await {
        tracing::warn!("downlink data report ack send error: {e}");
    }
    tracing::info!(up_seid, "downlink data for a CM-IDLE UE — requesting paging at the AMF");
    // Discover the serving AMF and ask it to page (best-effort, off the path).
    match discover_endpoint(&smf.nrf_base, "AMF").await {
        Ok(amf) => {
            let url = format!("{amf}/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages");
            match sbi_core::sbi_client().post(url).json(&serde_json::json!({})).traced().send().await {
                Ok(r) if r.status().is_success() => tracing::info!("AMF paging requested"),
                Ok(r) => tracing::warn!(status = %r.status(), "AMF paging request refused"),
                Err(e) => tracing::warn!("AMF paging request failed: {e}"),
            }
        }
        Err(e) => tracing::warn!("no AMF to page ({e})"),
    }
}

/// Re-authorize this session's policy at the PCF (`Npcf_SMPolicyControl_Update`)
/// and refresh the sm-context's stored QoS. A trigger for a **mid-session policy
/// change** (e.g. an operator/OAM policy update landing in the UDR): the PCF
/// re-reads the subscriber's Nudr policy-data and returns the current decision.
///
/// When the QoS changed, the SMF propagates it two ways: onto the **user plane**
/// (an N4 Session Modification with an Update QER re-rates the UPF's AMBR policer),
/// and to the **RAN/UE** via the serving AMF (Namf_Communication →
/// N2 PDU Session Resource Modify + N1 PDU Session Modification Command,
/// best-effort). Returns `200` + the (possibly changed) decision; `204` when the
/// session used the sm-data fallback (no PCF association); `404` for an unknown
/// context.
///
/// Bring the session's live ULCL breakout into line with the **AF influence** its SM
/// policy carries (design/135). A traffic-control decision naming a route (prefix → DNAI)
/// means the session should have a breakout; its absence means it should not. Run both at
/// **establishment** (so a group / any-UE influence already in the policy applies to a new
/// session, Phase 3) and on every **policy refresh** (so an influence arriving mid-session
/// applies to a live one, Phase 2).
///
/// Two things are deliberately left alone: a session whose DNN owns a *static* topology
/// route (that breakout is config-owned), and a breakout installed **directly** (OAM, or a
/// NEF with no PCF) — such a breakout is not expressed in the policy, so its absence there
/// says nothing about it. `policy_breakout` records which breakouts policy owns.
async fn reconcile_influence_breakout(smf: &Arc<SmfState>, sm_ref: &str) {
    let snapshot = {
        let ctxs = smf.contexts.lock().unwrap();
        ctxs.get(sm_ref).map(|c| {
            (
                c.chain,
                c.path.clone(),
                c.dnn.clone(),
                c.ue_ip,
                c.ue_ipv6,
                c.policy_breakout,
                c.policy.influence_route(),
            )
        })
    };
    let Some((chain, path, dnn, ue_ip, ue_ipv6, policy_breakout, desired)) = snapshot else {
        return;
    };
    // A breakout needs a classifier — the session's intermediate UPF.
    let (Some(leg), Some(iupf)) = (chain, path.intermediate.as_deref()) else { return };
    if smf.dnn_has_config_route(&dnn) {
        return;
    }
    match (desired, leg.breakout_seid.is_some()) {
        (Some((prefix, dnai)), false) => match smf.node_for_dnai(&dnai) {
            Some(via) => {
                let ue = pfcp::UeAddr { v4: ue_ip, v6: ue_ipv6.map(|(p, _)| p) };
                let r = insert_breakout(smf, sm_ref, &leg, iupf, ue, &dnn, &prefix, &via).await;
                // Remember that *policy* owns this breakout, so a later refresh that sees
                // no influence may withdraw it.
                if r.status().is_success()
                    && let Some(c) = smf.contexts.lock().unwrap().get_mut(sm_ref)
                {
                    c.policy_breakout = true;
                }
                tracing::info!(%sm_ref, %prefix, %dnai, status = ?r.status(), "AF-influenced breakout inserted from SM policy");
            }
            None => tracing::warn!(%sm_ref, %dnai, "AF influence names a DNAI with no UP node"),
        },
        (None, true) if policy_breakout => {
            let r = remove_breakout(smf, sm_ref, &leg, iupf, &path).await;
            if r.status().is_success()
                && let Some(c) = smf.contexts.lock().unwrap().get_mut(sm_ref)
            {
                c.policy_breakout = false;
            }
            tracing::info!(%sm_ref, status = ?r.status(), "AF-influenced breakout withdrawn from SM policy");
        }
        _ => {} // already in the desired state, or a directly-installed breakout
    }
}

async fn refresh_sm_policy(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
) -> Result<axum::response::Response, SbiProblem> {
    let (sm_policy, up_seid, old_policy, supi, psi, anchor) = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => (
                c.sm_policy.clone(),
                c.up_seid,
                c.policy.clone(),
                c.supi.clone(),
                c.pdu_session_id,
                c.path.anchor.clone(),
            ),
            None => {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "CONTEXT_NOT_FOUND",
                    "unknown SM context",
                ))
            }
        }
    };
    let Some((pcf_base, policy_id)) = sm_policy else {
        // sm-data fallback session — no PCF association to re-authorize.
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let update = pcf_client(&smf.nrf_base, pcf_base)
        .update_sm_policy(&policy_id, &sbi_core::npcf::SmPolicyUpdateContextData::default())
        .await
        .map_err(|e| {
            tracing::warn!(%sm_ref, "PCF SM policy update failed: {e}");
            problem(StatusCode::BAD_GATEWAY, "PCF_UNREACHABLE", "Npcf SM policy update failed")
        })?;
    // The Update response is a partial delta — merge it onto the stored policy to
    // recover the full authorized decision, keeping any attribute the PCF omitted.
    let mut decision = old_policy.clone();
    decision.apply(&update);
    let changed = old_policy != decision;

    // Propagate a changed session AMBR onto the user plane: re-rate the UPF's QER.
    let old_ambr = ambr_bps(&old_policy);
    let new_ambr = ambr_bps(&decision);
    if new_ambr != old_ambr {
        if let Some(ambr) = new_ambr {
            let seq = anchor.next_seq();
            let req = pfcp::session_qer_update_request(up_seid, seq, ambr);
            match anchor.transact(&req, seq).await {
                Some(resp) if pfcp::response_accepted(&resp) => tracing::info!(
                    %sm_ref, up_seid, "N4 QER re-rated: session AMBR now {}/{} bps",
                    ambr.uplink_bps, ambr.downlink_bps
                ),
                _ => tracing::warn!(%sm_ref, up_seid, "N4 QER update not accepted by the UPF"),
            }
        }
    }
    // Propagate per-flow (GBR) changes onto the user plane: add/re-rate/remove the
    // UPF's per-flow QERs to match the new decision.
    let old_flows = flow_qers(&old_policy);
    let new_flows = flow_qers(&decision);
    let (create, update, remove) = diff_flows(&old_flows, &new_flows);
    if !create.is_empty() || !update.is_empty() || !remove.is_empty() {
        let seq = anchor.next_seq();
        let req = pfcp::session_flow_modification_request(up_seid, seq, &create, &update, &remove);
        match anchor.transact(&req, seq).await {
            Some(resp) if pfcp::response_accepted(&resp) => tracing::info!(
                %sm_ref, up_seid, added = create.len(), updated = update.len(), removed = remove.len(),
                "N4 per-flow QERs updated"
            ),
            _ => tracing::warn!(%sm_ref, up_seid, "N4 per-flow QER update not accepted by the UPF"),
        }
    }
    // GBR flows fully gone from the new policy — released toward the RAN/UE (distinct
    // from the N4 `remove` above, which also covers filter-changed/re-provisioned QFIs).
    let released_qfis: Vec<u8> = old_flows
        .iter()
        .filter(|o| !new_flows.iter().any(|n| n.qfi == o.qfi))
        .map(|o| o.qfi)
        .collect();
    // Adjust the GFBR reservation to the new decision (best-effort — the PCF already
    // authorized it, so a mid-session increase isn't admission-refused here).
    let new_gfbr = decision_gfbr(&decision);
    // Refresh the sm-context's authoritative QoS record.
    if let Some(c) = smf.contexts.lock().unwrap().get_mut(&sm_ref) {
        if c.reserved_gfbr != new_gfbr {
            smf.adjust_gfbr(c.reserved_gfbr, new_gfbr);
            c.reserved_gfbr = new_gfbr;
        }
        c.policy = decision.clone();
    }
    // design/135 Phase 2: reconcile an **AF-influenced breakout** with the refreshed
    // decision. A traffic-control decision naming a route (prefix → DNAI) means the SMF
    // should have a live ULCL breakout; its absence means it should not. Only for a
    // chained session whose breakout is *not* config-driven (a static topology route owns
    // its own breakout — policy must not disturb it).
    reconcile_influence_breakout(&smf, &sm_ref).await;
    // Signal the change to the RAN/UE via the serving AMF (Namf_Communication →
    // N2 PDU Session Resource Modify + N1 PDU Session Modification Command).
    // Best-effort, off the response path — only when the QoS actually changed.
    if changed {
        tracing::info!(%sm_ref, flows = decision.qos_flows().len(), released = ?released_qfis, "SM policy refreshed from PCF (QoS changed)");
        spawn_amf_pdu_modify(smf.nrf_base.clone(), supi, psi, decision.clone(), released_qfis);
    }
    Ok((StatusCode::OK, Json(decision)).into_response())
}

/// Push a mid-session QoS change to the serving AMF (Namf_Communication), which
/// signals the RAN/UE (N2 PDU Session Resource Modify + N1 PDU Session Modification
/// Command), including any `released_qfis` (GBR flows to tear down). Best-effort,
/// spawned off the refresh path; the AMF is discovered via the NRF (single-AMF demo
/// — a real deployment would use the UECM serving AMF).
fn spawn_amf_pdu_modify(
    nrf_base: String,
    supi: String,
    psi: u8,
    decision: sbi_core::npcf::SmPolicyDecision,
    released_qfis: Vec<u8>,
) {
    tokio::spawn(async move {
        let amf = match discover_endpoint(&nrf_base, "AMF").await {
            Ok(base) => base,
            Err(e) => {
                tracing::warn!(psi, "PDU modify: no AMF to notify ({e})");
                return;
            }
        };
        let body = serde_json::json!({
            "pduSessionId": psi,
            "sessionAmbr": decision.session_ambr(),
            "qosFlows": decision.qos_flows(),
            "releasedQfis": released_qfis,
        });
        let url = format!("{amf}/namf-comm/v1/ue-contexts/{supi}/modify");
        match sbi_core::sbi_client().post(url).json(&body).traced().send().await {
            Ok(r) if r.status().is_success() => {
                tracing::info!(psi, "notified serving AMF of the mid-session QoS change")
            }
            Ok(r) => tracing::warn!(psi, status = %r.status(), "AMF PDU modify rejected"),
            Err(e) => tracing::warn!(psi, "AMF PDU modify call failed: {e}"),
        }
    });
}

/// The aggregate GFBR `(downlink_bps, uplink_bps)` a decision's GBR flows require —
/// the input to GFBR admission control. A flow whose GFBR strings don't parse
/// contributes 0 (it can't be admission-checked).
fn decision_gfbr(decision: &sbi_core::npcf::SmPolicyDecision) -> (u64, u64) {
    decision.qos_flows().iter().filter_map(|f| f.gbr.as_ref()).fold((0u64, 0u64), |(dl, ul), g| {
        (
            dl.saturating_add(sbi_core::npcf::bitrate_to_bps(&g.gfbr_dl).unwrap_or(0)),
            ul.saturating_add(sbi_core::npcf::bitrate_to_bps(&g.gfbr_ul).unwrap_or(0)),
        )
    })
}

/// The per-flow GBR QERs (classifier + MFBR) for the UPF, from a decision's GBR
/// flows that carry a packet filter. Non-GBR / filterless flows stay on the session
/// AMBR; a flow whose MFBR strings don't parse is skipped.
fn flow_qers(decision: &sbi_core::npcf::SmPolicyDecision) -> Vec<pfcp::FlowQer> {
    decision
        .qos_flows()
        .iter()
        .filter_map(|f| {
            let gbr = f.gbr.as_ref()?;
            let filter = f.filter.as_ref()?;
            let (uplink, downlink) = f.flow_status.gate();
            Some(pfcp::FlowQer {
                qfi: f.qfi,
                filter: pfcp::FlowFilter::transport(
                    filter.protocol,
                    filter.port_low,
                    filter.port_high,
                ),
                mfbr_dl_bps: sbi_core::npcf::bitrate_to_bps(&gbr.mfbr_dl)?,
                mfbr_ul_bps: sbi_core::npcf::bitrate_to_bps(&gbr.mfbr_ul)?,
                // The PCC rule's flowStatus becomes the flow's QER gate (design/151).
                gate: pfcp::Gate { uplink, downlink },
            })
        })
        .collect()
}

/// Diff the old vs new per-flow QERs into `(create, update, remove_qfis)` for a
/// mid-session flow modification: a new/filter-changed QFI is created (and, if the
/// filter changed, its old flow removed), an MFBR-only change is an update, and a
/// dropped QFI is removed. The UPF applies remove → create → update.
fn diff_flows(
    old: &[pfcp::FlowQer],
    new: &[pfcp::FlowQer],
) -> (Vec<pfcp::FlowQer>, Vec<pfcp::FlowQer>, Vec<u8>) {
    let (mut create, mut update, mut remove) = (Vec::new(), Vec::new(), Vec::new());
    for n in new {
        match old.iter().find(|o| o.qfi == n.qfi) {
            None => create.push(*n),
            Some(o) if o.filter != n.filter => create.push(*n),
            // An MFBR re-rate or a gate (flowStatus) flip is a mid-session update.
            Some(o)
                if (o.mfbr_dl_bps, o.mfbr_ul_bps, o.gate)
                    != (n.mfbr_dl_bps, n.mfbr_ul_bps, n.gate) =>
            {
                update.push(*n)
            }
            Some(_) => {}
        }
    }
    for o in old {
        if !new.iter().any(|n| n.qfi == o.qfi && n.filter == o.filter) {
            remove.push(o.qfi);
        }
    }
    (create, update, remove)
}

/// The session AMBR from a policy decision as a `pfcp::SessionAmbr` (bits/sec) for
/// the UPF's QER — `None` when the decision has no (parseable) session AMBR.
fn ambr_bps(decision: &sbi_core::npcf::SmPolicyDecision) -> Option<pfcp::SessionAmbr> {
    decision
        .session_ambr()
        .and_then(|a| a.to_bps())
        .map(|(uplink_bps, downlink_bps)| pfcp::SessionAmbr { uplink_bps, downlink_bps })
}

/// Register this SMF as the serving SMF for `(supi, pdu_session_id)` at the UDM
/// (Nudm_UECM). Best-effort, spawned off the signaling path.
fn spawn_uecm_register(nrf_base: String, supi: String, pdu_session_id: u8, dnn: String) {
    tokio::spawn(async move {
        let reg = sbi_core::nudm::SmfRegistration {
            smf_instance_id: SMF_INSTANCE_ID.clone(),
            pdu_session_id,
            dnn,
        };
        match discover_udm(&nrf_base).await {
            Ok(udm) => {
                if let Err(e) =
                    udm_client(&nrf_base, udm).uecm_register_smf(&supi, &reg).await
                {
                    tracing::warn!(psi = pdu_session_id, "UECM SMF registration failed: {e}");
                } else {
                    tracing::info!(psi = pdu_session_id, "UECM: registered as the serving SMF");
                }
            }
            Err(e) => tracing::warn!("UECM SMF registration skipped (no UDM): {e}"),
        }
    });
}

/// Purge this SMF's serving-SMF registration for the PDU session. Best-effort.
fn spawn_uecm_purge(nrf_base: String, supi: String, pdu_session_id: u8) {
    tokio::spawn(async move {
        match discover_udm(&nrf_base).await {
            Ok(udm) => {
                match udm_client(&nrf_base, udm)
                    .uecm_deregister_smf(&supi, pdu_session_id)
                    .await
                {
                    Ok(true) => tracing::info!(psi = pdu_session_id, "UECM: serving-SMF registration purged"),
                    Ok(false) => {} // already gone (e.g. the subscriber was withdrawn)
                    Err(e) => tracing::warn!(psi = pdu_session_id, "UECM SMF purge failed: {e}"),
                }
            }
            Err(e) => tracing::warn!("UECM SMF purge skipped (no UDM): {e}"),
        }
    });
}

/// Delete the PCF SM policy association for a released session. Best-effort.
fn spawn_sm_policy_delete(nrf_base: String, pcf_base: String, policy_id: String) {
    let pcf = pcf_client(&nrf_base, pcf_base);
    tokio::spawn(async move {
        match pcf.delete_sm_policy(&policy_id).await {
            Ok(()) => tracing::info!(%policy_id, "PCF: SM policy association deleted"),
            Err(e) => tracing::warn!(%policy_id, "PCF SM policy delete failed: {e}"),
        }
    });
}

/// Whether a gNB downlink target is plausibly routable (not a zero TEID, nor an
/// unspecified / broadcast / multicast address).
fn valid_gnb_target(teid: u32, ip: Ipv4Addr) -> bool {
    teid != 0 && !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast()
}

/// Mask a SUPI for logs — keep the scheme + a short prefix, redact the rest (PII).
fn masked_supi(supi: &str) -> String {
    match supi.split_once('-') {
        Some((scheme, rest)) if rest.len() > 5 => format!("{scheme}-{}***", &rest[..5]),
        _ => "***".to_string(),
    }
}

/// The `(sst, optional SD, DNN)` triples this SMF serves — advertised in its NRF
/// profile so the AMF can select it by `(S-NSSAI, DNN)`. Config in production;
/// here the demo slice + DNN, matching the UDR's smf-selection provisioning.
const SERVED_SLICES: &[(u8, Option<&str>, &str)] =
    &[(1, Some("010203"), "internet"), (1, Some("010203"), "ims")];

/// Register this SMF's `nsmf-pdusession` service with the NRF (advertising the
/// slices/DNNs it serves so the AMF can select it), keeping it alive via the
/// NRF-assigned heartbeat.
pub async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, SmfInfo};
    let mut profile = NfProfile::new(SMF_INSTANCE_ID.clone(), "SMF", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "nsmf-pdusession-1".into(),
        service_name: "nsmf-pdusession".into(),
        scheme: sbi_core::sbi_scheme().into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    profile.smf_info = Some(SmfInfo::from_served(SERVED_SLICES));
    sbi_core::nnrf::register_and_maintain(nrf_base, profile).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lazy-reuse pool: sequential allocation, reuse of freed values before the
    /// high-water mark advances, exhaustion, and idempotent release (design/137 G6).
    #[test]
    fn u32_pool_reuses_freed_and_bounds_the_range() {
        let mut pool = U32Pool::new(10, 13); // usable: 10, 11, 12
        assert_eq!((pool.alloc(), pool.alloc(), pool.alloc()), (Some(10), Some(11), Some(12)));
        assert_eq!(pool.alloc(), None, "range exhausted");

        // Releasing returns values to the pool; the lowest freed is reused first.
        pool.release(11);
        pool.release(10);
        assert_eq!((pool.alloc(), pool.alloc()), (Some(10), Some(11)), "freed values reused, lowest first");
        assert_eq!(pool.alloc(), None, "exhausted again");

        // A double-release is a no-op (set membership), so an address can't be handed
        // to two sessions; releasing a never-allocated value is ignored.
        pool.release(12);
        pool.release(12);
        pool.release(99); // >= next → never allocated → ignored
        assert_eq!(pool.alloc(), Some(12));
        assert_eq!(pool.alloc(), None, "the spurious releases added nothing");
    }

    /// The SMF's IPv4/IPv6 allocators reuse a released address instead of leaking it.
    #[test]
    fn ip_pools_round_trip_through_alloc_release() {
        let pool = Mutex::new(U32Pool::new(UE_IP_POOL_START, UE_IP_POOL_END));
        // Mirror SmfState::alloc_ue_ip / release_ue_ip against a bare pool.
        let alloc = || Ipv4Addr::from(pool.lock().unwrap().alloc().unwrap());
        let release = |a: Ipv4Addr| pool.lock().unwrap().release(u32::from(a));

        assert_eq!(alloc(), Ipv4Addr::new(10, 45, 0, 2));
        let second = alloc();
        assert_eq!(second, Ipv4Addr::new(10, 45, 0, 3));
        release(second);
        assert_eq!(alloc(), Ipv4Addr::new(10, 45, 0, 3), "released .3 handed back out");
    }

    /// A UPF's recovery timestamp only signals a restart when it's *newer* than what we
    /// last recorded; the first one is the baseline and a stale/reordered one is ignored
    /// (design/137 G4).
    #[tokio::test]
    async fn note_recovery_flags_only_a_newer_timestamp() {
        // UDP connect needs no listener, so a throwaway address serves for the unit test.
        let peer = N4Peer::connect("127.0.0.1:9".parse().unwrap(), None).await.unwrap();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(2000);
        assert_eq!(peer.note_recovery(t0), Recovery::Unchanged, "first timestamp is the baseline");
        assert_eq!(peer.note_recovery(t0), Recovery::Unchanged, "same timestamp — not a restart");
        assert_eq!(peer.note_recovery(t1), Recovery::Restarted, "a newer timestamp — restart");
        assert_eq!(peer.note_recovery(t0), Recovery::Unchanged, "a stale/reordered timestamp is ignored");
        assert_eq!(peer.note_recovery(t1), Recovery::Unchanged, "still current after the stale one");
    }

    /// PDU-session-type negotiation (design/131): the selected type + downgrade cause
    /// for every (requested × allowed) combination.
    #[test]
    fn negotiates_pdu_session_type() {
        use nas::PduSessionType::{Ipv4, Ipv4v6, Ipv6};
        let v4_only = 50;
        let v6_only = 51;
        // Dual-stack allowed: requests are granted as-is.
        assert_eq!(negotiate_pdu_type(Ipv4v6, true, true), (Ipv4v6, None));
        assert_eq!(negotiate_pdu_type(Ipv4, true, true), (Ipv4, None));
        assert_eq!(negotiate_pdu_type(Ipv6, true, true), (Ipv6, None));
        // IPv4-only DNN: IPv4v6/IPv6 downgrade to IPv4 with cause #50.
        assert_eq!(negotiate_pdu_type(Ipv4v6, true, false), (Ipv4, Some(v4_only)));
        assert_eq!(negotiate_pdu_type(Ipv6, true, false), (Ipv4, Some(v4_only)));
        assert_eq!(negotiate_pdu_type(Ipv4, true, false), (Ipv4, None));
        // IPv6-only DNN: IPv4v6/IPv4 downgrade to IPv6 with cause #51.
        assert_eq!(negotiate_pdu_type(Ipv4v6, false, true), (Ipv6, Some(v6_only)));
        assert_eq!(negotiate_pdu_type(Ipv4, false, true), (Ipv6, Some(v6_only)));
        assert_eq!(negotiate_pdu_type(Ipv6, false, true), (Ipv6, None));
    }

    /// The DNN's allowed families are read from sm-data `pduSessionTypes`
    /// (default + allowed list); an unset config is IPv4-only.
    #[test]
    fn parses_allowed_session_types() {
        let dual = serde_json::json!({
            "pduSessionTypes": { "defaultSessionType": "IPV4", "allowedSessionTypes": ["IPV4", "IPV6"] }
        });
        assert_eq!(parse_pdu_session_types(&dual), (true, true, nas::PduSessionType::Ipv4));
        let v4 = serde_json::json!({ "pduSessionTypes": { "defaultSessionType": "IPV4" } });
        assert_eq!(parse_pdu_session_types(&v4), (true, false, nas::PduSessionType::Ipv4));
        // IPV4V6 default implies both families; a bare config defaults to IPv4-only.
        let both = serde_json::json!({ "pduSessionTypes": { "defaultSessionType": "IPV4V6" } });
        assert_eq!(parse_pdu_session_types(&both), (true, true, nas::PduSessionType::Ipv4v6));
        assert_eq!(parse_pdu_session_types(&serde_json::json!({})), (true, false, nas::PduSessionType::Ipv4));
    }

    #[test]
    fn rejects_bogus_gnb_targets() {
        assert!(valid_gnb_target(0x5678, Ipv4Addr::new(10, 0, 0, 9)));
        assert!(!valid_gnb_target(0, Ipv4Addr::new(10, 0, 0, 9)), "zero TEID");
        assert!(!valid_gnb_target(0x5678, Ipv4Addr::UNSPECIFIED), "0.0.0.0");
        assert!(!valid_gnb_target(0x5678, Ipv4Addr::BROADCAST), "255.255.255.255");
        assert!(!valid_gnb_target(0x5678, Ipv4Addr::new(224, 0, 0, 1)), "multicast");
    }

    #[test]
    fn masks_supi_for_logging() {
        assert_eq!(masked_supi("imsi-999700000000001"), "imsi-99970***");
        assert_eq!(masked_supi("garbage"), "***");
    }

    /// Spin an NRF + UDR (in-memory, provisioned) + UDM chain; returns the NRF base
    /// the SMF should use. The demo subscriber may use DNN "internet" on slice
    /// sst=1/sd=010203 with a 1/2 Gbps session AMBR.
    /// Returns (nrf_base, udr_base).
    async fn spin_subscription_backend(supi: &str, plmn: &str) -> (String, String) {
        spin_subscription_backend_dnns(supi, plmn, &["internet"]).await
    }

    /// Like [`spin_subscription_backend`] but provisioning several DNNs on the one slice
    /// (each with the same demo QoS) — for the per-DNN UP-path selection test (design/134
    /// Phase 3b), where a subscriber reaches more than one data network.
    async fn spin_subscription_backend_dnns(
        supi: &str,
        plmn: &str,
        dnns: &[&str],
    ) -> (String, String) {
        use subscriber_db::{DataSet, ProvisionedDataStore, SubscriberStore};

        let dnn_infos: Vec<_> = dnns.iter().map(|d| serde_json::json!({ "dnn": d })).collect();
        let mut dnn_configs = serde_json::Map::new();
        for d in dnns {
            dnn_configs.insert(
                d.to_string(),
                serde_json::json!({
                    "sessionAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" },
                    "5gQosProfile": { "5qi": 9, "arp": { "priorityLevel": 8 } },
                    "qosFlows": [{
                        "qfi": 2, "fiveQi": 1, "arpPriority": 5, "preEmptCap": true,
                        "gbr": { "gfbrDl": "100 Mbps", "gfbrUl": "100 Mbps",
                                 "mfbrDl": "200 Mbps", "mfbrUl": "200 Mbps" }
                    }]
                }),
            );
        }

        let store = Arc::new(subscriber_db::InMemoryStore::new());
        store
            .put_provisioned(
                DataSet::SmfSelection,
                supi,
                plmn,
                &serde_json::json!({
                    "subscribedSnssaiInfos": {
                        "1-010203": { "dnnInfos": dnn_infos }
                    }
                }),
            )
            .unwrap();
        store
            .put_provisioned(
                DataSet::Sm,
                supi,
                plmn,
                &serde_json::json!([{
                    "singleNssai": { "sst": 1, "sd": "010203" },
                    "dnnConfigurations": dnn_configs
                }]),
            )
            .unwrap();
        let store: Arc<dyn SubscriberStore> = store;
        let udr_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udr_addr = udr_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udr_l, sbi_core::nudr::router(store)).await.unwrap() });

        let udr_base = format!("http://{udr_addr}");
        let udr = Arc::new(sbi_core::nudr::UdrClient::new(udr_base.clone()));
        let udm_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udm_addr = udm_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(udm_l, sbi_core::nudm::router(udr)).await.unwrap() });

        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let nrf_store = sbi_core::nnrf::NrfStore::default();
        tokio::spawn(async move { sbi_core::run_on(nrf_l, sbi_core::nnrf::router(nrf_store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");

        let mut profile = sbi_core::nnrf::NfProfile::new("udm-1", "UDM", udm_addr.ip().to_string());
        profile.nf_services = Some(vec![sbi_core::nnrf::NfService {
            service_instance_id: "nudm-1".into(),
            service_name: "nudm-sdm".into(),
            scheme: "http".into(),
            ip_end_points: vec![sbi_core::nnrf::IpEndPoint {
                ipv4_address: Some(udm_addr.ip().to_string()),
                port: Some(udm_addr.port()),
            }],
        }]);
        sbi_core::nnrf::NrfClient::new(nrf_base.clone()).register(&profile).await.unwrap();
        (nrf_base, udr_base)
    }

    /// Spin an in-process PCF and register it with the NRF at `nrf_base`. With
    /// `udr_base`, the PCF sources policy from that UDR (Nudr policy-data); without,
    /// it uses its local demo policy. Returns its state (to watch the assoc count).
    async fn spin_pcf(nrf_base: &str, udr_base: Option<&str>) -> sbi_core::npcf::PcfState {
        let mut state = sbi_core::npcf::PcfState::new(sbi_core::npcf::PolicyConfig::demo());
        if let Some(udr) = udr_base {
            state = state.with_udr(Arc::new(sbi_core::nudr::UdrClient::new(udr.to_string())));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = state.clone();
        tokio::spawn(async move {
            sbi_core::run_on(listener, sbi_core::npcf::router(served)).await.unwrap()
        });
        let mut profile = sbi_core::nnrf::NfProfile::new("pcf-1", "PCF", addr.ip().to_string());
        profile.nf_services = Some(vec![sbi_core::nnrf::NfService {
            service_instance_id: "npcf-smpolicycontrol-1".into(),
            service_name: "npcf-smpolicycontrol".into(),
            scheme: "http".into(),
            ip_end_points: vec![sbi_core::nnrf::IpEndPoint {
                ipv4_address: Some(addr.ip().to_string()),
                port: Some(addr.port()),
            }],
        }]);
        sbi_core::nnrf::NrfClient::new(nrf_base.to_string()).register(&profile).await.unwrap();
        state
    }

    /// Spin an in-process UPF: an N4 UDP loop over a real [`pfcp::UpfState`] the test
    /// can inspect. `node_ip` is the address the UPF puts in the F-TEIDs and F-SEIDs
    /// it hands out — give two UPFs different ones so a chain test can tell which node
    /// a tunnel endpoint belongs to (the sockets both live on loopback).
    async fn spin_upf(node_ip: Ipv4Addr) -> (Arc<Mutex<pfcp::UpfState>>, SocketAddr) {
        let state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let served = state.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
                let resp = {
                    let mut s = served.lock().unwrap();
                    pfcp::handle_n4(&buf[..n], node_ip, &mut s, 0)
                };
                if let Some(resp) = resp {
                    sock.send_to(&resp, peer).await.unwrap();
                }
            }
        });
        (state, addr)
    }

    /// Spin a real CHF (the `sbi_core::nchf` router), registered with the NRF as
    /// nf-type `CHF`. Returns the shared CDR store the test can inspect.
    async fn spin_chf(nrf_base: &str) -> sbi_core::nchf::ChfState {
        let state = sbi_core::nchf::ChfState::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = state.clone();
        tokio::spawn(async move {
            sbi_core::run_on(listener, sbi_core::nchf::router(served)).await.unwrap()
        });
        let mut profile = sbi_core::nnrf::NfProfile::new("chf-1", "CHF", addr.ip().to_string());
        profile.nf_services = Some(vec![sbi_core::nnrf::NfService {
            service_instance_id: "nchf-convergedcharging-1".into(),
            service_name: "nchf-convergedcharging".into(),
            scheme: "http".into(),
            ip_end_points: vec![sbi_core::nnrf::IpEndPoint {
                ipv4_address: Some(addr.ip().to_string()),
                port: Some(addr.port()),
            }],
        }]);
        sbi_core::nnrf::NrfClient::new(nrf_base.to_string()).register(&profile).await.unwrap();
        state
    }

    /// Spin a mock AMF that records `Namf_Communication` PDU-modify posts, registered
    /// with the NRF as nf-type `AMF`. Returns the shared record of received bodies.
    async fn spin_mock_amf(nrf_base: &str) -> Arc<Mutex<Vec<serde_json::Value>>> {
        async fn record(
            State(rec): State<Arc<Mutex<Vec<serde_json::Value>>>>,
            Json(body): Json<serde_json::Value>,
        ) -> StatusCode {
            rec.lock().unwrap().push(body);
            StatusCode::ACCEPTED
        }
        let recorder: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/namf-comm/v1/ue-contexts/{supi}/modify", post(record))
            .with_state(recorder.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(l, app).await.unwrap() });
        let mut profile = sbi_core::nnrf::NfProfile::new("amf-mock", "AMF", addr.ip().to_string());
        profile.nf_services = Some(vec![sbi_core::nnrf::NfService {
            service_instance_id: "namf-callback-1".into(),
            service_name: "namf-callback".into(),
            scheme: "http".into(),
            ip_end_points: vec![sbi_core::nnrf::IpEndPoint {
                ipv4_address: Some(addr.ip().to_string()),
                port: Some(addr.port()),
            }],
        }]);
        sbi_core::nnrf::NrfClient::new(nrf_base.to_string()).register(&profile).await.unwrap();
        recorder
    }

    /// Full Nsmf → N4 spine: an in-process UPF, the SMF as PFCP client + SBI server,
    /// driven over HTTP — with the subscription checked against a real UDR/UDM chain.
    /// Multi-UPF chaining (design/134): with an intermediate UPF configured, one
    /// CreateSMContext builds **two** N4 sessions and splices them, so the user plane
    /// runs gNB → I-UPF → N9 → anchor → N6. Both UPFs are real `UpfState`s over real
    /// PFCP, distinguished by their node addresses (.1 anchor, .2 intermediate).
    #[tokio::test]
    async fn chained_session_wires_the_iupf_between_the_ran_and_the_anchor() {
        let (anchor_ip, iupf_ip) = (Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2));
        let (anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;

        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let smf = Arc::new(
            SmfState::connect(UserPlane::chained(anchor_n4, iupf_n4), anchor_ip, nrf_base).await.unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(anchor.lock().unwrap().session_count(), 1, "anchor N4 session");
        assert_eq!(iupf.lock().unwrap().session_count(), 1, "intermediate N4 session");
        // The F-TEID handed to the RAN is the *intermediate* UPF's — the anchor is no
        // longer the node the gNB tunnels to.
        assert_eq!(created.up_n3_addr, iupf_ip, "the gNB tunnels to the I-UPF");
        let ran_teid = u32::from_str_radix(&created.up_n3_teid, 16).unwrap();

        // Uplink: the I-UPF's RAN-facing ingress forwards over N9 to the anchor's N3
        // ingress; the anchor, being the PSA, forwards on to N6.
        assert_eq!(
            iupf.lock().unwrap().uplink_egress_for_teid(ran_teid),
            Some(pfcp::Egress::ToPeer { teid: 1, addr: anchor_ip }),
            "the I-UPF forwards uplink over N9 to the anchor"
        );
        assert_eq!(
            anchor.lock().unwrap().uplink_egress_for_teid(1),
            Some(pfcp::Egress::ToN6),
            "the anchor terminates the session on N6"
        );

        // Downlink, first half: the anchor routes the UE's address back to the I-UPF's
        // N9 ingress rather than to a gNB.
        let ue_ip = created.ue_ipv4_addr.expect("UE IPv4");
        let n9_dl = anchor.lock().unwrap().route_downlink(ue_ip).expect("anchor downlink route");
        assert_eq!(n9_dl.1, iupf_ip, "the anchor sends downlink back to the I-UPF over N9");
        assert_ne!(n9_dl.0, ran_teid, "the I-UPF's two ingresses are distinct TEIDs");
        assert!(
            iupf.lock().unwrap().uplink_egress_for_teid(n9_dl.0).is_none(),
            "that TEID is the I-UPF's downlink ingress — it must not also match uplink"
        );

        // Downlink, second half: the gNB target from UpdateSMContext lands on the
        // *I-UPF's* downlink FAR — the anchor's stays pointed at N9.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"00005678","gnbN3Addr":"10.0.0.9"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "UpdateSMContext succeeded");
        assert_eq!(
            iupf.lock().unwrap().downlink_via_n9_ingress(n9_dl.0),
            Some((0x5678, Ipv4Addr::new(10, 0, 0, 9))),
            "the I-UPF forwards downlink out of N9 to the gNB"
        );
        assert_eq!(
            anchor.lock().unwrap().route_downlink(ue_ip),
            Some(n9_dl),
            "the anchor's downlink still points at the I-UPF, not the gNB"
        );

        // AN release: the *anchor* is the node that buffers, because it holds the URRs
        // and so is the association a Downlink Data Report can reach the SMF on.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"upCnxState":"DEACTIVATED"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "AN release succeeded");
        assert_eq!(
            anchor.lock().unwrap().route_downlink(ue_ip),
            None,
            "the anchor stopped forwarding downlink and buffers for the idle UE"
        );

        // Service Request re-activation restores the whole path, not just the RAN hop:
        // the anchor's N9 target has to be re-installed alongside the new gNB tunnel.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"0000abcd","gnbN3Addr":"10.0.0.11"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "re-activation succeeded");
        assert_eq!(
            anchor.lock().unwrap().route_downlink(ue_ip),
            Some(n9_dl),
            "the anchor's downlink is back on the N9 path to the I-UPF"
        );
        assert_eq!(
            iupf.lock().unwrap().downlink_via_n9_ingress(n9_dl.0),
            Some((0xabcd, Ipv4Addr::new(10, 0, 0, 11))),
            "the I-UPF now forwards downlink to the re-activated gNB tunnel"
        );

        // Release tears both halves down.
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");
        assert_eq!(anchor.lock().unwrap().session_count(), 0, "anchor N4 session deleted");
        assert_eq!(iupf.lock().unwrap().session_count(), 0, "intermediate N4 session deleted");
    }

    /// design/134 Phase 3b: a config-file topology names **two anchors, one per DNN**, and
    /// the SMF selects the path from the DNN — so a session on "internet" lands on one UPF
    /// and a session on "ims" on the other, from a single graph the operator wrote. This is
    /// the capability the env-var user plane can't express: it has one anchor for every DNN.
    #[tokio::test]
    async fn topology_routes_each_dnn_to_its_own_anchor() {
        let (internet_ip, ims_ip) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 4));
        let (internet, internet_n4) = spin_upf(internet_ip).await;
        let (ims, ims_n4) = spin_upf(ims_ip).await;

        let (nrf_base, _udr) =
            spin_subscription_backend_dnns("imsi-999700000000001", "99970", &["internet", "ims"])
                .await;

        // gNB hangs both anchors directly; each serves exactly one DNN.
        let topo = crate::topology::Topology::parse(&format!(
            r#"{{
                "upNodes": {{
                    "gNB":      {{ "type": "AN" }},
                    "internet": {{ "type": "UPF", "n4": "{internet_n4}", "dnns": ["internet"] }},
                    "ims":      {{ "type": "UPF", "n4": "{ims_n4}", "dnns": ["ims"] }}
                }},
                "links": [
                    {{ "a": "gNB", "b": "internet" }},
                    {{ "a": "gNB", "b": "ims" }}
                ]
            }}"#
        ))
        .unwrap();

        let smf = Arc::new(
            SmfState::connect_with_topology(topo, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        for (dnn, psi) in [("internet", 5u8), ("ims", 6u8)] {
            let status = client
                .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
                .json(&serde_json::json!({
                    "supi": "imsi-999700000000001", "pduSessionId": psi, "dnn": dnn,
                    "servingNetwork": { "mcc": "999", "mnc": "70" },
                    "sNssai": { "sst": 1, "sd": "010203" }
                }))
                .traced()
                .send()
                .await
                .unwrap()
                .status();
            assert!(status.is_success(), "create on DNN {dnn} failed: {status}");
        }

        // Each DNN's session landed on its own anchor — the graph, not a global default,
        // picked the UPF.
        assert_eq!(internet.lock().unwrap().session_count(), 1, "the internet DNN's anchor");
        assert_eq!(ims.lock().unwrap().session_count(), 1, "the ims DNN's anchor");
    }

    /// design/134 Phase 3c: the uplink classifier, now expressed in the topology config's
    /// `routes` rather than the `RADIAN_SMF_PSA2_N4`/`PREFIX` env vars. One session on the
    /// chained DNN fans out across the default anchor and the breakout anchor named by the
    /// route — the same two-anchor splice as Phase 2, driven entirely by config.
    #[tokio::test]
    async fn topology_breakout_route_splits_a_session_across_two_anchors() {
        let (anchor_ip, iupf_ip, edge_ip) = (
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
            Ipv4Addr::new(127, 0, 0, 4),
        );
        let (anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;
        let (edge, edge_n4) = spin_upf(edge_ip).await;

        let (nrf_base, _udr) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;

        // gNB → iupf → anchor for the default path; a route steers 10.99.0.0/16 to `edge`.
        let topo = crate::topology::Topology::parse(&format!(
            r#"{{
                "upNodes": {{
                    "gNB":    {{ "type": "AN" }},
                    "iupf":   {{ "type": "UPF", "n4": "{iupf_n4}" }},
                    "anchor": {{ "type": "UPF", "n4": "{anchor_n4}", "dnns": ["internet"] }},
                    "edge":   {{ "type": "UPF", "n4": "{edge_n4}" }}
                }},
                "links": [
                    {{ "a": "gNB", "b": "iupf" }},
                    {{ "a": "iupf", "b": "anchor" }},
                    {{ "a": "iupf", "b": "edge" }}
                ],
                "routes": [
                    {{ "dnn": "internet", "prefix": "10.99.0.0/16", "via": "edge" }}
                ]
            }}"#
        ))
        .unwrap();

        let smf = Arc::new(
            SmfState::connect_with_topology(topo, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "create failed: {status}");

        // One PDU session spliced across all three: the anchor, the classifier, and the
        // config-named breakout anchor.
        assert_eq!(anchor.lock().unwrap().session_count(), 1, "the default anchor");
        assert_eq!(iupf.lock().unwrap().session_count(), 1, "the classifier");
        assert_eq!(edge.lock().unwrap().session_count(), 1, "the breakout anchor from the route");
    }

    /// design/134 Phase 3e: a breakout inserted and removed **mid-session** via the OAM
    /// endpoint. A plain chained session (no route) gets a breakout spliced onto it live,
    /// then torn back down — the dynamic counterpart to Phase 2/3c's establishment-time
    /// breakout, exercising the Session Modification path Phase 2 leaves inert.
    #[tokio::test]
    async fn oam_inserts_and_removes_a_mid_session_breakout() {
        let (anchor_ip, iupf_ip, edge_ip) = (
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
            Ipv4Addr::new(127, 0, 0, 4),
        );
        let (anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;
        let (edge, edge_n4) = spin_upf(edge_ip).await;

        let (nrf_base, _udr) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;

        // A chain to the anchor, with `edge` present but NO route — establishment is a
        // plain chain and the breakout is added later, mid-session.
        let topo = crate::topology::Topology::parse(&format!(
            r#"{{
                "upNodes": {{
                    "gNB":    {{ "type": "AN" }},
                    "iupf":   {{ "type": "UPF", "n4": "{iupf_n4}" }},
                    "anchor": {{ "type": "UPF", "n4": "{anchor_n4}", "dnns": ["internet"] }},
                    "edge":   {{ "type": "UPF", "n4": "{edge_n4}" }}
                }},
                "links": [
                    {{ "a": "gNB", "b": "iupf" }},
                    {{ "a": "iupf", "b": "anchor" }},
                    {{ "a": "iupf", "b": "edge" }}
                ]
            }}"#
        ))
        .unwrap();

        let smf = Arc::new(
            SmfState::connect_with_topology(topo, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let ran_teid = u32::from_str_radix(&created.up_n3_teid, 16).unwrap();

        // A plain chain: anchor + classifier have sessions, the breakout anchor none.
        assert_eq!(edge.lock().unwrap().session_count(), 0, "no breakout yet");
        assert!(iupf.lock().unwrap().branches_for_teid(ran_teid).is_empty(), "no branch yet");

        // Insert the breakout via OAM.
        let insert = client
            .post(format!("{base}/oam/v1/breakout"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5,
                "prefix": "10.99.0.0/16", "via": "edge"
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(insert.is_success(), "insert failed: {insert}");
        assert_eq!(edge.lock().unwrap().session_count(), 1, "the breakout anchor now has a session");
        let branches = iupf.lock().unwrap().branches_for_teid(ran_teid);
        assert_eq!(branches.len(), 1, "the classifier now steers one branch");
        assert_eq!(
            branches[0].1,
            pfcp::Egress::ToPeer { teid: 1, addr: edge_ip },
            "the branch steers to the breakout anchor"
        );

        // Remove it via OAM.
        let remove = client
            .post(format!("{base}/oam/v1/breakout"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "remove": true
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(remove.is_success(), "remove failed: {remove}");
        assert_eq!(edge.lock().unwrap().session_count(), 0, "the breakout anchor's session is gone");
        assert!(iupf.lock().unwrap().branches_for_teid(ran_teid).is_empty(), "the branch is gone");
        assert_eq!(anchor.lock().unwrap().session_count(), 1, "the default anchor is untouched");
    }

    /// design/135 Phase 1: the same mid-session breakout, but driven by an **AF traffic
    /// influence** request through a real NEF. The AF names a **DNAI** (`mec`) and targets
    /// the UE by **SUPI + DNN** (no pduSessionId); the SMF resolves the DNAI to a node via
    /// its topology and finds the session, then splices the breakout — end to end.
    #[tokio::test]
    async fn af_traffic_influence_through_the_nef_splices_a_breakout() {
        let (anchor_ip, iupf_ip, edge_ip) = (
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
            Ipv4Addr::new(127, 0, 0, 4),
        );
        let (anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;
        let (edge, edge_n4) = spin_upf(edge_ip).await;

        let (nrf_base, _udr) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;

        // The breakout anchor `edge` exposes the DNAI "mec"; no route (added mid-session).
        let topo = crate::topology::Topology::parse(&format!(
            r#"{{
                "upNodes": {{
                    "gNB":    {{ "type": "AN" }},
                    "iupf":   {{ "type": "UPF", "n4": "{iupf_n4}" }},
                    "anchor": {{ "type": "UPF", "n4": "{anchor_n4}", "dnns": ["internet"] }},
                    "edge":   {{ "type": "UPF", "n4": "{edge_n4}", "dnai": "mec" }}
                }},
                "links": [
                    {{ "a": "gNB", "b": "iupf" }},
                    {{ "a": "iupf", "b": "anchor" }},
                    {{ "a": "iupf", "b": "edge" }}
                ]
            }}"#
        ))
        .unwrap();

        let smf = Arc::new(
            SmfState::connect_with_topology(topo, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        // A NEF pointed straight at the SMF.
        let nef = sbi_core::nnef::NefState::with_smf_base(format!("http://{smf_addr}"));
        let nef_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nef_addr = nef_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(nef_l, sbi_core::nnef::router(nef)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let ran_teid = u32::from_str_radix(&created.up_n3_teid, 16).unwrap();
        assert_eq!(edge.lock().unwrap().session_count(), 0, "no breakout yet");

        // AF POSTs a traffic-influence subscription: UE by SUPI on "internet", steer
        // 10.99.0.0/16 to the "mec" edge.
        let sub = client
            .post(format!("http://{nef_addr}/3gpp-traffic-influence/v1/app1/subscriptions"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "dnn": "internet",
                "trafficFilters": [{ "flowDescriptions": ["permit out ip from 10.0.0.0/8 to 10.99.0.0/16"] }],
                "trafficRoutes": [{ "dnai": "mec" }]
            }))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(sub.status().as_u16(), 201, "AF subscription created");
        let self_link = sub.headers().get("location").unwrap().to_str().unwrap().to_string();

        assert_eq!(edge.lock().unwrap().session_count(), 1, "the DNAI-named edge now anchors the breakout");
        let branches = iupf.lock().unwrap().branches_for_teid(ran_teid);
        assert_eq!(branches.len(), 1, "the classifier steers the AF-influenced prefix");
        assert_eq!(branches[0].1, pfcp::Egress::ToPeer { teid: 1, addr: edge_ip });

        // Delete the AF subscription → the breakout is withdrawn.
        let del = client
            .delete(format!("http://{nef_addr}{self_link}"))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(del.as_u16(), 204, "AF subscription deleted");
        assert_eq!(edge.lock().unwrap().session_count(), 0, "the breakout is gone");
        assert!(iupf.lock().unwrap().branches_for_teid(ran_teid).is_empty(), "the branch is gone");
        assert_eq!(anchor.lock().unwrap().session_count(), 1, "the default anchor is untouched");
    }

    /// design/135 Phase 2a: AF influence carried **through the SM policy**. A traffic-control
    /// decision (route a prefix to a DNAI) appearing in the PCF's decision makes the SMF
    /// splice a live breakout on a policy refresh; its withdrawal tears it down — so AF
    /// influence composes with QoS in one decision, rather than the Phase-1 NEF→SMF shortcut.
    #[tokio::test]
    async fn sm_policy_traffic_control_drives_a_breakout_on_refresh() {
        let (anchor_ip, iupf_ip, edge_ip) = (
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
            Ipv4Addr::new(127, 0, 0, 4),
        );
        let (anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;
        let (edge, edge_n4) = spin_upf(edge_ip).await;

        let (nrf_base, udr_base) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;
        // Baseline SM policy-data (no influence), backing a UDR-sourced PCF.
        let udr = sbi_core::nudr::UdrClient::new(udr_base.clone());
        let base_policy = serde_json::json!({ "default": {
            "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" } } },
            "pccRules": { "pcc-1": { "refQosData": "qos-1" } },
            "qosDecs": { "qos-1": { "qfi": 1, "fiveQi": 9 } }
        } });
        udr.put_sm_policy_data("imsi-999700000000001", &base_policy).await.unwrap();
        let _pcf = spin_pcf(&nrf_base, Some(&udr_base)).await;
        let _amf = spin_mock_amf(&nrf_base).await;

        // `edge` exposes DNAI "mec"; no static route — the breakout is policy-driven.
        let topo = crate::topology::Topology::parse(&format!(
            r#"{{
                "upNodes": {{
                    "gNB":    {{ "type": "AN" }},
                    "iupf":   {{ "type": "UPF", "n4": "{iupf_n4}" }},
                    "anchor": {{ "type": "UPF", "n4": "{anchor_n4}", "dnns": ["internet"] }},
                    "edge":   {{ "type": "UPF", "n4": "{edge_n4}", "dnai": "mec" }}
                }},
                "links": [
                    {{ "a": "gNB", "b": "iupf" }},
                    {{ "a": "iupf", "b": "anchor" }},
                    {{ "a": "iupf", "b": "edge" }}
                ]
            }}"#
        ))
        .unwrap();
        let smf = Arc::new(
            SmfState::connect_with_topology(topo, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let ran_teid = u32::from_str_radix(&created.up_n3_teid, 16).unwrap();
        let sm_ref = created.sm_context_ref;
        assert_eq!(edge.lock().unwrap().session_count(), 0, "no influence yet");

        // AF influence lands in the policy: steer 10.99.0.0/16 to DNAI "mec".
        let influenced = serde_json::json!({ "default": {
            "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" } } },
            "pccRules": { "pcc-1": { "refQosData": "qos-1" } },
            "qosDecs": { "qos-1": { "qfi": 1, "fiveQi": 9 } },
            "traffContDecs": { "tc-af": { "routeToLocs": [{ "dnai": "mec" }], "trafficPrefix": "10.99.0.0/16" } }
        } });
        udr.put_sm_policy_data("imsi-999700000000001", &influenced).await.unwrap();
        let refresh = |sm_ref: &str| {
            client.post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{sm_ref}/refresh-policy")).traced().send()
        };
        assert!(refresh(&sm_ref).await.unwrap().status().is_success(), "refresh (influence added)");
        assert_eq!(edge.lock().unwrap().session_count(), 1, "the influenced breakout is spliced in");
        assert_eq!(
            iupf.lock().unwrap().branches_for_teid(ran_teid).len(),
            1,
            "the classifier steers the influenced prefix"
        );

        // Withdraw the influence: the policy loses the traffic-control decision.
        udr.put_sm_policy_data("imsi-999700000000001", &base_policy).await.unwrap();
        assert!(refresh(&sm_ref).await.unwrap().status().is_success(), "refresh (influence withdrawn)");
        assert_eq!(edge.lock().unwrap().session_count(), 0, "the breakout is torn down");
        assert!(iupf.lock().unwrap().branches_for_teid(ran_teid).is_empty(), "the branch is gone");
        assert_eq!(anchor.lock().unwrap().session_count(), 1, "the default anchor is untouched");
    }

    /// design/135 Phase 2b: a breakout installed **directly** (OAM, or a NEF with no PCF)
    /// is not expressed in the SM policy, so a policy refresh that sees no influence must
    /// leave it alone — only a policy-installed breakout is reconciled away.
    #[tokio::test]
    async fn a_directly_installed_breakout_survives_a_policy_refresh() {
        let (anchor_ip, iupf_ip, edge_ip) = (
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
            Ipv4Addr::new(127, 0, 0, 4),
        );
        let (_anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;
        let (edge, edge_n4) = spin_upf(edge_ip).await;

        let (nrf_base, udr_base) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;
        // A PCF whose policy carries **no** influence — so a refresh sees no route.
        let udr = sbi_core::nudr::UdrClient::new(udr_base.clone());
        udr.put_sm_policy_data(
            "imsi-999700000000001",
            &serde_json::json!({ "default": {
                "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" } } },
                "pccRules": { "pcc-1": { "refQosData": "qos-1" } },
                "qosDecs": { "qos-1": { "qfi": 1, "fiveQi": 9 } }
            } }),
        )
        .await
        .unwrap();
        let _pcf = spin_pcf(&nrf_base, Some(&udr_base)).await;
        let _amf = spin_mock_amf(&nrf_base).await;

        let topo = crate::topology::Topology::parse(&format!(
            r#"{{
                "upNodes": {{
                    "gNB":    {{ "type": "AN" }},
                    "iupf":   {{ "type": "UPF", "n4": "{iupf_n4}" }},
                    "anchor": {{ "type": "UPF", "n4": "{anchor_n4}", "dnns": ["internet"] }},
                    "edge":   {{ "type": "UPF", "n4": "{edge_n4}", "dnai": "mec" }}
                }},
                "links": [
                    {{ "a": "gNB", "b": "iupf" }},
                    {{ "a": "iupf", "b": "anchor" }},
                    {{ "a": "iupf", "b": "edge" }}
                ]
            }}"#
        ))
        .unwrap();
        let smf = Arc::new(
            SmfState::connect_with_topology(topo, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let ran_teid = u32::from_str_radix(&created.up_n3_teid, 16).unwrap();

        // Install a breakout the *direct* way (the OAM trigger — not via policy).
        let insert = client
            .post(format!("{base}/oam/v1/breakout"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5,
                "prefix": "10.99.0.0/16", "via": "edge"
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(insert.is_success(), "direct breakout inserted");
        assert_eq!(edge.lock().unwrap().session_count(), 1);

        // A policy refresh (no influence in the policy) must NOT tear it down.
        let refreshed = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/refresh-policy",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(refreshed.is_success(), "policy refreshed");
        assert_eq!(
            edge.lock().unwrap().session_count(),
            1,
            "a directly-installed breakout survives a policy refresh"
        );
        assert_eq!(
            iupf.lock().unwrap().branches_for_teid(ran_teid).len(),
            1,
            "its classifier branch is still installed"
        );
    }

    /// design/135 Phase 2b: the **full production chain** — AF → NEF → PCF → SMF. The AF
    /// posts a traffic-influence subscription; the NEF authorizes it at the PCF
    /// (Npcf_PolicyAuthorization); the PCF folds the route into the session's SM policy and
    /// notifies the SMF on the `notificationUri` it registered; the SMF re-authorizes,
    /// finds the route in the decision, and splices the breakout. Deleting the AF
    /// subscription unwinds the same chain.
    #[tokio::test]
    async fn af_influence_through_the_pcf_drives_a_breakout() {
        let (anchor_ip, iupf_ip, edge_ip) = (
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
            Ipv4Addr::new(127, 0, 0, 4),
        );
        let (anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;
        let (edge, edge_n4) = spin_upf(edge_ip).await;

        let (nrf_base, udr_base) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;
        let udr = sbi_core::nudr::UdrClient::new(udr_base.clone());
        udr.put_sm_policy_data(
            "imsi-999700000000001",
            &serde_json::json!({ "default": {
                "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" } } },
                "pccRules": { "pcc-1": { "refQosData": "qos-1" } },
                "qosDecs": { "qos-1": { "qfi": 1, "fiveQi": 9 } }
            } }),
        )
        .await
        .unwrap();
        // A real PCF (UDR-backed) — the SMF discovers it, and the NEF authorizes through it.
        let pcf_state = spin_pcf(&nrf_base, Some(&udr_base)).await;
        let _amf = spin_mock_amf(&nrf_base).await;
        let pcf_base = discover_endpoint(&nrf_base, "PCF").await.expect("PCF discoverable");

        let topo = crate::topology::Topology::parse(&format!(
            r#"{{
                "upNodes": {{
                    "gNB":    {{ "type": "AN" }},
                    "iupf":   {{ "type": "UPF", "n4": "{iupf_n4}" }},
                    "anchor": {{ "type": "UPF", "n4": "{anchor_n4}", "dnns": ["internet"] }},
                    "edge":   {{ "type": "UPF", "n4": "{edge_n4}", "dnai": "mec" }}
                }},
                "links": [
                    {{ "a": "gNB", "b": "iupf" }},
                    {{ "a": "iupf", "b": "anchor" }},
                    {{ "a": "iupf", "b": "edge" }}
                ]
            }}"#
        ))
        .unwrap();

        // Bind the SMF's listener first so its callback base — the policy notificationUri
        // the PCF calls back on — is its real address.
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        let smf = Arc::new(
            SmfState::connect_with_topology(topo, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap()
                .with_callback_base(format!("http://{smf_addr}")),
        );
        smf.associate().await.unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        // A NEF that authorizes influences through the PCF (Phase 2b), not the SMF direct.
        let nef = sbi_core::nnef::NefState::with_smf_base(format!("http://{smf_addr}"))
            .with_pcf_base(pcf_base);
        let nef_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nef_addr = nef_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(nef_l, sbi_core::nnef::router(nef)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let ran_teid = u32::from_str_radix(&created.up_n3_teid, 16).unwrap();
        assert_eq!(pcf_state.association_count(), 1, "the SMF created an SM policy association");
        assert_eq!(edge.lock().unwrap().session_count(), 0, "no influence yet");

        // The AF asks the NEF to steer 10.99.0.0/16 to the "mec" edge.
        let sub = client
            .post(format!("http://{nef_addr}/3gpp-traffic-influence/v1/app1/subscriptions"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "dnn": "internet",
                "prefix": "10.99.0.0/16",
                "trafficRoutes": [{ "dnai": "mec" }]
            }))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(sub.status().as_u16(), 201, "AF subscription created");
        let self_link = sub.headers().get("location").unwrap().to_str().unwrap().to_string();

        // AF → NEF → PCF → (notify) → SMF → N4: the breakout is live, driven entirely by
        // the policy — no direct NEF→SMF call was made.
        assert_eq!(edge.lock().unwrap().session_count(), 1, "the influenced breakout is spliced in");
        assert_eq!(
            iupf.lock().unwrap().branches_for_teid(ran_teid).len(),
            1,
            "the classifier steers the AF-influenced prefix"
        );

        // Deleting the AF subscription deletes the PCF app-session, which re-authorizes
        // the SMF with no route → the breakout is withdrawn.
        let del = client
            .delete(format!("http://{nef_addr}{self_link}"))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(del.as_u16(), 204, "AF subscription deleted");
        assert_eq!(edge.lock().unwrap().session_count(), 0, "the breakout is withdrawn");
        assert!(iupf.lock().unwrap().branches_for_teid(ran_teid).is_empty(), "the branch is gone");
        assert_eq!(anchor.lock().unwrap().session_count(), 1, "the default anchor is untouched");
    }

    /// design/135 Phase 3: a **group / any-UE** influence. The AF's request names no single
    /// session, so the NEF stores it in the UDR as application influence data; the PCF reads
    /// it when it authorizes a policy, and the SMF applies it **at establishment** — so a
    /// session created *after* the AF made its request is born with the breakout in place.
    #[tokio::test]
    async fn a_group_influence_applies_to_a_new_session_at_establishment() {
        let (anchor_ip, iupf_ip, edge_ip) = (
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
            Ipv4Addr::new(127, 0, 0, 4),
        );
        let (anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;
        let (edge, edge_n4) = spin_upf(edge_ip).await;

        let (nrf_base, udr_base) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;
        let udr = sbi_core::nudr::UdrClient::new(udr_base.clone());
        udr.put_sm_policy_data(
            "imsi-999700000000001",
            &serde_json::json!({ "default": {
                "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" } } },
                "pccRules": { "pcc-1": { "refQosData": "qos-1" } },
                "qosDecs": { "qos-1": { "qfi": 1, "fiveQi": 9 } }
            } }),
        )
        .await
        .unwrap();
        let _pcf = spin_pcf(&nrf_base, Some(&udr_base)).await;
        let _amf = spin_mock_amf(&nrf_base).await;
        let pcf_base = discover_endpoint(&nrf_base, "PCF").await.expect("PCF discoverable");

        let topo = crate::topology::Topology::parse(&format!(
            r#"{{
                "upNodes": {{
                    "gNB":    {{ "type": "AN" }},
                    "iupf":   {{ "type": "UPF", "n4": "{iupf_n4}" }},
                    "anchor": {{ "type": "UPF", "n4": "{anchor_n4}", "dnns": ["internet"] }},
                    "edge":   {{ "type": "UPF", "n4": "{edge_n4}", "dnai": "mec" }}
                }},
                "links": [
                    {{ "a": "gNB", "b": "iupf" }},
                    {{ "a": "iupf", "b": "anchor" }},
                    {{ "a": "iupf", "b": "edge" }}
                ]
            }}"#
        ))
        .unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        let smf = Arc::new(
            SmfState::connect_with_topology(topo, Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap()
                .with_callback_base(format!("http://{smf_addr}")),
        );
        smf.associate().await.unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let nef = sbi_core::nnef::NefState::with_smf_base(format!("http://{smf_addr}"))
            .with_pcf_base(pcf_base)
            .with_udr_base(udr_base.clone());
        let nef_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nef_addr = nef_l.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(nef_l, sbi_core::nnef::router(nef)).await.unwrap() });

        let client = sbi_core::h2c_client();
        // The AF influences **any UE** on "internet" — BEFORE any session exists.
        let sub = client
            .post(format!("http://{nef_addr}/3gpp-traffic-influence/v1/app1/subscriptions"))
            .json(&serde_json::json!({
                "anyUeInd": true, "dnn": "internet",
                "prefix": "10.99.0.0/16",
                "trafficRoutes": [{ "dnai": "mec" }]
            }))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(sub.status().as_u16(), 201, "group influence stored");
        let self_link = sub.headers().get("location").unwrap().to_str().unwrap().to_string();
        assert_eq!(
            udr.list_influence_data().await.unwrap().len(),
            1,
            "the influence lives in the UDR, not on a session"
        );

        // Now a session is established — it must be born with the breakout.
        let base = format!("http://{smf_addr}");
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let ran_teid = u32::from_str_radix(&created.up_n3_teid, 16).unwrap();
        assert_eq!(
            edge.lock().unwrap().session_count(),
            1,
            "the new session is established with the group influence's breakout"
        );
        assert_eq!(
            iupf.lock().unwrap().branches_for_teid(ran_teid).len(),
            1,
            "its classifier already steers the influenced prefix"
        );
        assert_eq!(anchor.lock().unwrap().session_count(), 1, "and still has its default anchor");

        // Withdrawing the AF subscription drops the UDR influence data.
        let del = client
            .delete(format!("http://{nef_addr}{self_link}"))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(del.as_u16(), 204, "AF subscription deleted");
        assert!(
            udr.list_influence_data().await.unwrap().is_empty(),
            "the influence is gone from the UDR, so later sessions are unaffected"
        );
    }

    /// The **uplink classifier** (design/134 Phase 2): one PDU session, one UE address,
    /// **two anchors**. The I-UPF forwards most uplink to the default anchor but steers
    /// the breakout prefix to a second PSA — and both anchors return downlink through the
    /// same I-UPF ingress. Three real `UpfState`s over real PFCP (.1 anchor,
    /// .2 classifier, .3 breakout anchor).
    #[tokio::test]
    async fn uplink_classifier_splits_one_session_across_two_anchors() {
        let (anchor_ip, iupf_ip, psa2_ip) = (
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
        );
        let (anchor, anchor_n4) = spin_upf(anchor_ip).await;
        let (iupf, iupf_n4) = spin_upf(iupf_ip).await;
        let (psa2, psa2_n4) = spin_upf(psa2_ip).await;
        let edge = pfcp::IpPrefix::new(Ipv4Addr::new(10, 99, 0, 0), 16);

        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let smf = Arc::new(
            SmfState::connect(
                UserPlane::chained(anchor_n4, iupf_n4).with_breakout(psa2_n4, edge),
                anchor_ip,
                nrf_base,
            )
            .await
            .unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(psa2.lock().unwrap().session_count(), 1, "the breakout anchor has a session");

        // Uplink fans out: the branch prefix goes to the second anchor, everything else
        // keeps the default N9 egress. Both decisions come from the *same* ingress TEID —
        // the classifier picks per packet.
        let ran_teid = u32::from_str_radix(&created.up_n3_teid, 16).unwrap();
        let branches = iupf.lock().unwrap().branches_for_teid(ran_teid);
        assert_eq!(branches.len(), 1, "one branch rule installed on the classifier");
        assert_eq!(branches[0].0, pfcp::FlowFilter::to_prefix(edge), "steering on the prefix");
        assert_eq!(
            branches[0].1,
            pfcp::Egress::ToPeer { teid: 1, addr: psa2_ip },
            "the branch egress is the breakout anchor's N3 ingress"
        );
        assert_eq!(
            iupf.lock().unwrap().uplink_egress_for_teid(ran_teid),
            Some(pfcp::Egress::ToPeer { teid: 1, addr: anchor_ip }),
            "the default egress is still the original anchor"
        );
        // Both anchors terminate on N6 — neither forwards onward.
        for (name, upf) in [("default", &anchor), ("breakout", &psa2)] {
            assert_eq!(
                upf.lock().unwrap().uplink_egress_for_teid(1),
                Some(pfcp::Egress::ToN6),
                "the {name} anchor terminates the session on N6"
            );
        }

        // Downlink converges: both anchors send back to the *same* I-UPF ingress, since
        // it is the node holding the gNB tunnel.
        let ue_ip = created.ue_ipv4_addr.expect("UE IPv4");
        let n9_dl = anchor.lock().unwrap().route_downlink(ue_ip).expect("anchor downlink");
        assert_eq!(n9_dl.1, iupf_ip);
        assert_eq!(
            psa2.lock().unwrap().route_downlink(ue_ip),
            Some(n9_dl),
            "the breakout anchor returns downlink through the same classifier ingress"
        );

        // Activation points the classifier at the gNB — one return path for both anchors.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"00005678","gnbN3Addr":"10.0.0.9"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "UpdateSMContext succeeded");
        assert_eq!(
            iupf.lock().unwrap().downlink_via_n9_ingress(n9_dl.0),
            Some((0x5678, Ipv4Addr::new(10, 0, 0, 9))),
            "downlink from either anchor reaches the gNB through the classifier"
        );

        // AN release parks *both* anchors, so neither keeps feeding a released tunnel.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"upCnxState":"DEACTIVATED"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "AN release succeeded");
        assert_eq!(anchor.lock().unwrap().route_downlink(ue_ip), None, "default anchor parked");
        assert_eq!(psa2.lock().unwrap().route_downlink(ue_ip), None, "breakout anchor parked");

        // …and re-activation restores both.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"0000abcd","gnbN3Addr":"10.0.0.11"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "re-activation succeeded");
        assert_eq!(anchor.lock().unwrap().route_downlink(ue_ip), Some(n9_dl));
        assert_eq!(psa2.lock().unwrap().route_downlink(ue_ip), Some(n9_dl));

        // Release tears down all three legs.
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");
        for (name, upf) in [("anchor", &anchor), ("classifier", &iupf), ("breakout", &psa2)] {
            assert_eq!(upf.lock().unwrap().session_count(), 0, "{name} N4 session deleted");
        }
    }

    /// CreateSMContext authorizes the DNN and establishes the session (UPF allocates
    /// the uplink TEID); UpdateSMContext installs the gNB downlink target on the UPF.
    #[tokio::test]
    async fn pdu_session_create_then_update_drives_n4() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);

        // In-process UPF: an N4 UDP loop over a shared UpfState the test can inspect.
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;

        // SMF: connect, associate, serve Nsmf.
        let smf =
            Arc::new(SmfState::connect(UserPlane::single(upf_addr), Ipv4Addr::new(127, 0, 0, 1), nrf_base).await.unwrap());
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        // AMF → SMF: CreateSMContext, with the UE's requested slice.
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(created.up_n3_teid, "00000001", "UPF allocated the first N3 TEID");
        // The SMF recorded itself as the serving SMF for the session (Nudm_UECM).
        // The registration is spawned off the create path — poll briefly.
        let udr = sbi_core::nudr::UdrClient::new(udr_base);
        let mut smf_reg = None;
        for _ in 0..50 {
            smf_reg = udr.get_smf_registration("imsi-999700000000001", 5).await.unwrap();
            if smf_reg.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let reg = smf_reg.expect("serving-SMF registration recorded");
        assert_eq!(reg.get("dnn").and_then(|v| v.as_str()), Some("internet"));
        assert_eq!(reg.get("pduSessionId").and_then(|v| v.as_u64()), Some(5));
        // The serving slice (== validated requested slice) + AMBR ride back for the
        // AMF's N1 accept.
        assert_eq!(created.s_nssai.sst, 1);
        assert_eq!(created.s_nssai.sd.as_deref(), Some("010203"));
        let ambr = created.session_ambr.as_ref().expect("subscribed session AMBR");
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("1 Gbps", "2 Gbps"));
        // The default (QFI 1, 5QI 9) + the provisioned GBR flow (QFI 2, 5QI 1) ride back.
        assert_eq!(created.qos_flows.len(), 2, "default + GBR flow");
        assert_eq!((created.qos_flows[0].qfi, created.qos_flows[0].five_qi), (1, 9));
        assert_eq!((created.qos_flows[1].qfi, created.qos_flows[1].five_qi), (2, 1));
        assert!(created.qos_flows[1].gbr.is_some(), "the second flow is GBR");
        assert_eq!(
            created.ue_ipv4_addr,
            Some(Ipv4Addr::new(10, 45, 0, 2)),
            "SMF allocated a UE IP from the pool"
        );
        assert_eq!(created.selected_pdu_session_type, "IPV4", "default session type");
        assert_eq!(upf_state.lock().unwrap().session_count(), 1, "N4 session established");

        // AMF → SMF: UpdateSMContext with the gNB's downlink F-TEID (from N2 setup).
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"00005678","gnbN3Addr":"10.0.0.9"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "UpdateSMContext succeeded");

        // The UPF now has the downlink installed for the session, reachable both by
        // UP-SEID and — the N6 datapath's view — by routing on the UE's assigned IP.
        assert_eq!(
            upf_state.lock().unwrap().downlink_for(1),
            Some((0x5678, Ipv4Addr::new(10, 0, 0, 9))),
            "N4 modification installed the gNB downlink target"
        );
        assert_eq!(
            upf_state.lock().unwrap().route_downlink(Ipv4Addr::new(10, 45, 0, 2)),
            Some((0x5678, Ipv4Addr::new(10, 0, 0, 9))),
            "UPF routes an N6 downlink packet to the gNB by the UE's assigned IP"
        );

        // AMF → SMF: a second UpdateSMContext re-pointing to a DIFFERENT gNB — a
        // handover / path switch. The modification carries a GTP-U End Marker request
        // (PFCPSMReq-Flags SNDEM); the UPF tolerates it and re-points the downlink.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"00009abc","gnbN3Addr":"10.0.0.10"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "re-point UpdateSMContext succeeded");
        assert_eq!(
            upf_state.lock().unwrap().downlink_for(1),
            Some((0x9abc, Ipv4Addr::new(10, 0, 0, 10))),
            "the downlink followed the handover to the new gNB tunnel"
        );

        // AMF → SMF: ReleaseSMContext (deregistration) — the N4 session goes too.
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");
        assert_eq!(upf_state.lock().unwrap().session_count(), 0, "N4 session deleted at the UPF");
        // The serving-SMF registration is purged (spawned off the release path).
        let mut gone = false;
        for _ in 0..50 {
            if udr.get_smf_registration("imsi-999700000000001", 5).await.unwrap().is_none() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(gone, "serving-SMF registration purged on release");

        // A second release of the same context → 404.
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404, "released context is gone");

        // A fresh session reuses the released UE IP rather than leaking the pool
        // (design/137 G6): the released 10.45.0.2 is handed back out, not 10.45.0.3.
        let created2: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 6, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            created2.ue_ipv4_addr,
            Some(Ipv4Addr::new(10, 45, 0, 2)),
            "the released address is reused, not leaked"
        );
    }

    /// N4 liveness (design/137 G4): when a UPF restarts — reported by a newer recovery
    /// timestamp on the next heartbeat — the SMF drops the now-stranded sessions and
    /// reclaims their addresses, so the UE can re-establish. Before this, a UPF restart
    /// left the SMF's contexts (and their leased IPs) pointing at sessions the UPF had
    /// forgotten.
    #[tokio::test]
    async fn upf_restart_drops_stranded_sessions_and_frees_addresses() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let (upf_state, upf_n4) = spin_upf(upf_ip).await;
        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let smf =
            Arc::new(SmfState::connect(UserPlane::single(upf_n4), upf_ip, nrf_base).await.unwrap());
        smf.associate().await.unwrap(); // records the UPF's baseline recovery timestamp
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        {
            let smf = smf.clone();
            tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });
        }
        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let create = |psi: u8| {
            let (client, base) = (client.clone(), base.clone());
            async move {
                client
                    .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
                    .json(&serde_json::json!({
                        "supi": "imsi-999700000000001", "pduSessionId": psi, "dnn": "internet",
                        "servingNetwork": { "mcc": "999", "mnc": "70" },
                        "sNssai": { "sst": 1, "sd": "010203" }
                    }))
                    .traced()
                    .send()
                    .await
                    .unwrap()
                    .json::<SmContextCreatedData>()
                    .await
                    .unwrap()
            }
        };

        // A session establishes and leases 10.45.0.2; the UPF holds its N4 session.
        let created = create(5).await;
        assert_eq!(created.ue_ipv4_addr, Some(Ipv4Addr::new(10, 45, 0, 2)));
        assert_eq!(upf_state.lock().unwrap().session_count(), 1);

        // The UPF restarts: a fresh state (no sessions) with a strictly newer recovery
        // timestamp. NTP is 1s-resolution, so +1000s is unambiguously later.
        *upf_state.lock().unwrap() =
            pfcp::UpfState::with_recovery_time(SystemTime::now() + Duration::from_secs(1000));

        // One heartbeat round sees the new timestamp, re-associates, and drops the
        // stranded context — returning its IP to the pool.
        smf.heartbeat_round().await;

        // Proof the context was dropped and its address freed: a new session reuses
        // 10.45.0.2 rather than advancing to .0.3, and the old context is gone (404).
        let created2 = create(6).await;
        assert_eq!(
            created2.ue_ipv4_addr,
            Some(Ipv4Addr::new(10, 45, 0, 2)),
            "the stranded session's address was reclaimed and reused"
        );
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"00001111","gnbN3Addr":"10.0.0.9"}))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404, "the stranded context was dropped");
    }

    /// With a PCF registered, the SMF sources the SM policy from it: a policy
    /// association is created at CreateSMContext and deleted at release. (The demo
    /// PCF returns the same QoS as sm-data, so the association count — not the flow
    /// values — is what distinguishes the PCF path from the fallback.)
    #[tokio::test]
    async fn pcf_drives_sm_policy_and_release_deletes_it() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let pcf = spin_pcf(&nrf_base, None).await;

        let smf = Arc::new(
            SmfState::connect(UserPlane::single(upf_addr), Ipv4Addr::new(127, 0, 0, 1), nrf_base).await.unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // The PCF's decision drove the response, and its association was created
        // synchronously on the create path.
        assert_eq!(pcf.association_count(), 1, "SMF created a PCF SM policy association");
        let ambr = created.session_ambr.as_ref().expect("PCF session AMBR");
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("1 Gbps", "2 Gbps"));
        assert_eq!(created.qos_flows.len(), 2, "PCF default + GBR flow");
        assert!(created.qos_flows.iter().any(|f| f.gbr.is_some()), "a GBR flow from the PCF");
        // The GBR flow's per-flow QER (classifier + MFBR) was installed at the UPF.
        assert_eq!(
            upf_state.lock().unwrap().flow_qfis(1),
            vec![2],
            "the UPF polices the GBR flow (QFI 2) per-flow"
        );

        // Release deletes the PCF association (spawned off the release path — poll).
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");
        let mut deleted = false;
        for _ in 0..50 {
            if pcf.association_count() == 0 {
                deleted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(deleted, "PCF SM policy association deleted on release");
    }

    /// GFBR admission control: a session whose GBR flow's GFBR exceeds the remaining
    /// budget is refused (503 → 5GSM #26); releasing a session frees the budget.
    #[tokio::test]
    async fn gfbr_admission_control_refuses_when_budget_exhausted() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        // Local demo PCF: its GBR flow has GFBR 100 Mbps each way.
        let _pcf = spin_pcf(&nrf_base, None).await;
        // Budget = exactly one demo GBR flow.
        let smf = Arc::new(
            SmfState::connect(UserPlane::single(upf_addr), Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap()
                .with_gfbr_budget(100_000_000, 100_000_000),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        let create = |psi: u8| {
            client
                .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
                .json(&serde_json::json!({
                    "supi": "imsi-999700000000001", "pduSessionId": psi, "dnn": "internet",
                    "servingNetwork": { "mcc": "999", "mnc": "70" },
                    "sNssai": { "sst": 1, "sd": "010203" }
                }))
                .traced()
                .send()
        };

        // First GBR session fits the budget exactly.
        let r1 = create(5).await.unwrap();
        assert_eq!(r1.status().as_u16(), 201, "first GBR session admitted");
        let created: SmContextCreatedData = r1.json().await.unwrap();
        // The second would exceed it → refused (GFBR admission control).
        let r2 = create(6).await.unwrap();
        assert_eq!(r2.status().as_u16(), 503, "second GBR session refused (insufficient resources)");

        // Releasing the first frees the budget, so a new session is admitted again.
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");
        let r3 = create(6).await.unwrap();
        assert_eq!(r3.status().as_u16(), 201, "budget freed on release — new session admitted");
    }

    /// The full charging loop (design/59): CreateSMContext opens an Nchf charging
    /// session at the NRF-discovered CHF; a UPF volume-threshold Session Report
    /// Request is acked and relayed as an Nchf update; release closes the CDR with
    /// the unreported remainder — the CDR totals exactly what moved, no
    /// double-billing.
    #[tokio::test]
    async fn charging_bills_threshold_reports_and_final_usage() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);

        // In-process UPF whose socket the test keeps a handle on, so it can play
        // the nf-upf reporter (send a UPF-initiated Session Report Request).
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upf_addr = upf_sock.local_addr().unwrap();
        let smf_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        {
            let upf_state = upf_state.clone();
            let upf_sock = upf_sock.clone();
            let smf_peer = smf_peer.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    *smf_peer.lock().unwrap() = Some(peer);
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, _udr) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let chf = spin_chf(&nrf_base).await;

        // SMF with a 1000-byte usage threshold + the usage-report handler running.
        let smf = Arc::new(
            SmfState::connect(UserPlane::single(upf_addr), Ipv4Addr::new(127, 0, 0, 1), nrf_base)
                .await
                .unwrap()
                .with_usage_threshold(1000),
        );
        smf.associate().await.unwrap();
        tokio::spawn(handle_usage_reports(smf.clone()));
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        // CreateSMContext → the SMF opened a charging data session at the CHF.
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(chf.open_sessions(), 1, "charging session opened with the PDU session");
        let cdr_ref = "0"; // the CHF's first charging-data allocation
        let cdr = chf.cdr(cdr_ref).expect("CDR opened");
        assert_eq!(cdr.subscriber_identifier, "imsi-999700000000001");
        assert_eq!(
            cdr.pdu_session_charging_information.as_ref().map(|p| (p.pdu_session_id, p.dnn.as_str())),
            Some((5, "internet"))
        );

        // 1500 uplink bytes cross the 1000-byte threshold: the UPF flags a report;
        // the test sends it from the UPF socket (what nf-upf's reporter task does).
        assert!(upf_state.lock().unwrap().admit_uplink(1, 0, &[0u8; 1500]));
        let due = upf_state.lock().unwrap().take_due_report().expect("threshold crossed");
        let peer = smf_peer.lock().unwrap().expect("SMF's N4 address learned");
        upf_sock.send_to(&pfcp::session_report_request(&due, 99), peer).await.unwrap();

        // The SMF acks and relays: the CDR accumulates the mid-session usage.
        let mut billed = None;
        for _ in 0..50 {
            billed = chf.cdr(cdr_ref).and_then(|c| c.usage.get(&0).copied());
            if billed.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let billed = billed.expect("mid-session usage billed at the CHF");
        assert_eq!((billed.uplink_volume, billed.total_volume), (1500, 1500));

        // 400 more bytes (under the threshold), then release: the deletion report
        // carries only the unreported remainder.
        assert!(upf_state.lock().unwrap().admit_uplink(1, 0, &[0u8; 400]));
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/release",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 204, "release succeeded");

        // The Nchf release is spawned off the path — poll for the closed CDR.
        let mut closed = None;
        for _ in 0..50 {
            closed = chf.cdr(cdr_ref).filter(|c| c.released);
            if closed.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let closed = closed.expect("CDR closed at release");
        assert_eq!(
            closed.usage[&0].total_volume,
            1900,
            "threshold report (1500) + final remainder (400) = the true total — no double-billing"
        );
        assert_eq!(chf.open_sessions(), 0);
    }

    /// A per-flow URR is charged under the rating group of its flow's PCF charging
    /// decision (`refChgData` → `chgDecs`), not the QFI; the session URR is group 0,
    /// and a flow with no charging decision falls back to the QFI.
    #[test]
    fn container_charges_under_the_flows_rating_group() {
        use sbi_core::npcf::{ChargingData, FlowStatus, QosFlowPolicy, SmPolicyDecision};
        let flow = |qfi, chg: Option<&str>| QosFlowPolicy {
            qfi,
            five_qi: 1,
            arp_priority: 8,
            pre_empt_cap: false,
            pre_empt_vuln: false,
            gbr: None,
            filter: None,
            ref_chg_data: chg.map(String::from),
            flow_status: FlowStatus::Enabled,
        };
        // QFI 2 is charged under "chg" (rating group 100); QFI 3 has no charging decision.
        let mut decision = SmPolicyDecision {
            charging_descs: std::collections::HashMap::from([(
                "chg".to_string(),
                ChargingData { rating_group: 100, metering_method: None, online: None, offline: None },
            )]),
            ..Default::default()
        };
        decision.set_flows([flow(2, Some("chg")), flow(3, None)]);
        let usage = |urr_id| pfcp::UsageVolume { urr_id, total: 30, uplink: 10, downlink: 20 };
        // The per-flow URR of QFI 2 → the charging decision's rating group (100), not 2.
        assert_eq!(container_for(&usage(pfcp::PER_FLOW_URR_BASE + 2), &decision).rating_group, 100);
        // QFI 3 has no charging decision → legacy fallback (rating group = QFI).
        assert_eq!(container_for(&usage(pfcp::PER_FLOW_URR_BASE + 3), &decision).rating_group, 3);
        // The session-level URR → rating group 0.
        assert_eq!(container_for(&usage(1), &decision).rating_group, 0);
    }

    /// The PCF→SMF gate bridge (design/151, G18): a GBR flow whose bound PCC rule
    /// carries a directional `flowStatus` becomes a `FlowQer` with the matching QER gate
    /// — proving the (uplink, downlink) pair is not transposed on the way to the UPF.
    #[test]
    fn flow_status_becomes_the_qer_gate() {
        use sbi_core::npcf::{
            FlowStatus, GbrPolicy, PacketFilterPolicy, PccRule, QosData, SmPolicyDecision,
        };
        let mut d = SmPolicyDecision::default();
        d.qos_descs.insert(
            "qos".into(),
            QosData {
                qfi: 5,
                five_qi: 1,
                arp_priority: 8,
                pre_empt_cap: false,
                pre_empt_vuln: false,
                gbr: Some(GbrPolicy {
                    gfbr_dl: "1 Mbps".into(),
                    gfbr_ul: "1 Mbps".into(),
                    mfbr_dl: "2 Mbps".into(),
                    mfbr_ul: "2 Mbps".into(),
                }),
            },
        );
        d.pcc_rules.insert(
            "pcc".into(),
            PccRule {
                precedence: 10,
                flow_info: Some(PacketFilterPolicy { protocol: 17, port_low: 5000, port_high: 5010 }),
                ref_qos_data: Some("qos".into()),
                ref_chg_data: None,
                flow_status: FlowStatus::EnabledUplink, // uplink open, downlink closed
            },
        );
        let flows = flow_qers(&d);
        assert_eq!(flows.len(), 1, "the GBR flow is emitted");
        assert_eq!(
            flows[0].gate,
            pfcp::Gate { uplink: true, downlink: false },
            "ENABLED-UPLINK maps to an uplink-open, downlink-closed QER gate",
        );
    }

    /// A UDR-backed PCF + the SMF's refresh-policy trigger: a mid-session change to
    /// the subscriber's UDR policy-data is picked up by Npcf_SMPolicyControl_Update
    /// and lands in the SMF's response.
    #[tokio::test]
    async fn refresh_policy_applies_a_mid_session_udr_change() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, udr_base) =
            spin_subscription_backend("imsi-999700000000001", "99970").await;
        // Provision the subscriber's SM policy-data (v1) in the same UDR, and back
        // the PCF with it.
        let udr = sbi_core::nudr::UdrClient::new(udr_base.clone());
        let v1 = serde_json::json!({ "default": {
            "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "200 Mbps", "downlink": "400 Mbps" } } },
            "pccRules": { "pcc-1": { "refQosData": "qos-1" } },
            "qosDecs": { "qos-1": { "qfi": 1, "fiveQi": 9 } } } });
        udr.put_sm_policy_data("imsi-999700000000001", &v1).await.unwrap();
        let _pcf = spin_pcf(&nrf_base, Some(&udr_base)).await;
        // A mock AMF records the SMF's Namf_Communication PDU-modify notification.
        let amf_modifies = spin_mock_amf(&nrf_base).await;

        let smf = Arc::new(
            SmfState::connect(UserPlane::single(upf_addr), Ipv4Addr::new(127, 0, 0, 1), nrf_base).await.unwrap(),
        );
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
                "servingNetwork": { "mcc": "999", "mnc": "70" },
                "sNssai": { "sst": 1, "sd": "010203" }
            }))
            .traced()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // Initial policy = the UDR's v1 (200/400 Mbps, one flow) — not the local demo.
        let ambr = created.session_ambr.as_ref().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("200 Mbps", "400 Mbps"));
        assert_eq!(created.qos_flows.len(), 1);
        // The AMBR was installed on the user plane as a QER (the UPF's first session
        // is up_seid 1).
        assert_eq!(
            upf_state.lock().unwrap().ambr_for(1),
            Some(pfcp::SessionAmbr { uplink_bps: 200_000_000, downlink_bps: 400_000_000 }),
            "UPF polices the v1 session AMBR"
        );
        assert!(
            upf_state.lock().unwrap().flow_qfis(1).is_empty(),
            "no per-flow QER for the v1 (non-GBR) policy"
        );

        // Mid-session change: reprovision the UDR policy-data (v2) — new session AMBR
        // plus a GBR flow (QFI 2) with a classifier.
        let v2 = serde_json::json!({ "default": {
            "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "50 Mbps", "downlink": "100 Mbps" } } },
            "pccRules": {
                "pcc-1": { "refQosData": "qos-1" },
                "pcc-2": { "refQosData": "qos-2",
                           "flowInfo": { "protocol": 17, "portLow": 5000, "portHigh": 5010 } }
            },
            "qosDecs": {
                "qos-1": { "qfi": 1, "fiveQi": 9 },
                "qos-2": { "qfi": 2, "fiveQi": 1, "gbr": {
                    "gfbrDl": "10 Mbps", "gfbrUl": "10 Mbps",
                    "mfbrDl": "20 Mbps", "mfbrUl": "20 Mbps" } }
            } } });
        udr.put_sm_policy_data("imsi-999700000000001", &v2).await.unwrap();

        // refresh-policy re-authorizes via Npcf Update → the changed decision.
        let resp = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/refresh-policy",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "refresh succeeded");
        let updated: sbi_core::npcf::SmPolicyDecision = resp.json().await.unwrap();
        let ambr = updated.session_ambr().unwrap();
        assert_eq!((ambr.uplink.as_str(), ambr.downlink.as_str()), ("50 Mbps", "100 Mbps"));
        assert_eq!(updated.qos_flows().len(), 2, "the mid-session change added a GBR flow");
        // The change reached the user plane: the SMF re-rated the UPF's QER...
        assert_eq!(
            upf_state.lock().unwrap().ambr_for(1),
            Some(pfcp::SessionAmbr { uplink_bps: 50_000_000, downlink_bps: 100_000_000 }),
            "UPF now polices the v2 session AMBR"
        );
        // ...and installed the newly-authorized GBR flow's per-flow QER mid-session.
        assert_eq!(
            upf_state.lock().unwrap().flow_qfis(1),
            vec![2],
            "the UPF now polices the mid-session-added GBR flow (QFI 2)"
        );
        // And it reached the RAN/UE path: the SMF notified the serving AMF
        // (Namf_Communication) — spawned off the response, so poll briefly.
        let mut notified = None;
        for _ in 0..50 {
            if let Some(b) = amf_modifies.lock().unwrap().first().cloned() {
                notified = Some(b);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let body = notified.expect("SMF notified the AMF of the QoS change");
        assert_eq!(body.get("pduSessionId").and_then(|v| v.as_u64()), Some(5));
        assert_eq!(
            body.pointer("/sessionAmbr/downlink").and_then(|v| v.as_str()),
            Some("100 Mbps")
        );
        assert_eq!(body.get("qosFlows").and_then(|v| v.as_array()).map(|a| a.len()), Some(2));
        assert_eq!(
            body.get("releasedQfis").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(0),
            "nothing released when a flow is added"
        );

        // Second mid-session change: v3 removes the GBR flow (back to non-GBR only).
        let v3 = serde_json::json!({ "default": {
            "sessRules": { "rule-1": { "authSessAmbr": { "uplink": "50 Mbps", "downlink": "100 Mbps" } } },
            "pccRules": { "pcc-1": { "refQosData": "qos-1" } },
            "qosDecs": { "qos-1": { "qfi": 1, "fiveQi": 9 } } } });
        udr.put_sm_policy_data("imsi-999700000000001", &v3).await.unwrap();
        let status = client
            .post(format!(
                "{base}/nsmf-pdusession/v1/sm-contexts/{}/refresh-policy",
                created.sm_context_ref
            ))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 200, "second refresh succeeded");
        // The UPF dropped the per-flow QER...
        assert!(
            upf_state.lock().unwrap().flow_qfis(1).is_empty(),
            "the UPF removed the GBR flow's per-flow QER"
        );
        // ...and the AMF was told to release QFI 2 toward the RAN/UE.
        let mut released = None;
        for _ in 0..50 {
            if let Some(b) = amf_modifies.lock().unwrap().get(1).cloned() {
                released = Some(b);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let body = released.expect("SMF notified the AMF of the flow removal");
        assert_eq!(
            body.get("releasedQfis").and_then(|v| v.as_array()),
            Some(&vec![serde_json::json!(2)]),
            "QFI 2 released toward the RAN/UE"
        );

        // refresh-policy on an unknown context → 404.
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/nope/refresh-policy"))
            .traced()
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404, "unknown context");
    }

    /// An unsubscribed DNN is rejected with 403 *before* any N4 state is created.
    #[tokio::test]
    async fn unsubscribed_dnn_is_rejected_without_n4_state() {
        let upf_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upf_state = Arc::new(Mutex::new(pfcp::UpfState::new()));
        let upf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upf_addr = upf_sock.local_addr().unwrap();
        {
            let upf_state = upf_state.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, peer) = upf_sock.recv_from(&mut buf).await.unwrap();
                    let resp = {
                        let mut s = upf_state.lock().unwrap();
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s, 0)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        let (nrf_base, _udr_base) = spin_subscription_backend("imsi-999700000000001", "99970").await;
        let smf =
            Arc::new(SmfState::connect(UserPlane::single(upf_addr), Ipv4Addr::new(127, 0, 0, 1), nrf_base).await.unwrap());
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");
        // POST and return (status, ProblemDetails cause).
        let post = |body: serde_json::Value| {
            let client = client.clone();
            let url = format!("{base}/nsmf-pdusession/v1/sm-contexts");
            async move {
                let resp = client.post(url).json(&body).traced().send().await.unwrap();
                let status = resp.status().as_u16();
                let cause = resp
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|b| b.get("cause").and_then(|c| c.as_str()).map(str::to_owned));
                (status, cause)
            }
        };

        // DNN not in the subscription (no slice requested) → 403 DNN_DENIED.
        let (status, cause) = post(serde_json::json!({
            "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "corporate",
            "servingNetwork": { "mcc": "999", "mnc": "70" }
        }))
        .await;
        assert_eq!((status, cause.as_deref()), (403, Some("DNN_DENIED")));

        // Requested slice not subscribed → 403 SNSSAI_DENIED.
        let (status, cause) = post(serde_json::json!({
            "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet",
            "servingNetwork": { "mcc": "999", "mnc": "70" },
            "sNssai": { "sst": 2, "sd": "010203" }
        }))
        .await;
        assert_eq!((status, cause.as_deref()), (403, Some("SNSSAI_DENIED")));

        // Subscribed slice, but the DNN isn't allowed in it → 403 DNN_DENIED.
        let (status, cause) = post(serde_json::json!({
            "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "corporate",
            "servingNetwork": { "mcc": "999", "mnc": "70" },
            "sNssai": { "sst": 1, "sd": "010203" }
        }))
        .await;
        assert_eq!((status, cause.as_deref()), (403, Some("DNN_DENIED")));

        // Unknown subscriber → 403 (no smf-selection data at all).
        let (status, _) = post(serde_json::json!({
            "supi": "imsi-999700000000099", "pduSessionId": 5, "dnn": "internet",
            "servingNetwork": { "mcc": "999", "mnc": "70" }
        }))
        .await;
        assert_eq!(status, 403);

        // Missing serving network → 400.
        let (status, cause) = post(serde_json::json!({
            "supi": "imsi-999700000000001", "pduSessionId": 5, "dnn": "internet"
        }))
        .await;
        assert_eq!((status, cause.as_deref()), (400, Some("MANDATORY_IE_MISSING")));

        assert_eq!(upf_state.lock().unwrap().session_count(), 0, "no N4 session was created");
    }

    #[tokio::test]
    async fn smf_registers_and_is_discoverable() {
        use sbi_core::nnrf::NrfClient;
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let store = sbi_core::nnrf::NrfStore::default();
        tokio::spawn(async move { sbi_core::run_on(nrf_l, sbi_core::nnrf::router(store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");

        register_with_nrf(&nrf_base, Ipv4Addr::new(127, 0, 0, 1), 8002).await.unwrap();

        let found = NrfClient::new(nrf_base).discover("SMF", "AMF").await.unwrap();
        assert_eq!(found.len(), 1, "SMF is discoverable via the NRF after registration");
    }
}
