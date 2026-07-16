//! radian-gnb — the standalone gNodeB (design/128 Phases 0–1). It terminates **N2**
//! (NGAP over SCTP to the AMF, with NG Setup and reconnect), **N3** (GTP-U to the UPF,
//! marking uplink G-PDUs with the QFI per TS 38.415), and a **Uu** toward UEs ([`uu`])
//! that carries **real RRC over PDCP** on signalling radio bearers (Phase 1) — SRB0 for
//! connection setup, SRB1 (PDCP) for NAS transport, the security-mode procedure, and
//! release. NAS rides opaque inside the RRC. The [`UuTransport`] seam is unchanged (Phase
//! 3 swaps it for F1).
//!
//! State per UE: the RAN/AMF UE-NGAP-IDs, the Uu peer, each PDU session's F-TEIDs + QFI,
//! and the RRC/PDCP context — the SRB1 PDCP entity (integrity/ciphering activated at the
//! security-mode procedure with keys derived from K_gNB) and the RRC transaction counter.
//! Contexts die with the N2 association (or a release command).

pub mod uu;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use pdcp::{PdcpSrb, Role};
use sctp_rs::{
    ConnectedSocket, NotificationOrData, SendData, SendInfo, Socket, SocketToAssociation,
};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::uu::{DlMessage, UlMessage};

const NGAP_PPID: u32 = 60;
/// How long to wait for the NGSetupResponse before retrying the association.
const NG_SETUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Backoff between association attempts (and after an association loss).
const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
/// The first RAN-allocated downlink N3 F-TEID (then incrementing).
const FIRST_DL_TEID: u32 = 0x2001;
/// AS security algorithms this gNB selects — 128-NEA2 / 128-NIA2 (matching the NAS
/// algorithms the core negotiates; the only pair we ship, per design/128 §6).
const NEA2: u8 = 2;
const NIA2: u8 = 2;
/// Signalling radio bearer identities on the Uu.
const SRB0: u8 = 0;
const SRB1: u8 = 1;

// ── configuration ───────────────────────────────────────────────────────────────────────

/// gNB configuration, read from `RADIAN_GNB_*` environment variables.
#[derive(Debug, Clone)]
pub struct GnbConfig {
    /// The 22-bit gNB identity advertised in NG Setup (`RADIAN_GNB_ID`, default 0x314).
    pub gnb_id: u32,
    /// PLMN (`RADIAN_GNB_MCC` / `RADIAN_GNB_MNC`, default 999/70 — the test PLMN).
    pub mcc: String,
    pub mnc: String,
    /// Served tracking areas (`RADIAN_GNB_TACS`, comma-separated 6-hex-digit TACs,
    /// default "000001").
    pub tacs: Vec<[u8; 3]>,
    /// The AMF's N2 endpoint (`RADIAN_GNB_AMF_N2`, default 127.0.0.1:38412).
    pub amf_addr: SocketAddr,
    /// The gNB's N3 address — bound for GTP-U and advertised in DL F-TEIDs
    /// (`RADIAN_GNB_N3_ADDR`, default 127.0.0.1).
    pub n3_addr: Ipv4Addr,
    /// The fake-Uu UDP endpoint UEs reach the gNB at (`RADIAN_GNB_UU_BIND`,
    /// default 127.0.0.1:4997).
    pub uu_bind: SocketAddr,
}

impl Default for GnbConfig {
    fn default() -> Self {
        Self {
            gnb_id: 0x314,
            mcc: "999".into(),
            mnc: "70".into(),
            tacs: vec![[0, 0, 1]],
            amf_addr: "127.0.0.1:38412".parse().unwrap(),
            n3_addr: Ipv4Addr::LOCALHOST,
            uu_bind: "127.0.0.1:4997".parse().unwrap(),
        }
    }
}

impl GnbConfig {
    /// Read the configuration from the environment, falling back to defaults.
    pub fn from_env() -> Result<Self> {
        let d = Self::default();
        let var = |name: &str| std::env::var(name).ok();
        Ok(Self {
            gnb_id: match var("RADIAN_GNB_ID") {
                Some(v) => v.parse().context("RADIAN_GNB_ID")?,
                None => d.gnb_id,
            },
            mcc: var("RADIAN_GNB_MCC").unwrap_or(d.mcc),
            mnc: var("RADIAN_GNB_MNC").unwrap_or(d.mnc),
            tacs: match var("RADIAN_GNB_TACS") {
                Some(v) => v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(parse_tac)
                    .collect::<Result<Vec<_>>>()?,
                None => d.tacs,
            },
            amf_addr: match var("RADIAN_GNB_AMF_N2") {
                Some(v) => v.parse().context("RADIAN_GNB_AMF_N2")?,
                None => d.amf_addr,
            },
            n3_addr: match var("RADIAN_GNB_N3_ADDR") {
                Some(v) => v.parse().context("RADIAN_GNB_N3_ADDR")?,
                None => d.n3_addr,
            },
            uu_bind: match var("RADIAN_GNB_UU_BIND") {
                Some(v) => v.parse().context("RADIAN_GNB_UU_BIND")?,
                None => d.uu_bind,
            },
        })
    }
}

/// Parse a 6-hex-digit TAC ("000001") into its 3 wire bytes.
fn parse_tac(tac: &str) -> Result<[u8; 3]> {
    anyhow::ensure!(tac.len() == 6, "TAC must be 6 hex digits, got {tac:?}");
    let mut out = [0u8; 3];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&tac[2 * i..2 * i + 2], 16)
            .with_context(|| format!("TAC {tac:?} is not hex"))?;
    }
    Ok(out)
}

// ── the Uu seam ─────────────────────────────────────────────────────────────────────────

/// The UE-facing seam (design/128 P0): the gNB core is generic over how it
/// reaches UEs, so the same core can serve the P0 UDP fake Uu ([`UdpUu`]), an
/// in-process test link, and eventually the Phase-3 F1 adapter.
#[allow(async_fn_in_trait)] // used generically inside this binary, never boxed
pub trait UuTransport {
    /// A stable address for one UE endpoint.
    type Peer: Copy + Eq + std::hash::Hash + std::fmt::Debug;

    /// The next decoded uplink message and the peer it came from.
    async fn recv(&mut self) -> Result<(Self::Peer, UlMessage)>;
    /// Send one downlink message to a peer.
    async fn send(&mut self, peer: Self::Peer, msg: &DlMessage) -> Result<()>;
}

/// The P0 fake Uu: one [`uu`] message per UDP datagram; a UE endpoint is its
/// socket address.
pub struct UdpUu {
    sock: UdpSocket,
    buf: Vec<u8>,
}

impl UdpUu {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let sock = UdpSocket::bind(addr).await.with_context(|| format!("bind Uu at {addr}"))?;
        Ok(Self { sock, buf: vec![0u8; 4096] })
    }
}

impl UuTransport for UdpUu {
    type Peer = SocketAddr;

    async fn recv(&mut self) -> Result<(SocketAddr, UlMessage)> {
        loop {
            let (n, peer) = self.sock.recv_from(&mut self.buf).await.context("Uu recv")?;
            match UlMessage::decode(&self.buf[..n]) {
                Some(msg) => return Ok((peer, msg)),
                None => warn!(%peer, bytes = n, "undecodable Uu uplink datagram — dropped"),
            }
        }
    }

    async fn send(&mut self, peer: SocketAddr, msg: &DlMessage) -> Result<()> {
        self.sock.send_to(&msg.encode(), peer).await.context("Uu send")?;
        Ok(())
    }
}

// ── per-UE state ────────────────────────────────────────────────────────────────────────

/// One PDU session's user plane: the QFI uplink G-PDUs are marked with, the
/// UPF's UL F-TEID (encap target), and the DL F-TEID this gNB allocated.
#[derive(Debug, Clone, Copy)]
struct SessionCtx {
    psi: u8,
    qfi: u8,
    upf_teid: u32,
    upf_addr: Ipv4Addr,
    dl_teid: u32,
}

/// The N2 side of a pending Initial Context Setup, held while the AS security-mode
/// procedure runs — replayed into the Initial Context Setup Response once the UE
/// confirms security (so the response reflects the same admitted sessions).
#[derive(Debug, Clone)]
struct PendingIcs {
    amf_ue_id: u64,
    /// `(psi, gnb_dl_teid, gnb_dl_addr)` admitted inline (empty at initial registration).
    admitted: Vec<(u8, u32, Ipv4Addr)>,
}

/// One UE's RAN context — the NGAP identities, its PDU sessions, and its RRC/PDCP state.
struct UeCtx<P> {
    peer: P,
    /// Learned from the first UE-associated downlink (DL NAS / ICS).
    amf_ue_id: Option<u64>,
    sessions: Vec<SessionCtx>,
    /// The SRB1 PDCP entity (gNB side): adds the SN, and — once the security-mode
    /// procedure activates it — the MAC-I and ciphering.
    srb1: PdcpSrb,
    /// Next RRC transaction identifier for gNB-originated DCCH messages (2-bit).
    rrc_txn: u8,
    /// NAS to deliver to the UE once AS security is active (the ICS's Registration
    /// Accept, held across the security-mode procedure).
    pending_dl_nas: Vec<Vec<u8>>,
    /// The ICS response to send once AS security completes.
    pending_ics: Option<PendingIcs>,
}

impl<P> UeCtx<P> {
    fn new(peer: P) -> Self {
        Self {
            peer,
            amf_ue_id: None,
            sessions: Vec::new(),
            srb1: PdcpSrb::new(Role::Gnb, SRB1),
            rrc_txn: 0,
            pending_dl_nas: Vec::new(),
            pending_ics: None,
        }
    }

    /// The next 2-bit RRC transaction identifier.
    fn next_txn(&mut self) -> u8 {
        let t = self.rrc_txn;
        self.rrc_txn = (self.rrc_txn + 1) & 0x3;
        t
    }

    /// Build the SRB1 wire payload for a downlink NAS message: wrap it in an RRC
    /// DLInformationTransfer and PDCP-protect it (protected once security is active).
    fn dl_nas_srb1(&mut self, nas: Vec<u8>) -> Vec<u8> {
        let txn = self.next_txn();
        self.srb1.protect(&rrc::dl_information_transfer(txn, nas))
    }
}

/// The gNB's mutable state: UE contexts and the ID/TEID allocators.
struct GnbState<P> {
    ues: HashMap<u32, UeCtx<P>>,
    by_peer: HashMap<P, u32>,
    /// Every Uu peer ever seen — the paging "broadcast domain" (released UEs
    /// keep camping and must still be pageable).
    camped: Vec<P>,
    next_ran_ue_id: u32,
    next_dl_teid: u32,
}

impl<P: Copy + Eq + std::hash::Hash> GnbState<P> {
    fn new() -> Self {
        Self {
            ues: HashMap::new(),
            by_peer: HashMap::new(),
            camped: Vec::new(),
            next_ran_ue_id: 1,
            next_dl_teid: FIRST_DL_TEID,
        }
    }

    /// A fresh UE context for `peer` (dropping any stale one — a new connection
    /// from the same endpoint replaces the old RRC-level association).
    fn new_ue(&mut self, peer: P) -> u32 {
        if let Some(old) = self.by_peer.remove(&peer) {
            self.ues.remove(&old);
        }
        let ran_ue_id = self.next_ran_ue_id;
        self.next_ran_ue_id += 1;
        self.ues.insert(ran_ue_id, UeCtx::new(peer));
        self.by_peer.insert(peer, ran_ue_id);
        if !self.camped.contains(&peer) {
            self.camped.push(peer);
        }
        ran_ue_id
    }

    fn alloc_dl_teid(&mut self) -> u32 {
        let teid = self.next_dl_teid;
        self.next_dl_teid += 1;
        teid
    }

    fn remove_ue(&mut self, ran_ue_id: u32) -> Option<UeCtx<P>> {
        let ctx = self.ues.remove(&ran_ue_id)?;
        self.by_peer.remove(&ctx.peer);
        Some(ctx)
    }

    /// The UE context owning DL F-TEID `teid`, as `(ran_ue_id, psi, peer)`.
    fn session_by_dl_teid(&self, teid: u32) -> Option<(u32, u8, P)> {
        self.ues.iter().find_map(|(id, ue)| {
            ue.sessions.iter().find(|s| s.dl_teid == teid).map(|s| (*id, s.psi, ue.peer))
        })
    }
}

// ── NGAP plumbing ───────────────────────────────────────────────────────────────────────

/// APER-encode and send one NGAP PDU on the N2 association.
async fn send_ngap(conn: &ConnectedSocket, pdu: &ngap::NGAP_PDU) -> Result<()> {
    let payload = pdu.encode().map_err(|e| anyhow!("NGAP encode failed: {e:?}"))?;
    conn.sctp_send(SendData {
        payload,
        snd_info: Some(SendInfo { ppid: NGAP_PPID, ..Default::default() }),
    })
    .await
    .context("N2 sctp_send")
}

/// Receive the next NGAP PDU, skipping SCTP notifications. An empty payload is
/// the peer closing the association — surfaced as an error so the caller
/// reconnects.
async fn recv_ngap(conn: &ConnectedSocket) -> Result<ngap::NGAP_PDU> {
    loop {
        match conn.sctp_recv().await.context("N2 sctp_recv")? {
            NotificationOrData::Notification(_) => continue,
            NotificationOrData::Data(data) => {
                if data.payload.is_empty() {
                    bail!("the AMF closed the N2 association");
                }
                return ngap::NGAP_PDU::decode(&data.payload)
                    .map_err(|e| anyhow!("NGAP decode failed: {e:?}"));
            }
        }
    }
}

/// Open the N2 association and run NG Setup.
async fn connect_and_setup(cfg: &GnbConfig) -> Result<ConnectedSocket> {
    let socket = Socket::new_v4(SocketToAssociation::OneToOne).context("create SCTP socket")?;
    let (conn, _assoc) = socket.connect(cfg.amf_addr).await.context("connect N2 SCTP")?;
    send_ngap(&conn, &ngap::ng_setup_request(cfg.gnb_id, &cfg.mcc, &cfg.mnc, &cfg.tacs)).await?;
    let pdu = tokio::time::timeout(NG_SETUP_TIMEOUT, recv_ngap(&conn))
        .await
        .map_err(|_| anyhow!("timed out waiting for the NGSetupResponse"))??;
    match &pdu {
        ngap::NGAP_PDU::SuccessfulOutcome(o)
            if matches!(o.value, ngap::SuccessfulOutcomeValue::Id_NGSetup(_)) =>
        {
            Ok(conn)
        }
        other => bail!("expected NGSetupResponse, got {other}"),
    }
}

// ── the gNB ─────────────────────────────────────────────────────────────────────────────

/// Run the gNB: bind N3, then keep an N2 association alive — connect, NG Setup,
/// serve until the association drops, back off, reconnect. UE contexts do not
/// survive an association loss (their NGAP IDs are association-scoped).
pub async fn run<T: UuTransport>(cfg: GnbConfig, mut transport: T) -> Result<()> {
    let n3 = UdpSocket::bind(SocketAddrV4::new(cfg.n3_addr, gtpu::GTPU_PORT))
        .await
        .with_context(|| format!("bind N3 GTP-U at {}:{}", cfg.n3_addr, gtpu::GTPU_PORT))?;
    info!(n3 = %cfg.n3_addr, uu = %cfg.uu_bind, "gNB up: N3 (GTP-U) bound, Uu listening");

    loop {
        match connect_and_setup(&cfg).await {
            Ok(conn) => {
                info!(amf = %cfg.amf_addr, gnb_id = format_args!("{:#x}", cfg.gnb_id),
                      "NG Setup complete");
                let mut state = GnbState::new();
                if let Err(e) = serve(&cfg, &conn, &mut transport, &n3, &mut state).await {
                    warn!("N2 association lost: {e:#}; reconnecting");
                }
            }
            Err(e) => warn!(amf = %cfg.amf_addr, "N2 setup failed: {e:#}; retrying"),
        }
        tokio::time::sleep(RECONNECT_BACKOFF).await;
    }
}

/// The gNB's event loop over its three interfaces. Returns `Err` only for N2
/// association failures (the caller reconnects); per-datagram Uu/N3 problems are
/// logged and served past.
async fn serve<T: UuTransport>(
    cfg: &GnbConfig,
    conn: &ConnectedSocket,
    transport: &mut T,
    n3: &UdpSocket,
    state: &mut GnbState<T::Peer>,
) -> Result<()> {
    let mut n3_buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            pdu = recv_ngap(conn) => {
                handle_ngap(cfg, conn, transport, state, &pdu?).await?;
            }
            msg = transport.recv() => {
                let (peer, msg) = msg.context("Uu transport failed")?;
                handle_uu(cfg, conn, transport, n3, state, peer, msg).await?;
            }
            recv = n3.recv_from(&mut n3_buf) => {
                let (n, src) = recv.context("N3 recv")?;
                if let Err(e) = handle_n3(transport, n3, state, &n3_buf[..n], src).await {
                    warn!(%src, "N3 datagram handling failed: {e:#}");
                }
            }
        }
    }
}

/// Dispatch one NGAP PDU from the AMF.
async fn handle_ngap<T: UuTransport>(
    cfg: &GnbConfig,
    conn: &ConnectedSocket,
    transport: &mut T,
    state: &mut GnbState<T::Peer>,
    pdu: &ngap::NGAP_PDU,
) -> Result<()> {
    // DownlinkNASTransport → relay the NAS to the UE in an RRC DLInformationTransfer on
    // SRB1 (unprotected before AS security, ciphered after), learning its AMF-UE-NGAP-ID.
    if let Some((amf_ue_id, ran_ue_id, nas)) = ngap::downlink_nas_transport_params(pdu) {
        let Some(ue) = state.ues.get_mut(&ran_ue_id) else {
            warn!(ran_ue_id, "downlink NAS for an unknown UE context — dropped");
            return Ok(());
        };
        ue.amf_ue_id = Some(amf_ue_id);
        let (peer, payload) = (ue.peer, ue.dl_nas_srb1(nas));
        if let Err(e) = transport.send(peer, &DlMessage::Srb { srb_id: SRB1, payload }).await {
            warn!(ran_ue_id, "Uu downlink NAS relay failed: {e:#}");
        }
        return Ok(());
    }

    // InitialContextSetupRequest → the AMF hands us K_gNB. Run the AS **security-mode
    // procedure** over SRB1 (derive K_RRC, send an integrity-protected RRC
    // SecurityModeCommand), and hold the ICS's NAS (Registration Accept) + the ICS
    // response until the UE confirms security. Any inline PDU sessions (Service Request
    // resume) are admitted now and reflected in the deferred response.
    if let Some((amf_ue_id, ran_ue_id, ic)) = ngap::initial_context_setup_params(pdu) {
        if !state.ues.contains_key(&ran_ue_id) {
            warn!(ran_ue_id, "InitialContextSetupRequest for an unknown UE — ignored");
            return Ok(());
        }
        let qfis: HashMap<u8, u8> = ngap::initial_context_setup_request_qfis(pdu).into_iter().collect();
        let mut admitted = Vec::new();
        let mut sessions = Vec::new();
        for (psi, upf_teid, upf_addr) in ngap::initial_context_setup_request_session_ids(pdu) {
            let dl_teid = state.alloc_dl_teid();
            let qfi = qfis.get(&psi).copied().unwrap_or(1);
            sessions.push(SessionCtx { psi, qfi, upf_teid, upf_addr, dl_teid });
            admitted.push((psi, dl_teid, cfg.n3_addr));
            info!(ran_ue_id, psi, qfi, upf_teid, dl_teid, "PDU session restored at context setup");
        }
        // Derive the AS keys from K_gNB and start the security-mode procedure: activate
        // SRB1 integrity, send the SecurityModeCommand (integrity-protected, not yet
        // ciphered), then activate ciphering for everything after.
        let keys = aka::rrc_keys(&ic.security_key, NEA2, NIA2);
        let ue = state.ues.get_mut(&ran_ue_id).expect("context checked above");
        ue.amf_ue_id = Some(amf_ue_id);
        ue.sessions.extend(&sessions);
        ue.srb1.activate_integrity(keys.krrc_int, NIA2);
        let txn = ue.next_txn();
        let smc = ue.srb1.protect(&rrc::security_mode_command(txn, NEA2, NIA2));
        ue.srb1.activate_ciphering(keys.krrc_enc, NEA2);
        if !ic.nas.is_empty() {
            ue.pending_dl_nas.push(ic.nas);
        }
        ue.pending_ics = Some(PendingIcs { amf_ue_id, admitted });
        let peer = ue.peer;
        info!(ran_ue_id, amf_ue_id, "AS security-mode procedure started (SecurityModeCommand sent)");
        if let Err(e) = transport.send(peer, &DlMessage::Srb { srb_id: SRB1, payload: smc }).await {
            warn!(ran_ue_id, "Uu SecurityModeCommand send failed: {e:#}");
        }
        return Ok(());
    }

    // PDUSessionResourceSetupRequest → allocate the DL F-TEID, confirm, relay the
    // NAS (the PDU Session Establishment Accept) to the UE.
    if let Some((amf_ue_id, ran_ue_id, sessions)) = ngap::pdu_session_resource_setup_request_params(pdu) {
        let Some(ue) = state.ues.get(&ran_ue_id) else {
            warn!(ran_ue_id, "PDUSessionResourceSetupRequest for an unknown UE — ignored");
            return Ok(());
        };
        let peer = ue.peer;
        let qfis: HashMap<u8, u8> = ngap::pdu_session_setup_request_qfis(pdu).into_iter().collect();
        if sessions.len() > 1 {
            // The response builder reports one session; the AMF sets up one per
            // request today. Honest failure over silent partial setup.
            warn!(ran_ue_id, count = sessions.len(), "only the first PDU session of the request is set up");
        }
        for (psi, upf_teid, upf_addr, nas) in sessions.into_iter().take(1) {
            let dl_teid = state.alloc_dl_teid();
            let qfi = qfis.get(&psi).copied().unwrap_or(1);
            let ue = state.ues.get_mut(&ran_ue_id).expect("context checked above");
            ue.sessions.push(SessionCtx { psi, qfi, upf_teid, upf_addr, dl_teid });
            send_ngap(
                conn,
                &ngap::pdu_session_resource_setup_response(amf_ue_id, ran_ue_id, psi, qfi, dl_teid, cfg.n3_addr),
            )
            .await?;
            info!(ran_ue_id, psi, qfi, upf_teid, dl_teid, "PDU session set up");
            // Relay the PDU Session Establishment Accept to the UE over SRB1 (ciphered).
            if !nas.is_empty() {
                let payload = ue.dl_nas_srb1(nas);
                if let Err(e) = transport.send(peer, &DlMessage::Srb { srb_id: SRB1, payload }).await {
                    warn!(ran_ue_id, "Uu session-accept NAS relay failed: {e:#}");
                }
            }
        }
        return Ok(());
    }

    // UEContextReleaseCommand → send an RRC Release on SRB1, drop the context, confirm.
    if let Some((amf_ue_id, ran_ue_id, _cause)) = ngap::parse_ue_context_release_command(pdu) {
        send_ngap(conn, &ngap::ue_context_release_complete(amf_ue_id, ran_ue_id)).await?;
        // Tell the UE its RRC connection is released (RRCRelease on SRB1) before tearing
        // the context down, then the Uu-level released marker.
        if let Some(ue) = state.ues.get_mut(&ran_ue_id) {
            let txn = ue.next_txn();
            let (peer, payload) = (ue.peer, ue.srb1.protect(&rrc::rrc_release(txn)));
            let _ = transport.send(peer, &DlMessage::Srb { srb_id: SRB1, payload }).await;
        }
        match state.remove_ue(ran_ue_id) {
            Some(ctx) => {
                info!(ran_ue_id, amf_ue_id, "UE context released");
                if let Err(e) = transport.send(ctx.peer, &DlMessage::Released).await {
                    warn!(ran_ue_id, "Uu release notification failed: {e:#}");
                }
            }
            None => warn!(ran_ue_id, "release command for an unknown UE context"),
        }
        return Ok(());
    }

    // Paging → broadcast to every camped UE; each matches its own 5G-TMSI.
    if let Some(tmsi) = ngap::tmsi_from_paging(pdu) {
        info!(tmsi, peers = state.camped.len(), "paging camped UEs");
        for peer in state.camped.clone() {
            if let Err(e) = transport.send(peer, &DlMessage::Paging { tmsi }).await {
                warn!(?peer, "Uu paging send failed: {e:#}");
            }
        }
        return Ok(());
    }

    info!("unhandled NGAP PDU: {}", pdu.procedure_name());
    Ok(())
}

/// Dispatch one uplink Uu message from a UE — the RRC/PDCP decode side of the gNB.
async fn handle_uu<T: UuTransport>(
    cfg: &GnbConfig,
    conn: &ConnectedSocket,
    transport: &mut T,
    n3: &UdpSocket,
    state: &mut GnbState<T::Peer>,
    peer: T::Peer,
    msg: UlMessage,
) -> Result<()> {
    match msg {
        // SRB0 (CCCH, no PDCP): the UE opens an RRC connection.
        UlMessage::Srb { srb_id: SRB0, payload } => match rrc::parse_ul_ccch(&payload) {
            Some(rrc::UlCcch::RrcSetupRequest { ue_identity, cause }) => {
                let ran_ue_id = state.new_ue(peer);
                info!(ran_ue_id, ?peer, ue_identity, cause, "RRC connection request");
                // RRCSetup configures SRB1 (an opaque masterCellGroup over the fake Uu).
                let setup = rrc::rrc_setup(0, &[0x00]);
                if let Err(e) = transport.send(peer, &DlMessage::Srb { srb_id: SRB0, payload: setup }).await
                {
                    warn!(ran_ue_id, "Uu RRCSetup send failed: {e:#}");
                }
            }
            other => warn!(?peer, ?other, "unexpected UL-CCCH message — dropped"),
        },
        // SRB1 (DCCH, PDCP): NAS transport, the security-mode procedure, reconfiguration.
        UlMessage::Srb { srb_id: SRB1, payload } => {
            let Some(ran_ue_id) = state.by_peer.get(&peer).copied() else {
                warn!(?peer, "SRB1 message from a UE with no context — dropped");
                return Ok(());
            };
            let rrc_bytes = {
                let ue = state.ues.get_mut(&ran_ue_id).expect("context exists for a mapped peer");
                match ue.srb1.unprotect(&payload) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!(ran_ue_id, "SRB1 PDCP unprotect failed: {e}");
                        return Ok(());
                    }
                }
            };
            match rrc::parse_ul_dcch(&rrc_bytes) {
                Some(rrc::UlDcch::RrcSetupComplete { nas, .. }) => {
                    // The first uplink NAS (Registration/Service Request) → InitialUEMessage.
                    let tac = cfg.tacs.first().copied().unwrap_or([0, 0, 1]);
                    let pdu = ngap::initial_ue_message_with_nas_at(ran_ue_id, nas, &cfg.mcc, &cfg.mnc, &tac);
                    send_ngap(conn, &pdu).await?;
                    info!(ran_ue_id, "RRC setup complete (InitialUEMessage sent)");
                }
                Some(rrc::UlDcch::UlInformationTransfer { nas }) => {
                    let Some((_, amf_ue_id)) = ue_ids_for_peer(state, peer) else {
                        warn!(ran_ue_id, "uplink NAS before the UE is AMF-addressable — dropped");
                        return Ok(());
                    };
                    send_ngap(conn, &ngap::uplink_nas_transport(amf_ue_id, ran_ue_id, nas)).await?;
                }
                Some(rrc::UlDcch::SecurityModeComplete { .. }) => {
                    on_as_security_complete(conn, transport, state, ran_ue_id).await?;
                }
                Some(rrc::UlDcch::RrcReconfigurationComplete { .. }) => {
                    info!(ran_ue_id, "RRC reconfiguration complete");
                }
                other => warn!(ran_ue_id, ?other, "unhandled UL-DCCH message"),
            }
        }
        UlMessage::Srb { srb_id, .. } => warn!(?peer, srb_id, "message on an unsupported SRB — dropped"),
        UlMessage::Idle => {
            let Some((ran_ue_id, amf_ue_id)) = ue_ids_for_peer(state, peer) else {
                warn!(?peer, "idle indication from a UE with no addressable context — ignored");
                return Ok(());
            };
            info!(ran_ue_id, "UE went idle — requesting AN release (user inactivity)");
            send_ngap(
                conn,
                &ngap::ue_context_release_request(
                    amf_ue_id,
                    ran_ue_id,
                    ngap::CauseRadioNetwork::USER_INACTIVITY,
                ),
            )
            .await?;
        }
        UlMessage::Data { psi, packet } => {
            let session = state
                .by_peer
                .get(&peer)
                .and_then(|id| state.ues.get(id))
                .and_then(|ue| ue.sessions.iter().find(|s| s.psi == psi).copied());
            let Some(s) = session else {
                warn!(?peer, psi, "uplink data with no matching PDU session — dropped");
                return Ok(());
            };
            let gpdu = gtpu::encap_ul_qfi(s.upf_teid, s.qfi, &packet);
            let dst = SocketAddrV4::new(s.upf_addr, gtpu::GTPU_PORT);
            if let Err(e) = n3.send_to(&gpdu, dst).await {
                warn!(psi, %dst, "N3 uplink send failed: {e}");
            } else {
                info!(psi, qfi = s.qfi, teid = s.upf_teid, bytes = packet.len(), "Uu→N3 uplink forwarded");
            }
        }
    }
    Ok(())
}

/// `(ran_ue_id, amf_ue_id)` for a Uu peer, once the AMF has addressed the UE.
fn ue_ids_for_peer<P: Copy + Eq + std::hash::Hash>(
    state: &GnbState<P>,
    peer: P,
) -> Option<(u32, u64)> {
    let ran_ue_id = *state.by_peer.get(&peer)?;
    let amf_ue_id = state.ues.get(&ran_ue_id)?.amf_ue_id?;
    Some((ran_ue_id, amf_ue_id))
}

/// The UE confirmed AS security (SecurityModeComplete). Deliver the NAS held across the
/// procedure (the Registration Accept, now ciphered) and send the deferred Initial
/// Context Setup Response — completing the context establishment the AMF asked for.
async fn on_as_security_complete<T: UuTransport>(
    conn: &ConnectedSocket,
    transport: &mut T,
    state: &mut GnbState<T::Peer>,
    ran_ue_id: u32,
) -> Result<()> {
    let (peer, payloads, ics) = {
        let ue = state.ues.get_mut(&ran_ue_id).expect("context exists for a mapped peer");
        let held = std::mem::take(&mut ue.pending_dl_nas);
        let mut payloads = Vec::with_capacity(held.len());
        for nas in held {
            payloads.push(ue.dl_nas_srb1(nas));
        }
        (ue.peer, payloads, ue.pending_ics.take())
    };
    info!(ran_ue_id, "AS security active (SecurityModeComplete received)");
    for payload in payloads {
        if let Err(e) = transport.send(peer, &DlMessage::Srb { srb_id: SRB1, payload }).await {
            warn!(ran_ue_id, "Uu post-security NAS relay failed: {e:#}");
        }
    }
    if let Some(ics) = ics {
        let resp = if ics.admitted.is_empty() {
            ngap::initial_context_setup_response(ics.amf_ue_id, ran_ue_id)
        } else {
            ngap::initial_context_setup_response_with_sessions(ics.amf_ue_id, ran_ue_id, &ics.admitted)
        };
        send_ngap(conn, &resp).await?;
        info!(ran_ue_id, "initial context established (ICS response sent)");
    }
    Ok(())
}

/// Dispatch one N3 (GTP-U) datagram from the UPF.
async fn handle_n3<T: UuTransport>(
    transport: &mut T,
    n3: &UdpSocket,
    state: &GnbState<T::Peer>,
    datagram: &[u8],
    src: SocketAddr,
) -> Result<()> {
    match gtpu::parse(datagram) {
        Some(gtpu::N3Message::EchoRequest { sequence }) => {
            n3.send_to(&gtpu::echo_response(sequence), src).await.context("N3 echo send")?;
        }
        Some(gtpu::N3Message::GPdu { teid, qfi, payload }) => {
            let Some((ran_ue_id, psi, peer)) = state.session_by_dl_teid(teid) else {
                warn!(teid, "downlink G-PDU for an unknown DL F-TEID — dropped");
                return Ok(());
            };
            transport
                .send(peer, &DlMessage::Data { psi, packet: payload.to_vec() })
                .await
                .context("Uu downlink data send")?;
            info!(ran_ue_id, psi, qfi, bytes = payload.len(), "N3→Uu downlink forwarded");
        }
        Some(gtpu::N3Message::EndMarker { teid }) => {
            info!(teid, "GTP-U End Marker received (downlink path switched away)");
        }
        other => warn!(%src, "unhandled N3 GTP-U message {other:?}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tac_parsing() {
        assert_eq!(parse_tac("000001").unwrap(), [0, 0, 1]);
        assert_eq!(parse_tac("A0B1C2").unwrap(), [0xA0, 0xB1, 0xC2]);
        assert!(parse_tac("0001").is_err(), "too short");
        assert!(parse_tac("zzzzzz").is_err(), "not hex");
    }

    #[test]
    fn state_allocates_and_routes() {
        let mut state: GnbState<u32> = GnbState::new();
        let a = state.new_ue(10);
        let b = state.new_ue(20);
        assert_ne!(a, b, "RAN-UE-NGAP-IDs are unique");
        assert_eq!(state.by_peer[&10], a);

        // A new connection from the same peer replaces the stale context.
        let a2 = state.new_ue(10);
        assert_ne!(a2, a);
        assert!(!state.ues.contains_key(&a), "the stale context is gone");
        assert_eq!(state.camped, vec![10, 20], "camping survives context churn");

        // Session lookup by DL F-TEID finds the owner.
        let teid = state.alloc_dl_teid();
        state.ues.get_mut(&a2).unwrap().sessions.push(SessionCtx {
            psi: 1,
            qfi: 9,
            upf_teid: 0x77,
            upf_addr: Ipv4Addr::LOCALHOST,
            dl_teid: teid,
        });
        assert_eq!(state.session_by_dl_teid(teid), Some((a2, 1, 10)));
        assert_eq!(state.session_by_dl_teid(0xFFFF_FFFF), None);

        // Release keeps the peer camped (it must stay pageable).
        assert!(state.remove_ue(a2).is_some());
        assert!(!state.by_peer.contains_key(&10));
        assert!(state.camped.contains(&10));
    }
}
