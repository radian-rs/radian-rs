//! A Rust **gNB-DU stub** (design/128 Phase 3e): the counterpart to the CU's [`crate::f1`]
//! south side. It stands in for OCUDU's `odu` in CI — it terminates **F1** toward the CU
//! (F1-C over SCTP, F1-U over GTP-U) and the **Uu** toward the UE ([`crate::uu`]), bridging
//! the two so a UE registers on the core through a real F1 split without a PHY:
//!
//! - a UE's `RRCSetupRequest` on SRB0 becomes an **InitialULRRCMessageTransfer** (the DU
//!   assigns the gNB-DU-UE-F1AP-ID and a C-RNTI); further SRB1 uplink becomes **ULRRCMessageTransfer**;
//! - the CU's **DLRRCMessageTransfer** is delivered to the UE on its SRB, and teaches the DU
//!   the gNB-CU-UE-F1AP-ID for this UE;
//! - the CU's F1-U **DL USER DATA** is delivered to the UE as Uu user data; a UE's uplink Uu
//!   data is relayed to the CU as a plain F1-U G-PDU;
//! - `Idle` becomes a DU-initiated **UEContextReleaseRequest**; a CU **UEContextReleaseCommand**
//!   tears the context down (**UEContextReleaseComplete**); **Paging** is broadcast on the Uu.
//!
//! The DU is deliberately dumb: it carries RRC and PDCP opaquely (both live in the CU) and
//! keeps no security state. The F1-U TEIDs are the CU/DU-agreed [`crate::f1::f1u_teid`].

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use sctp_rs::{ConnectedSocket, NotificationOrData, SendData, SendInfo, Socket, SocketToAssociation};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::f1::{f1u_teid, split_teid};
use crate::uu::{DlMessage, UlMessage};

const F1AP_PPID: u32 = 62;
const NR_CELL_ID: u64 = 1;
const CAUSE_NORMAL_RELEASE: u8 = 10;

/// gNB-DU stub configuration (from `RADIAN_DU_*`).
#[derive(Debug, Clone)]
pub struct DuConfig {
    /// The CU's F1-C (SCTP) endpoint to connect to (`RADIAN_DU_CU_F1C`, default 127.0.0.1:38472).
    pub cu_f1c: SocketAddr,
    /// The CU's F1-U endpoint for uplink user data (`RADIAN_DU_CU_F1U`, default 127.0.0.1:2153).
    pub cu_f1u: SocketAddr,
    /// The Uu the UE camps on (`RADIAN_DU_UU_BIND`, default 127.0.0.1:4997).
    pub uu_bind: SocketAddr,
    /// This DU's own F1-U bind (`RADIAN_DU_F1U_BIND`, default 127.0.0.1:2154).
    pub f1u_bind: SocketAddr,
    /// PLMN carried in F1AP (`RADIAN_DU_MCC` / `RADIAN_DU_MNC`, default 999/70).
    pub mcc: String,
    pub mnc: String,
    /// The gNB-DU id advertised in F1 Setup (`RADIAN_DU_ID`, default 1).
    pub gnb_du_id: u64,
}

impl Default for DuConfig {
    fn default() -> Self {
        Self {
            cu_f1c: "127.0.0.1:38472".parse().unwrap(),
            cu_f1u: "127.0.0.1:2153".parse().unwrap(),
            uu_bind: "127.0.0.1:4997".parse().unwrap(),
            f1u_bind: "127.0.0.1:2154".parse().unwrap(),
            mcc: "999".into(),
            mnc: "70".into(),
            gnb_du_id: 1,
        }
    }
}

impl DuConfig {
    /// Read the configuration from `RADIAN_DU_*`, falling back to defaults.
    pub fn from_env() -> Result<Self> {
        let d = Self::default();
        let addr = |name: &str, def: SocketAddr| -> Result<SocketAddr> {
            match std::env::var(name).ok() {
                Some(v) => v.parse().with_context(|| name.to_string()),
                None => Ok(def),
            }
        };
        Ok(Self {
            cu_f1c: addr("RADIAN_DU_CU_F1C", d.cu_f1c)?,
            cu_f1u: addr("RADIAN_DU_CU_F1U", d.cu_f1u)?,
            uu_bind: addr("RADIAN_DU_UU_BIND", d.uu_bind)?,
            f1u_bind: addr("RADIAN_DU_F1U_BIND", d.f1u_bind)?,
            mcc: std::env::var("RADIAN_DU_MCC").unwrap_or(d.mcc),
            mnc: std::env::var("RADIAN_DU_MNC").unwrap_or(d.mnc),
            gnb_du_id: match std::env::var("RADIAN_DU_ID").ok() {
                Some(v) => v.parse().context("RADIAN_DU_ID")?,
                None => d.gnb_du_id,
            },
        })
    }
}

/// One UE the DU is bridging.
struct DuUe {
    du_ue_id: u32,
    /// The CU-UE-F1AP-ID, learned from the CU's first DLRRCMessageTransfer.
    cu_ue_id: Option<u32>,
    /// The UE's Uu (UDP) address.
    peer: SocketAddr,
}

/// The running gNB-DU stub: the F1-C association, the F1-U and Uu sockets, and the UEs.
struct Du {
    cfg: DuConfig,
    cu: ConnectedSocket,
    uu: UdpSocket,
    f1u: UdpSocket,
    ues: Vec<DuUe>,
    /// Every UE that ever camped — the paging "broadcast domain". A released UE keeps
    /// camping and must still be pageable, so this outlives its [`DuUe`] context.
    camped: Vec<SocketAddr>,
    next_du_ue_id: u32,
    next_c_rnti: u16,
}

/// Connect F1-C to the CU, complete F1 Setup, bind the Uu + F1-U sockets, and bridge until
/// the F1-C association drops.
pub async fn run(cfg: DuConfig) -> Result<()> {
    let sock = Socket::new_v4(SocketToAssociation::OneToOne).context("create F1-C SCTP socket")?;
    let (cu, _assoc) = sock
        .connect(cfg.cu_f1c)
        .await
        .with_context(|| format!("connect F1-C to {}", cfg.cu_f1c))?;
    send_f1ap(&cu, f1ap::f1_setup_request(0, cfg.gnb_du_id)).await?;
    loop {
        match cu.sctp_recv().await.context("F1-C recv (awaiting F1 Setup Response)")? {
            NotificationOrData::Notification(_) => continue,
            NotificationOrData::Data(d) => {
                if f1ap::decode(&d.payload).is_some_and(|pdu| f1ap::parse_f1_setup(&pdu).is_some()) {
                    break;
                }
            }
        }
    }
    let uu = UdpSocket::bind(cfg.uu_bind)
        .await
        .with_context(|| format!("bind Uu at {}", cfg.uu_bind))?;
    let f1u = UdpSocket::bind(cfg.f1u_bind)
        .await
        .with_context(|| format!("bind F1-U at {}", cfg.f1u_bind))?;
    info!(cu = %cfg.cu_f1c, uu = %cfg.uu_bind, f1u = %cfg.f1u_bind, "gNB-DU up: F1 Setup complete, Uu + F1-U bound");

    let mut du = Du {
        cfg,
        cu,
        uu,
        f1u,
        ues: Vec::new(),
        camped: Vec::new(),
        next_du_ue_id: 1,
        next_c_rnti: 0x4601,
    };
    loop {
        let ev = du.recv_event().await?;
        du.dispatch(ev).await?;
    }
}

/// A raw event from one of the DU's three interfaces.
enum DuEvent {
    Uu(SocketAddr, UlMessage),
    F1c(Vec<u8>),
    F1u(Vec<u8>),
}

impl Du {
    /// Block for the next event on the Uu, F1-C, or F1-U (skipping undecodable/notification input).
    async fn recv_event(&self) -> Result<DuEvent> {
        loop {
            let mut ub = [0u8; 4096];
            let mut fb = [0u8; 4096];
            let ev = tokio::select! {
                r = self.uu.recv_from(&mut ub) => {
                    let (n, peer) = r.context("Uu recv")?;
                    match UlMessage::decode(&ub[..n]) {
                        Some(m) => Some(DuEvent::Uu(peer, m)),
                        None => { warn!(%peer, "undecodable Uu uplink — dropped"); None }
                    }
                }
                r = self.cu.sctp_recv() => match r.context("F1-C recv")? {
                    NotificationOrData::Notification(_) => None,
                    NotificationOrData::Data(d) => {
                        if d.payload.is_empty() { bail!("the CU closed the F1-C association"); }
                        Some(DuEvent::F1c(d.payload))
                    }
                },
                r = self.f1u.recv_from(&mut fb) => {
                    let (n, _src) = r.context("F1-U recv")?;
                    Some(DuEvent::F1u(fb[..n].to_vec()))
                }
            };
            if let Some(ev) = ev {
                return Ok(ev);
            }
        }
    }

    async fn dispatch(&mut self, ev: DuEvent) -> Result<()> {
        match ev {
            DuEvent::Uu(peer, msg) => self.handle_uu(peer, msg).await,
            DuEvent::F1c(payload) => self.handle_f1ap(&payload).await,
            DuEvent::F1u(datagram) => self.handle_f1u_downlink(&datagram).await,
        }
    }

    fn ue_by_peer(&mut self, peer: SocketAddr) -> Option<&mut DuUe> {
        self.ues.iter_mut().find(|u| u.peer == peer)
    }
    fn ue_by_du_id(&mut self, du_ue_id: u32) -> Option<&mut DuUe> {
        self.ues.iter_mut().find(|u| u.du_ue_id == du_ue_id)
    }
    fn peer_by_cu_id(&self, cu_ue_id: u32) -> Option<SocketAddr> {
        self.ues.iter().find(|u| u.cu_ue_id == Some(cu_ue_id)).map(|u| u.peer)
    }

    /// A UE → gNB uplink Uu message: translate to F1 toward the CU.
    async fn handle_uu(&mut self, peer: SocketAddr, msg: UlMessage) -> Result<()> {
        match msg {
            // SRB0 RRCSetupRequest — a UE opening an RRC connection (a fresh DU context).
            UlMessage::Srb { srb_id: 0, payload } => {
                self.ues.retain(|u| u.peer != peer); // a re-camp replaces any stale context
                let du_ue_id = self.next_du_ue_id;
                self.next_du_ue_id += 1;
                let c_rnti = self.next_c_rnti;
                self.next_c_rnti = self.next_c_rnti.wrapping_add(1).max(0x4601);
                self.ues.push(DuUe { du_ue_id, cu_ue_id: None, peer });
                if !self.camped.contains(&peer) {
                    self.camped.push(peer);
                }
                let msg = f1ap::initial_ul_rrc_message_transfer(
                    du_ue_id, &self.cfg.mcc, &self.cfg.mnc, NR_CELL_ID, c_rnti, payload,
                );
                send_f1ap(&self.cu, msg).await?;
                info!(du_ue_id, c_rnti, %peer, "Initial UL RRC (new UE camped)");
            }
            // SRB1 uplink RRC (PDCP-wrapped NAS/security) → UL RRC Message Transfer.
            UlMessage::Srb { srb_id, payload } => {
                let Some(ue) = self.ue_by_peer(peer) else {
                    warn!(%peer, "SRB uplink from an unknown UE — dropped");
                    return Ok(());
                };
                let Some(cu_ue_id) = ue.cu_ue_id else {
                    warn!(%peer, "SRB1 uplink before the CU addressed the UE — dropped");
                    return Ok(());
                };
                let (du_ue_id, cu_ue_id) = (ue.du_ue_id, cu_ue_id);
                send_f1ap(&self.cu, f1ap::ul_rrc_message_transfer(cu_ue_id, du_ue_id, srb_id, payload)).await?;
            }
            // The UE went radio-idle → a DU-initiated release request.
            UlMessage::Idle => {
                let Some(ue) = self.ue_by_peer(peer) else {
                    warn!(%peer, "idle from an unknown UE — dropped");
                    return Ok(());
                };
                let Some(cu_ue_id) = ue.cu_ue_id else {
                    warn!(%peer, "idle before the UE has a CU context — dropped");
                    return Ok(());
                };
                let du_ue_id = ue.du_ue_id;
                send_f1ap(&self.cu, f1ap::ue_context_release_request(cu_ue_id, du_ue_id, CAUSE_NORMAL_RELEASE)).await?;
            }
            // Uplink user data — relay the (ciphered) PDCP PDU to the CU on the DRB's F1-U tunnel.
            UlMessage::Data { psi, packet } => {
                let Some(ue) = self.ue_by_peer(peer) else {
                    warn!(%peer, "uplink data from an unknown UE — dropped");
                    return Ok(());
                };
                let Some(cu_ue_id) = ue.cu_ue_id else {
                    warn!(%peer, "uplink data before the UE has a CU context — dropped");
                    return Ok(());
                };
                let gpdu = gtpu::encap(f1u_teid(cu_ue_id, psi), &packet);
                self.f1u.send_to(&gpdu, self.cfg.cu_f1u).await.context("F1-U uplink send")?;
            }
        }
        Ok(())
    }

    /// A CU → DU F1AP PDU: deliver it toward the UE and/or answer the procedure.
    async fn handle_f1ap(&mut self, payload: &[u8]) -> Result<()> {
        let Some(pdu) = f1ap::decode(payload) else {
            warn!(bytes = payload.len(), "undecodable F1AP PDU from the CU — dropped");
            return Ok(());
        };
        // DL RRC Message Transfer → deliver on the UE's SRB, learning the CU-UE-F1AP-ID.
        if let Some(t) = f1ap::parse_dl_rrc(&pdu) {
            let Some(ue) = self.ue_by_du_id(t.gnb_du_ue_id) else {
                warn!(du_ue_id = t.gnb_du_ue_id, "DL RRC for an unknown DU context — dropped");
                return Ok(());
            };
            ue.cu_ue_id = Some(t.gnb_cu_ue_id);
            let peer = ue.peer;
            self.send_uu(peer, &DlMessage::Srb { srb_id: t.srb_id, payload: t.rrc }).await?;
            return Ok(());
        }
        // UE Context Setup → admit the context; answer so the CU's F1-U tunnel is "up".
        if let Some((cu_ue_id, rrc)) = f1ap::parse_ue_context_setup_request(&pdu) {
            let Some(peer) = self.peer_by_cu_id(cu_ue_id) else {
                warn!(cu_ue_id, "UE Context Setup for an unknown CU context — dropped");
                return Ok(());
            };
            let du_ue_id = self.ues.iter().find(|u| u.peer == peer).unwrap().du_ue_id;
            if !rrc.is_empty() {
                self.send_uu(peer, &DlMessage::Srb { srb_id: 1, payload: rrc }).await?;
            }
            send_f1ap(&self.cu, f1ap::ue_context_setup_response(cu_ue_id, du_ue_id, Vec::new())).await?;
            info!(cu_ue_id, du_ue_id, "UE Context Setup — DRB admitted");
            return Ok(());
        }
        // UE Context Release → deliver any RRCRelease, mark the UE released, confirm.
        if let Some((cu_ue_id, du_ue_id, _cause, rrc)) = f1ap::parse_ue_context_release_command(&pdu) {
            if let Some(peer) = self.peer_by_cu_id(cu_ue_id) {
                if let Some(rrc) = rrc {
                    self.send_uu(peer, &DlMessage::Srb { srb_id: 1, payload: rrc }).await?;
                }
                self.send_uu(peer, &DlMessage::Released).await?;
            }
            send_f1ap(&self.cu, f1ap::ue_context_release_complete(cu_ue_id, du_ue_id)).await?;
            self.ues.retain(|u| u.cu_ue_id != Some(cu_ue_id));
            info!(cu_ue_id, du_ue_id, "UE Context released");
            return Ok(());
        }
        // Paging → broadcast to every camped UE (each matches its own 5G-TMSI). This uses
        // `camped`, not the live contexts: the UE being paged is precisely the one whose
        // context was released when it went idle. A send to a departed UE is ignored.
        if let Some(tmsi) = f1ap::parse_paging_5g_s_tmsi(&pdu) {
            for peer in self.camped.clone() {
                if let Err(e) = self.send_uu(peer, &DlMessage::Paging { tmsi: tmsi as u32 }).await {
                    warn!(%peer, "Uu paging send failed: {e:#}");
                }
            }
            return Ok(());
        }
        Ok(())
    }

    /// A CU → DU F1-U datagram (DL USER DATA): deliver its PDCP PDU to the UE on the Uu.
    async fn handle_f1u_downlink(&mut self, datagram: &[u8]) -> Result<()> {
        let Some((teid, _frame, pdcp)) = gtpu::parse_nr_ran_container(datagram) else {
            warn!("F1-U downlink is not an NR RAN Container G-PDU — dropped");
            return Ok(());
        };
        let (cu_ue_id, psi) = split_teid(teid);
        let pdcp = pdcp.to_vec();
        let Some(peer) = self.peer_by_cu_id(cu_ue_id) else {
            warn!(cu_ue_id, "F1-U downlink for an unknown UE — dropped");
            return Ok(());
        };
        self.send_uu(peer, &DlMessage::Data { psi, packet: pdcp }).await
    }

    /// Send one downlink Uu message to a UE.
    async fn send_uu(&self, peer: SocketAddr, msg: &DlMessage) -> Result<()> {
        self.uu.send_to(&msg.encode(), peer).await.context("Uu downlink send")?;
        Ok(())
    }
}

/// Send one F1AP PDU on the F1-C association.
async fn send_f1ap(cu: &ConnectedSocket, pdu: Vec<u8>) -> Result<()> {
    cu.sctp_send(SendData {
        payload: pdu,
        snd_info: Some(SendInfo { ppid: F1AP_PPID, ..Default::default() }),
    })
    .await
    .context("F1-C sctp_send")
}
