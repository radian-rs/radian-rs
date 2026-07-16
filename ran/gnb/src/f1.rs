//! The CU's **F1 south side** (design/128 Phase 3e): a [`UuTransport`] that reaches UEs not
//! over the fake Uu but over a real **F1** interface to a gNB-DU — F1-C (F1AP over SCTP) for
//! control and F1-U (GTP-U + NR-U) for user data. The CU core (`serve`/`handle_*`) is
//! unchanged; this adapter translates its per-UE Uu message model to and from F1:
//!
//! | Uu ([`crate::uu`])            | F1 (this adapter)                                     |
//! |------------------------------|-------------------------------------------------------|
//! | `Srb{0}` uplink              | InitialULRRCMessageTransfer (a new UE appears)        |
//! | `Srb{1}` uplink              | ULRRCMessageTransfer                                  |
//! | `Srb{_}` downlink            | DLRRCMessageTransfer                                  |
//! | `Data` downlink              | F1-U **DL USER DATA** (NR-U SN + the ciphered PDCP PDU) |
//! | `Data` uplink                | a plain F1-U G-PDU (the ciphered PDCP PDU as T-PDU)    |
//! | `Idle` uplink               | a DU-sent **UEContextReleaseRequest**                 |
//! | `Paging` downlink            | F1AP Paging                                           |
//! | `Released` downlink          | UEContextReleaseCommand                               |
//!
//! The F1-U tunnel TEID for each DRB is derived from the CU-UE-F1AP-ID and the PDU-session id
//! ([`f1u_teid`]) so both ends agree without a TEID exchange; the UEContextSetup that would
//! carry it in real F1 is still sent (for the DU to admit the context) but is not load-bearing
//! here. The gNB-DU association is accepted once, before the serve loop, in [`F1Transport::start`]
//! (SCTP accept is not cancellation-safe, so it must not run inside a `select!`).

use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use sctp_rs::{ConnectedSocket, Listener, NotificationOrData, SendData, SendInfo, Socket, SocketToAssociation};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::uu::{DlMessage, UlMessage};
use crate::UuTransport;

/// SCTP Payload Protocol Identifier for F1AP (TS 38.472 §7).
const F1AP_PPID: u32 = 62;
/// The single cell this CU/DU serves (NR Cell Identity); carried in F1AP, not cross-checked.
const NR_CELL_ID: u64 = 1;
/// F1AP radio-network cause "normal release" — the cause of a DU-initiated release request.
const CAUSE_NORMAL_RELEASE: u8 = 10;

/// The F1-U tunnel TEID for a UE's DRB: the CU-UE-F1AP-ID in the high bits, the PDU-session
/// id in the low octet, so the CU and DU agree on it without exchanging F-TEIDs.
pub fn f1u_teid(cu_ue_id: u32, psi: u8) -> u32 {
    (cu_ue_id << 8) | psi as u32
}

/// Recover `(cu_ue_id, psi)` from an F1-U TEID built by [`f1u_teid`].
pub fn split_teid(teid: u32) -> (u32, u8) {
    (teid >> 8, (teid & 0xFF) as u8)
}

/// One UE's F1 state on the CU side.
struct F1Ue {
    du_ue_id: u32,
    /// The DU has admitted the UE context (UEContextSetup sent) — done lazily on first data.
    ctx_setup: bool,
    /// Per-DRB (keyed by PDU-session id) downlink NR-U sequence number.
    dl_sn: HashMap<u8, u32>,
}

/// The CU-side F1 transport: an F1-C SCTP association to one gNB-DU plus the F1-U GTP-U socket.
pub struct F1Transport {
    mcc: String,
    mnc: String,
    /// The F1-C listener; the DU connects here and sends F1 Setup.
    listener: Listener,
    /// The accepted gNB-DU association (set in [`F1Transport::start`]).
    du: Option<ConnectedSocket>,
    /// The F1-U (GTP-U) socket toward the DU.
    f1u: UdpSocket,
    /// Where downlink F1-U goes — configured, then refined to the DU's learned source.
    du_f1u: SocketAddr,
    ues: HashMap<u32, F1Ue>,
    next_cu_ue_id: u32,
}

impl F1Transport {
    /// Bind the F1-C SCTP listener and the F1-U socket. `du_f1u` is the DU's F1-U endpoint
    /// (a fallback until learned from the DU's first uplink datagram).
    pub async fn bind(
        f1c_bind: SocketAddr,
        f1u_bind: SocketAddr,
        du_f1u: SocketAddr,
        mcc: String,
        mnc: String,
    ) -> Result<Self> {
        let socket = Socket::new_v4(SocketToAssociation::OneToOne).context("create F1-C SCTP socket")?;
        socket.bind(f1c_bind).with_context(|| format!("bind F1-C at {f1c_bind}"))?;
        let listener = socket.listen(16).context("listen F1-C SCTP")?;
        let f1u = UdpSocket::bind(f1u_bind)
            .await
            .with_context(|| format!("bind F1-U at {f1u_bind}"))?;
        info!(%f1c_bind, %f1u_bind, "F1 south side up: F1-C listening, F1-U bound");
        Ok(Self {
            mcc,
            mnc,
            listener,
            du: None,
            f1u,
            du_f1u,
            ues: HashMap::new(),
            next_cu_ue_id: 1,
        })
    }

    /// Send one F1AP PDU to the gNB-DU.
    async fn send_f1ap(&self, pdu: Vec<u8>) -> Result<()> {
        let du = self.du.as_ref().context("no gNB-DU association")?;
        du.sctp_send(SendData {
            payload: pdu,
            snd_info: Some(SendInfo { ppid: F1AP_PPID, ..Default::default() }),
        })
        .await
        .context("F1-C sctp_send")
    }

    /// Handle one F1AP PDU from the DU; `Some` when it maps to an uplink Uu message the CU
    /// core should see, `None` when it is an F1-internal message consumed here.
    async fn handle_f1ap(&mut self, payload: &[u8]) -> Result<Option<(u32, UlMessage)>> {
        let Some(pdu) = f1ap::decode(payload) else {
            warn!(bytes = payload.len(), "undecodable F1AP PDU — dropped");
            return Ok(None);
        };
        // F1 Setup Request → respond, completing the DU's bring-up.
        if let Some((txn, _)) = f1ap::parse_f1_setup(&pdu) {
            self.send_f1ap(f1ap::f1_setup_response(txn)).await?;
            info!("F1 Setup complete (gNB-DU associated)");
            return Ok(None);
        }
        // Initial UL RRC (a new UE camped on the DU) → allocate a CU-UE-F1AP-ID.
        if let Some((du_ue_id, c_rnti, rrc)) = f1ap::parse_initial_ul_rrc(&pdu) {
            let cu_ue_id = self.next_cu_ue_id;
            self.next_cu_ue_id += 1;
            self.ues.insert(cu_ue_id, F1Ue { du_ue_id, ctx_setup: false, dl_sn: HashMap::new() });
            info!(cu_ue_id, du_ue_id, c_rnti, "F1 UE context created (Initial UL RRC)");
            return Ok(Some((cu_ue_id, UlMessage::Srb { srb_id: 0, payload: rrc })));
        }
        if let Some(t) = f1ap::parse_ul_rrc(&pdu) {
            return Ok(Some((t.gnb_cu_ue_id, UlMessage::Srb { srb_id: t.srb_id, payload: t.rrc })));
        }
        // DU-initiated release request (radio inactivity) → the CU's idle trigger.
        if let Some((cu_ue_id, _du, _cause)) = f1ap::parse_ue_context_release_request(&pdu) {
            info!(cu_ue_id, "F1 UEContextReleaseRequest (DU reports the UE idle)");
            return Ok(Some((cu_ue_id, UlMessage::Idle)));
        }
        if let Some((cu, du, _cg)) = f1ap::parse_ue_context_setup_response(&pdu) {
            info!(cu_ue_id = cu, du_ue_id = du, "F1 UEContextSetupResponse");
            return Ok(None);
        }
        if let Some((cu, du)) = f1ap::parse_ue_context_release_complete(&pdu) {
            info!(cu_ue_id = cu, du_ue_id = du, "F1 UEContextReleaseComplete");
            return Ok(None);
        }
        info!("unhandled F1AP PDU from the DU — ignored");
        Ok(None)
    }

    /// Handle one F1-U datagram from the DU: an uplink G-PDU carrying a UE's ciphered PDCP PDU.
    fn handle_f1u(&self, datagram: &[u8]) -> Option<(u32, UlMessage)> {
        let (teid, pdcp) = gtpu::decap(datagram)?;
        let (cu_ue_id, psi) = split_teid(teid);
        Some((cu_ue_id, UlMessage::Data { psi, packet: pdcp.to_vec() }))
    }
}

impl UuTransport for F1Transport {
    type Peer = u32; // gNB-CU-UE-F1AP-ID

    async fn start(&mut self) -> Result<()> {
        let (du, peer) = self.listener.accept().await.context("accept the gNB-DU F1-C association")?;
        info!(%peer, "gNB-DU associated on F1-C");
        self.du = Some(du);
        Ok(())
    }

    async fn recv(&mut self) -> Result<(u32, UlMessage)> {
        loop {
            // Receive either an F1AP PDU (F1-C) or an F1-U datagram — whichever is ready.
            let mut ubuf = [0u8; 4096];
            enum Rx {
                F1c(Vec<u8>),
                F1u(usize, SocketAddr),
            }
            let rx = {
                let du = self.du.as_ref().context("gNB-DU not associated")?;
                tokio::select! {
                    got = du.sctp_recv() => match got.context("F1-C recv")? {
                        NotificationOrData::Notification(_) => continue,
                        NotificationOrData::Data(d) => {
                            if d.payload.is_empty() {
                                bail!("the gNB-DU closed the F1-C association");
                            }
                            Rx::F1c(d.payload)
                        }
                    },
                    got = self.f1u.recv_from(&mut ubuf) => {
                        let (n, src) = got.context("F1-U recv")?;
                        Rx::F1u(n, src)
                    }
                }
            };
            match rx {
                Rx::F1c(payload) => {
                    if let Some(msg) = self.handle_f1ap(&payload).await? {
                        return Ok(msg);
                    }
                }
                Rx::F1u(n, src) => {
                    self.du_f1u = src; // learn the DU's F1-U source for downlink
                    if let Some(msg) = self.handle_f1u(&ubuf[..n]) {
                        return Ok(msg);
                    }
                }
            }
        }
    }

    async fn send(&mut self, peer: u32, msg: &DlMessage) -> Result<()> {
        // Paging is cell-level in F1 and carries its own identity — it needs no UE context,
        // and must still reach a UE whose context the CU already released (an idle UE is
        // exactly the one being paged).
        if let DlMessage::Paging { tmsi } = msg {
            let p = f1ap::paging(&self.mcc, &self.mnc, NR_CELL_ID, *tmsi as u64, (*tmsi % 1024) as u16);
            return self.send_f1ap(p).await;
        }
        let Some(ue) = self.ues.get(&peer) else {
            warn!(cu_ue_id = peer, ?msg, "downlink for an unknown F1 UE context — dropped");
            return Ok(());
        };
        let du_ue_id = ue.du_ue_id;
        match msg {
            // RRC (SRB0/SRB1) rides down in a DL RRC Message Transfer.
            DlMessage::Srb { srb_id, payload } => {
                self.send_f1ap(f1ap::dl_rrc_message_transfer(peer, du_ue_id, *srb_id, payload.clone()))
                    .await?;
            }
            // User plane: admit the DU context on first use, then send an NR-U DL USER DATA
            // frame carrying the ciphered PDCP PDU on the DRB's F1-U tunnel.
            DlMessage::Data { psi, packet } => {
                if !ue.ctx_setup {
                    let req = f1ap::ue_context_setup_request(peer, &self.mcc, &self.mnc, NR_CELL_ID, Vec::new());
                    self.send_f1ap(req).await?;
                    self.ues.get_mut(&peer).unwrap().ctx_setup = true;
                }
                let sn = {
                    let dl = self.ues.get_mut(&peer).unwrap();
                    let sn = dl.dl_sn.entry(*psi).or_insert(0);
                    let cur = *sn;
                    *sn = sn.wrapping_add(1) & 0xFF_FFFF; // 24-bit NR-U SN
                    cur
                };
                let gpdu = gtpu::encap_f1u_dl_user_data(f1u_teid(peer, *psi), sn, packet);
                let dst = self.du_f1u;
                self.f1u.send_to(&gpdu, dst).await.context("F1-U downlink send")?;
            }
            // A page — cell-level in F1 (the tmsi rides in the paging identity).
            DlMessage::Paging { tmsi } => {
                let p = f1ap::paging(&self.mcc, &self.mnc, NR_CELL_ID, *tmsi as u64, (*tmsi % 1024) as u16);
                self.send_f1ap(p).await?;
            }
            // Release: command the DU to release the context, then forget it.
            DlMessage::Released => {
                self.send_f1ap(f1ap::ue_context_release_command(peer, du_ue_id, CAUSE_NORMAL_RELEASE, None))
                    .await?;
                self.ues.remove(&peer);
            }
        }
        Ok(())
    }
}
