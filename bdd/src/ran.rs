//! Scripted gNB + UE (design/116 Tier B): the test process speaks **real NGAP over
//! SCTP** to the live AMF and real NAS through it, built from radian's own crates —
//! `sctp-rs` (the same SCTP the AMF serves), `ngap` builders/parsers, the `nas` security
//! context, and the `aka` USIM-side crypto with the demo subscriber's TS 35.208 key.
//!
//! This tier needs no external simulator binary, so it runs everywhere the core builds;
//! it complements (never replaces) the `@sim` free-ran-ue tier, which keeps the
//! wire-compat role — a symmetric encode/decode bug is invisible to a scripted peer.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use pdcp::{PdcpDrb, PdcpSrb, Role};
use sctp_rs::{ConnectedSocket, NotificationOrData, SendData, SendInfo, Socket, SocketToAssociation};
use tokio::net::UdpSocket;

/// The Uu message types, re-exported so the step code addresses them as
/// `ran::UlMessage` / `ran::DlMessage` alongside the UE link.
pub use radian_gnb::uu::{DlMessage, UlMessage};

const NGAP_PPID: u32 = 60;
/// How long to wait for the AMF's next NGAP message before declaring the flow stuck.
const RECV_TIMEOUT: Duration = Duration::from_secs(10);

// ── UE ↔ standalone gNB link (design/128 Phase 0 `@gnb` tier) ─────────────────────────────

/// A UE's fake-Uu link to the **standalone `radian-gnb`**: one [`UlMessage`] /
/// [`DlMessage`] per UDP datagram (design/128 P0). Unlike [`ScriptedGnb`], the
/// test does not play the gNB here — the real gNB binary terminates N2/N3 and this
/// is only the radio link a UE camps on. The NAS/AKA logic stays in [`ScriptedUe`].
pub struct GnbUeLink {
    sock: UdpSocket,
}

impl std::fmt::Debug for GnbUeLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GnbUeLink")
    }
}

impl GnbUeLink {
    /// Open a UDP link to the gNB's Uu endpoint (an ephemeral local port — the
    /// gNB keys UE context off this source address, so one link is one UE).
    pub async fn connect(gnb_uu: SocketAddr) -> Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0").await.context("bind UE Uu socket")?;
        sock.connect(gnb_uu).await.context("connect to gNB Uu")?;
        Ok(Self { sock })
    }

    /// Send one uplink Uu message to the gNB.
    pub async fn send(&self, msg: &UlMessage) -> Result<()> {
        self.sock.send(&msg.encode()).await.context("Uu send")?;
        Ok(())
    }

    /// Receive the next downlink Uu message, bounded by [`RECV_TIMEOUT`].
    pub async fn recv(&self) -> Result<DlMessage> {
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(RECV_TIMEOUT, self.sock.recv(&mut buf))
            .await
            .map_err(|_| anyhow!("timed out waiting for a downlink Uu message from the gNB"))?
            .context("Uu recv")?;
        DlMessage::decode(&buf[..n]).ok_or_else(|| anyhow!("undecodable downlink Uu datagram"))
    }

    /// Drain downlink messages up to `secs`, returning the first **user-plane
    /// Data** packet `(psi, packet)` — other messages are skipped. `None` on
    /// timeout. Used for the datapath echo, where the reply may take a retry.
    pub async fn recv_data(&self, secs: u64) -> Result<Option<(u8, Vec<u8>)>> {
        let mut buf = vec![0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match tokio::time::timeout(remaining, self.sock.recv(&mut buf)).await {
                Err(_) => return Ok(None),
                Ok(res) => {
                    let n = res.context("Uu recv")?;
                    if let Some(DlMessage::Data { psi, packet }) = DlMessage::decode(&buf[..n]) {
                        return Ok(Some((psi, packet)));
                    }
                }
            }
        }
    }
}

// ── UE running real RRC over PDCP (design/128 Phase 1) ────────────────────────────────────

/// A UE speaking **real RRC over PDCP** to the standalone gNB (design/128 Phase 1). It
/// owns the Uu link, the [`ScriptedUe`]'s NAS/USIM state (5G-AKA, NAS security), and the
/// SRB1 PDCP entity. Steps drive it to open an RRC connection, relay NAS inside RRC
/// InformationTransfers, and run the AS security-mode procedure that turns on PDCP
/// integrity + ciphering with keys derived from the same K_gNB the AMF handed the gNB.
pub struct UeRrc {
    link: GnbUeLink,
    /// The NAS/USIM side; public so steps drive NAS crypto directly.
    pub ue: ScriptedUe,
    srb1: PdcpSrb,
    rrc_txn: u8,
    /// The data radio bearer, established when a PDU session comes up (SDAP over a
    /// ciphered PDCP DRB — design/128 Phase 2). `None` until then.
    drb: Option<PdcpDrb>,
    /// The QFI the UE marks its uplink user-plane packets with.
    drb_qfi: u8,
}

impl std::fmt::Debug for UeRrc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UeRrc")
    }
}

impl UeRrc {
    /// Camp on the gNB's Uu endpoint as the demo subscriber.
    pub async fn camp(gnb_uu: SocketAddr) -> Result<Self> {
        Ok(Self {
            link: GnbUeLink::connect(gnb_uu).await?,
            ue: ScriptedUe::demo(),
            srb1: PdcpSrb::new(Role::Ue, 1),
            rrc_txn: 0,
            drb: None,
            drb_qfi: 0,
        })
    }

    /// Establish the DRB for a PDU session: a PDCP DRB (id = `psi`) ciphered with the
    /// user-plane key derived from K_gNB, carrying QoS flow `qfi`. Called once the UE
    /// reads its PDU session accept.
    pub fn establish_drb(&mut self, psi: u8, qfi: u8) -> Result<()> {
        let kgnb = self.ue.kgnb.context("no K_gNB — register first")?;
        let mut drb = PdcpDrb::new(Role::Ue, psi.max(1));
        drb.activate_ciphering(aka::up_keys(&kgnb, 2, 2).kup_enc, 2);
        self.drb = Some(drb);
        self.drb_qfi = qfi;
        Ok(())
    }

    fn next_txn(&mut self) -> u8 {
        let t = self.rrc_txn;
        self.rrc_txn = (self.rrc_txn + 1) & 0x3;
        t
    }

    /// Open the RRC connection carrying the initial NAS: RRCSetupRequest (SRB0) → await
    /// RRCSetup (SRB0) → RRCSetupComplete with `nas` (SRB1, before AS security).
    pub async fn rrc_connect(&mut self, nas: Vec<u8>) -> Result<()> {
        let req = rrc::rrc_setup_request(
            0x1234_5678 & ((1 << 39) - 1),
            rrc::establishment_cause::MO_SIGNALLING,
        );
        self.link.send(&UlMessage::Srb { srb_id: 0, payload: req }).await?;
        let setup = self.recv_srb(0).await?;
        match rrc::parse_dl_ccch(&setup) {
            Some(rrc::DlCcch::RrcSetup { .. }) => {}
            other => bail!("expected an RRCSetup on SRB0, got {other:?}"),
        }
        let txn = self.next_txn();
        let complete = self.srb1.protect(&rrc::rrc_setup_complete(txn, 1, nas));
        self.link.send(&UlMessage::Srb { srb_id: 1, payload: complete }).await
    }

    /// Send an uplink NAS message in an RRC ULInformationTransfer on SRB1.
    pub async fn send_nas(&mut self, nas: Vec<u8>) -> Result<()> {
        let pdu = self.srb1.protect(&rrc::ul_information_transfer(nas));
        self.link.send(&UlMessage::Srb { srb_id: 1, payload: pdu }).await
    }

    /// Receive a downlink NAS message: SRB1 → PDCP-unprotect → RRC DLInformationTransfer.
    pub async fn recv_nas(&mut self) -> Result<Vec<u8>> {
        let rrc_bytes = self.recv_srb1_rrc().await?;
        match rrc::parse_dl_dcch(&rrc_bytes) {
            Some(rrc::DlDcch::DlInformationTransfer { nas, .. }) => Ok(nas),
            other => bail!("expected a DLInformationTransfer, got {other:?}"),
        }
    }

    /// Pre-activate SRB1 AS integrity once K_gNB is known (after NAS security) — so the
    /// AS SecurityModeCommand, which arrives integrity-protected, verifies on receipt.
    pub fn arm_as_security(&mut self) -> Result<()> {
        let kgnb = self.ue.kgnb.context("no K_gNB — complete NAS security first")?;
        self.srb1.activate_integrity(aka::rrc_keys(&kgnb, 2, 2).krrc_int, 2);
        Ok(())
    }

    /// Run the AS security-mode procedure: verify + read the RRC SecurityModeCommand
    /// (integrity active), activate ciphering, and send SecurityModeComplete (integrity +
    /// ciphered). Returns the `(ciphering, integrity)` algorithms the gNB selected.
    pub async fn complete_as_security(&mut self) -> Result<(u8, u8)> {
        let rrc_bytes = self.recv_srb1_rrc().await?;
        let (txn, nea, nia) = match rrc::parse_dl_dcch(&rrc_bytes) {
            Some(rrc::DlDcch::SecurityModeCommand { transaction_id, ciphering, integrity }) => {
                (transaction_id, ciphering, integrity)
            }
            other => bail!("expected a SecurityModeCommand, got {other:?}"),
        };
        let kgnb = self.ue.kgnb.context("no K_gNB")?;
        self.srb1.activate_ciphering(aka::rrc_keys(&kgnb, nea, nia).krrc_enc, nea);
        let complete = self.srb1.protect(&rrc::security_mode_complete(txn));
        self.link.send(&UlMessage::Srb { srb_id: 1, payload: complete }).await?;
        Ok((nea, nia))
    }

    /// Send an uplink user-plane IP packet on `psi`: add the SDAP header (QFI) and cipher
    /// it on the DRB, then send it over the Uu.
    pub async fn send_data(&mut self, psi: u8, packet: Vec<u8>) -> Result<()> {
        let qfi = self.drb_qfi;
        let drb = self.drb.as_mut().context("no DRB established — set up a PDU session first")?;
        let pdu = drb.protect(&sdap::encap_ul(qfi, &packet));
        self.link.send(&UlMessage::Data { psi, packet: pdu }).await
    }

    /// Drain downlink messages up to `secs`, returning the first user-plane packet — the
    /// DRB PDU deciphered and the SDAP header stripped to the inner IP `(psi, ip)`.
    pub async fn recv_data(&mut self, secs: u64) -> Result<Option<(u8, Vec<u8>)>> {
        let Some((psi, pdu)) = self.link.recv_data(secs).await? else {
            return Ok(None);
        };
        let drb = self.drb.as_mut().context("no DRB established")?;
        let sdap_pdu = drb.unprotect(&pdu).map_err(|e| anyhow!("DRB PDCP unprotect failed: {e}"))?;
        let (_hdr, ip) = sdap::decap_dl(&sdap_pdu).context("empty SDAP PDU on the DRB")?;
        Ok(Some((psi, ip.to_vec())))
    }

    /// Announce the UE went radio-idle (drives the gNB's AN release).
    pub async fn go_idle(&self) -> Result<()> {
        self.link.send(&UlMessage::Idle).await
    }

    /// Await the gNB's RRC release: it sends an RRCRelease on SRB1 then the Uu `Released`
    /// marker. Consumes the RRCRelease, returns on `Released`.
    pub async fn await_release(&mut self) -> Result<()> {
        loop {
            match self.link.recv().await? {
                DlMessage::Released => return Ok(()),
                DlMessage::Srb { srb_id: 1, payload } => {
                    let _ = self.srb1.unprotect(&payload); // the (ciphered) RRCRelease
                }
                other => bail!("expected RRCRelease/Released, got {other:?}"),
            }
        }
    }

    /// Receive the next paging message, returning the paged 5G-TMSI.
    pub async fn recv_paging(&self) -> Result<u32> {
        match self.link.recv().await? {
            DlMessage::Paging { tmsi } => Ok(tmsi),
            other => bail!("expected a Paging, got {other:?}"),
        }
    }

    async fn recv_srb(&self, srb_id: u8) -> Result<Vec<u8>> {
        match self.link.recv().await? {
            DlMessage::Srb { srb_id: got, payload } if got == srb_id => Ok(payload),
            other => bail!("expected an SRB{srb_id} message, got {other:?}"),
        }
    }

    async fn recv_srb1_rrc(&mut self) -> Result<Vec<u8>> {
        let payload = self.recv_srb(1).await?;
        self.srb1.unprotect(&payload).map_err(|e| anyhow!("SRB1 PDCP unprotect failed: {e}"))
    }
}

// ── scripted gNB ────────────────────────────────────────────────────────────────────────

/// A gNB played by the test process: one SCTP association to the AMF's N2, sending and
/// receiving APER-encoded NGAP PDUs.
pub struct ScriptedGnb {
    conn: ConnectedSocket,
}

impl std::fmt::Debug for ScriptedGnb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScriptedGnb")
    }
}

impl ScriptedGnb {
    /// Open the SCTP association to the AMF's N2 endpoint.
    pub async fn connect(amf: SocketAddr) -> Result<Self> {
        let socket = Socket::new_v4(SocketToAssociation::OneToOne).context("create SCTP socket")?;
        let (conn, _assoc) = socket.connect(amf).await.context("connect N2 SCTP")?;
        Ok(Self { conn })
    }

    /// Run NG Setup: send the request (gNB id, PLMN, supported TAs) and require the
    /// AMF's NGSetupResponse.
    pub async fn ng_setup(&self, gnb_id: u32, mcc: &str, mnc: &str, tacs: &[[u8; 3]]) -> Result<()> {
        self.send(&ngap::ng_setup_request(gnb_id, mcc, mnc, tacs)).await?;
        let pdu = self.recv().await?;
        match &pdu {
            ngap::NGAP_PDU::SuccessfulOutcome(o)
                if matches!(o.value, ngap::SuccessfulOutcomeValue::Id_NGSetup(_)) =>
            {
                Ok(())
            }
            other => bail!("expected NGSetupResponse, got {other}"),
        }
    }

    /// APER-encode and send one NGAP PDU with the NGAP PPID.
    pub async fn send(&self, pdu: &ngap::NGAP_PDU) -> Result<()> {
        let payload = pdu.encode().map_err(|e| anyhow!("NGAP encode failed: {e:?}"))?;
        self.conn
            .sctp_send(SendData {
                payload,
                snd_info: Some(SendInfo { ppid: NGAP_PPID, ..Default::default() }),
            })
            .await
            .context("sctp_send")
    }

    /// Receive the next NGAP PDU (skipping SCTP notifications), bounded by
    /// [`RECV_TIMEOUT`] so a silent AMF fails the step instead of hanging the run.
    pub async fn recv(&self) -> Result<ngap::NGAP_PDU> {
        tokio::time::timeout(RECV_TIMEOUT, async {
            loop {
                match self.conn.sctp_recv().await.context("sctp_recv")? {
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
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for an NGAP message from the AMF"))?
    }

    /// Receive, requiring a DownlinkNASTransport: `(AMF-UE-NGAP-ID, raw NAS PDU)`.
    pub async fn recv_downlink_nas(&self) -> Result<(u64, Vec<u8>)> {
        let pdu = self.recv().await?;
        downlink_nas(&pdu).ok_or_else(|| anyhow!("expected DownlinkNASTransport, got {pdu}"))
    }
}

/// Extract `(AMF-UE-NGAP-ID, NAS PDU)` from a DownlinkNASTransport.
pub fn downlink_nas(pdu: &ngap::NGAP_PDU) -> Option<(u64, Vec<u8>)> {
    let ngap::NGAP_PDU::InitiatingMessage(m) = pdu else {
        return None;
    };
    let ngap::InitiatingMessageValue::Id_DownlinkNASTransport(msg) = &m.value else {
        return None;
    };
    let (mut amf_ue_id, mut nas) = (None, None);
    for ie in &msg.protocol_i_es.0 {
        match &ie.value {
            ngap::DownlinkNASTransportProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(v) => {
                amf_ue_id = Some(v.0)
            }
            ngap::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(v) => {
                nas = Some(v.0.clone())
            }
            _ => {}
        }
    }
    Some((amf_ue_id?, nas?))
}

// ── scripted UE ─────────────────────────────────────────────────────────────────────────

/// The USIM's reply to an Authentication Request.
#[derive(Debug)]
pub enum ChallengeReply {
    /// AUTN verified and the challenge was fresh — the Authentication Response (RES*).
    Response(Vec<u8>),
    /// The challenge's SQN was not ahead of the USIM's — an Authentication Failure
    /// with cause *synch failure* (#21) carrying AUTS (TS 33.102 §6.3.3).
    SynchFailure(Vec<u8>),
}

/// A UE/USIM played by the test process: the demo subscriber's long-term key, the
/// UE-side 5G-AKA run, and the NAS security context it derives — the mirror image of
/// what the AMF/AUSF/UDM hold.
#[derive(Debug)]
pub struct ScriptedUe {
    sub: aka::SubscriberKey,
    mcc: String,
    mnc: String,
    msin: String,
    supi: String,
    /// The USIM's stored SQN (`SQNms`). When set, a challenge whose SQN is not
    /// ahead of it triggers a synchronisation failure; `None` accepts any SQN.
    sqn_ms: Option<[u8; 6]>,
    kseaf: Option<[u8; 32]>,
    /// K_AMF — retained so the test can cross-check the K_gNB the AMF hands the gNB.
    pub kamf: Option<[u8; 32]>,
    /// The K_gNB bound to the Security Mode Complete's UL NAS COUNT (TS 33.501 A.9).
    pub kgnb: Option<[u8; 32]>,
    /// The NAS security context, established at the Security Mode procedure.
    pub sec: Option<nas::NasSecurityContext>,
}

/// A 6-byte SQN as a big-endian integer, for freshness comparison.
fn sqn_u64(sqn: &[u8; 6]) -> u64 {
    sqn.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

impl ScriptedUe {
    /// The advertised UE security capability: EA0+EA2 / IA2 (`[EA, IA]`).
    pub const SEC_CAP: [u8; 2] = [0xA0, 0x20];

    /// The demo subscriber the BDD UDR provisions: `imsi-999700000000001` with the
    /// TS 35.208 test-set-1 key.
    pub fn demo() -> Self {
        Self {
            sub: aka::SubscriberKey {
                k: [
                    0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2,
                    0x38, 0xa6, 0xbc,
                ],
                opc: [
                    0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37,
                    0xa0, 0x2b, 0xaf,
                ],
                amf: [0x80, 0x00],
            },
            mcc: "999".into(),
            mnc: "70".into(),
            msin: "0000000001".into(),
            supi: "imsi-999700000000001".into(),
            sqn_ms: None,
            kseaf: None,
            kamf: None,
            kgnb: None,
            sec: None,
        }
    }

    /// The SUPI this UE's SUCI deconceals to.
    pub fn supi(&self) -> &str {
        &self.supi
    }

    /// Give the USIM a stored SQN — a challenge whose SQN is not strictly ahead of
    /// it fails synchronisation (drives the AUTS resync path, TS 33.102 §6.3.3). A
    /// large value guarantees the first network challenge is stale.
    pub fn set_sqn_ms(&mut self, sqn_ms: [u8; 6]) {
        self.sqn_ms = Some(sqn_ms);
    }

    /// The initial (plain) SUCI Registration Request.
    pub fn registration_request(&self) -> Vec<u8> {
        nas::registration_request_suci(&self.mcc, &self.mnc, &self.msin, &Self::SEC_CAP)
    }

    /// A SUCI Registration Request carrying a Requested NSSAI (the slices the UE asks
    /// for; the AMF intersects them with the subscription).
    pub fn registration_request_requesting(&self, slices: &[(u8, Option<[u8; 3]>)]) -> Vec<u8> {
        nas::registration_request_suci_with_nssai(&self.mcc, &self.mnc, &self.msin, &Self::SEC_CAP, slices)
    }

    /// A Registration Request identifying the UE by its **5G-GUTI** (`tmsi`) — a
    /// returning UE that holds a GUTI a previous Registration Accept assigned. The
    /// AMF resolves it via its GUTI directory (or asks for the SUCI on a miss) and
    /// re-authenticates. Sent plain (ngKSI 7 — no key referenced).
    pub fn guti_registration_request(&self, tmsi: u32) -> Vec<u8> {
        nas::registration_request_with_guti(&self.mcc, &self.mnc, tmsi, &Self::SEC_CAP)
    }

    /// An **Identity Response** carrying the UE's SUCI — the answer to an Identity
    /// Request (e.g. after the AMF fails to resolve an unknown GUTI). Sent plain.
    pub fn identity_response(&self) -> Vec<u8> {
        nas::identity_response_suci(&self.mcc, &self.mnc, &self.msin)
    }

    /// Answer the Authentication Request. The USIM verifies AUTN and — if it tracks
    /// an SQN — checks freshness: a stale challenge yields a synch-failure AUTS,
    /// otherwise it derives K_AUSF → K_SEAF and returns RES*.
    pub fn authenticate(&mut self, auth_req: &[u8]) -> Result<ChallengeReply> {
        let (rand, autn) = nas::parse_authentication_request(auth_req)
            .context("not an Authentication Request")?;
        if let Some(sqn_ms) = self.sqn_ms {
            let net_sqn =
                aka::ue_recover_sqn(&self.sub, &rand, &autn).context("AUTN failed the USIM's check")?;
            if sqn_u64(&net_sqn) <= sqn_u64(&sqn_ms) {
                let auts = aka::compute_auts(&self.sub, &rand, &sqn_ms);
                return Ok(ChallengeReply::SynchFailure(nas::authentication_failure_synch(&auts)));
            }
            self.sqn_ms = Some(net_sqn); // adopt the network's fresher SQN
        }
        let (res_star, kausf) = aka::ue_authenticate(&self.sub, &rand, &autn, &self.mcc, &self.mnc)
            .map_err(|e| anyhow!("USIM refused the challenge: {e}"))?;
        self.kseaf = Some(aka::kseaf(&kausf, &self.mcc, &self.mnc));
        Ok(ChallengeReply::Response(nas::authentication_response(&res_star)))
    }

    /// Complete the Security Mode procedure: read the announced algorithm selection
    /// from the (integrity-protected, new-context) command, derive the algorithm-bound
    /// NAS keys, verify the command's MAC, and return
    /// `(nea, nia, replayed capability, protected Security Mode Complete)`.
    pub fn complete_security(&mut self, smc: &[u8]) -> Result<(u8, u8, Vec<u8>, Vec<u8>)> {
        anyhow::ensure!(
            smc.len() > 7 && smc[0] == 0x7E && smc[1] == nas::sht::INTEGRITY_NEW_CONTEXT,
            "expected a Security Mode Command protected with a new context"
        );
        // SHT 3 is integrity-only, so the inner message is readable before keys exist —
        // the UE must read it first to learn WHICH keys to derive.
        let inner = nas::decode_nas_5gs_message(&smc[7..])
            .map_err(|e| anyhow!("SMC payload decode failed: {e:?}"))?;
        let (nea, nia, replayed) =
            nas::security_mode_selection(&inner).context("not a Security Mode Command")?;

        let kseaf = self.kseaf.context("authenticate before completing security")?;
        let kamf = aka::kamf(&kseaf, &self.supi, &[0x00, 0x00]);
        let keys = aka::nas_keys(&kamf, nea, nia);
        let mut sec = nas::NasSecurityContext::new(keys.knas_int, keys.knas_enc, nia, nea);
        sec.unprotect(smc, 1).context("the SMC failed the UE's integrity check")?;

        let ul_count = sec.ul_count; // the COUNT the SM Complete goes out under
        let complete =
            sec.protect(&nas::security_mode_complete(), nas::sht::INTEGRITY_CIPHERED_NEW_CONTEXT, 0);
        self.kamf = Some(kamf);
        self.kgnb = Some(aka::kgnb(&kamf, ul_count));
        self.sec = Some(sec);
        Ok((nea, nia, replayed, complete))
    }

    /// A NAS-protected **UL NAS Transport** carrying a PDU Session Establishment
    /// Request for `psi` (PTI 1) — the UE asks the network for a PDU session.
    pub fn pdu_session_request(&mut self, psi: u8) -> Result<Vec<u8>> {
        let container = nas::pdu_session_establishment_request(psi, 1);
        let transport = nas::ul_nas_transport_sm(psi, container, None, None);
        let inner = nas::decode_nas_5gs_message(&transport).context("encode UL NAS Transport")?;
        self.protected_uplink(&inner)
    }

    /// A NAS-protected UL NAS Transport requesting a PDU session on a specific
    /// **DNN** — used to drive the unsubscribed-DNN rejection path.
    pub fn pdu_session_request_for_dnn(&mut self, psi: u8, dnn: &str) -> Result<Vec<u8>> {
        let container = nas::pdu_session_establishment_request(psi, 1);
        let transport = nas::ul_nas_transport_sm(psi, container, Some(dnn), None);
        let inner = nas::decode_nas_5gs_message(&transport).context("encode UL NAS Transport")?;
        self.protected_uplink(&inner)
    }

    /// A NAS-protected UL NAS Transport requesting a PDU session that **signals a
    /// requested PDU session type** (IPv4/IPv6/IPv4v6, design/131), optionally on a
    /// specific `dnn`.
    pub fn pdu_session_request_typed(
        &mut self,
        psi: u8,
        ty: nas::PduSessionType,
        dnn: Option<&str>,
    ) -> Result<Vec<u8>> {
        let container = nas::pdu_session_establishment_request_typed(psi, 1, ty);
        let transport = nas::ul_nas_transport_sm(psi, container, dnn, None);
        let inner = nas::decode_nas_5gs_message(&transport).context("encode UL NAS Transport")?;
        self.protected_uplink(&inner)
    }

    /// Like [`pdu_session_request_typed`] but also requesting DNS server addresses via
    /// PCO (design/131 Phase D) — the network returns the IPv6 DNS in the accept's ePCO.
    pub fn pdu_session_request_typed_with_dns(
        &mut self,
        psi: u8,
        ty: nas::PduSessionType,
    ) -> Result<Vec<u8>> {
        let container = nas::pdu_session_establishment_request_with_dns(psi, 1, ty);
        let transport = nas::ul_nas_transport_sm(psi, container, None, None);
        let inner = nas::decode_nas_5gs_message(&transport).context("encode UL NAS Transport")?;
        self.protected_uplink(&inner)
    }

    /// The IPv6 DNS server from a relayed accept's ePCO (design/131 Phase D), if the
    /// network returned one.
    pub fn read_pdu_session_dns_ipv6(&mut self, dl_nas: &[u8]) -> Result<Option<std::net::Ipv6Addr>> {
        let msg = self.read_downlink(dl_nas)?;
        let (_psi, container) =
            nas::sm_container_from_dl_nas_transport(&msg).context("no SM container in the DL NAS")?;
        Ok(nas::dns_ipv6_from_establishment_accept(&container))
    }

    /// Read a relayed **PDU Session Establishment Accept**, returning `(psi, PDU
    /// address, optional 5GSM cause)` — handles IPv4, IPv6 (interface identifier),
    /// and IPv4v6, plus the session-type downgrade cause (design/131).
    pub fn read_pdu_session_accept_addr(
        &mut self,
        dl_nas: &[u8],
    ) -> Result<(u8, nas::PduAddress, Option<u8>)> {
        let msg = self.read_downlink(dl_nas)?;
        let (psi, container) =
            nas::sm_container_from_dl_nas_transport(&msg).context("no SM container in the DL NAS")?;
        anyhow::ensure!(
            container.get(3) == Some(&0xc2),
            "the SM container is not a PDU Session Establishment Accept (got type {:#x?})",
            container.get(3)
        );
        let addr = nas::pdu_address_from_establishment_accept(&container)
            .context("the accept carries no PDU address")?;
        let cause = nas::accept_5gsm_cause(&container);
        Ok((psi, addr, cause))
    }

    /// Read a **PDU Session Establishment Reject** the network relayed in a protected
    /// DL NAS Transport: returns `(5GSM cause, optional T3396 back-off octet)`.
    pub fn read_pdu_session_reject(&mut self, dl_nas: &[u8]) -> Result<(u8, Option<u8>)> {
        let msg = self.read_downlink(dl_nas)?;
        let (_psi, container) =
            nas::sm_container_from_dl_nas_transport(&msg).context("no SM container in the DL NAS")?;
        nas::pdu_session_reject_info(&container).context("the SM container is not an Establishment Reject")
    }

    /// Read a **PDU Session Establishment Accept** the network relayed (the NAS-PDU
    /// inside the N2 setup, a protected DL NAS Transport): returns
    /// `(psi, assigned UE IPv4)`. Errors if it is not an accept for a session.
    pub fn read_pdu_session_accept(&mut self, dl_nas: &[u8]) -> Result<(u8, std::net::Ipv4Addr)> {
        let msg = self.read_downlink(dl_nas)?;
        let (psi, container) =
            nas::sm_container_from_dl_nas_transport(&msg).context("no SM container in the DL NAS")?;
        anyhow::ensure!(
            container.get(3) == Some(&0xc2),
            "the SM container is not a PDU Session Establishment Accept (got type {:#x?})",
            container.get(3)
        );
        let ip = nas::ue_ipv4_from_establishment_accept(&container)
            .context("the accept carries no IPv4 PDU address")?;
        Ok((psi, ip))
    }

    /// Answer with a deliberately **wrong** RES* — the AUSF's confirmation must
    /// reject it (RES\* ≠ XRES\*). Drives the authentication-not-accepted path.
    pub fn wrong_challenge_response(&self, auth_req: &[u8]) -> Result<Vec<u8>> {
        let (rand, autn) = nas::parse_authentication_request(auth_req)
            .context("not an Authentication Request")?;
        let (mut res_star, _kausf) = aka::ue_authenticate(&self.sub, &rand, &autn, &self.mcc, &self.mnc)
            .map_err(|e| anyhow!("USIM refused the challenge: {e}"))?;
        res_star[0] ^= 0xFF; // corrupt RES* so it fails the network's check
        Ok(nas::authentication_response(&res_star))
    }

    /// Build a NAS-protected **Service Request** (signalling, ngKSI 0) identifying
    /// the UE by its 5G-TMSI — a CM-IDLE UE resuming its N2 connection. Records the
    /// **resume K_gNB** derived from the NAS COUNT this message goes out under
    /// (TS 33.501 §6.9.2.1.1); the AMF derives the same for the Initial Context Setup.
    pub fn service_request(&mut self, tmsi: u32) -> Result<Vec<u8>> {
        let plain = nas::service_request(0, 0, tmsi);
        let inner = nas::decode_nas_5gs_message(&plain).context("decode Service Request")?;
        let kamf = self.kamf.context("no K_AMF — register first")?;
        let sec = self.sec.as_mut().context("no NAS security context")?;
        let count = sec.ul_count; // the COUNT the Service Request is protected under
        let protected = sec.protect(&inner, nas::sht::INTEGRITY_CIPHERED, 0);
        self.kgnb = Some(aka::kgnb(&kamf, count));
        Ok(protected)
    }

    /// Verify + decode a protected downlink NAS message.
    pub fn read_downlink(&mut self, bytes: &[u8]) -> Result<nas::Nas5gsMessage> {
        let sec = self.sec.as_mut().context("no NAS security context yet")?;
        sec.unprotect(bytes, 1).context("downlink NAS failed the UE's check")
    }

    /// Protect an uplink NAS message under the established context.
    pub fn protected_uplink(&mut self, msg: &nas::Nas5gsMessage) -> Result<Vec<u8>> {
        let sec = self.sec.as_mut().context("no NAS security context yet")?;
        Ok(sec.protect(msg, nas::sht::INTEGRITY_CIPHERED, 0))
    }
}
