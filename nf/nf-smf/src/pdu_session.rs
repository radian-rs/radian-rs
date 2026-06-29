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

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

/// FAR id shared by the uplink Create FAR (establishment) and the downlink Update FAR.
const FAR_ID: u32 = 1;

/// Per-PDU-session SMF state.
struct SmContext {
    /// UP-SEID — addresses the session toward the UPF.
    up_seid: u64,
    /// UPF-allocated uplink N3 F-TEID.
    n3_teid: u32,
    /// gNB downlink target, once `UpdateSMContext` installs it.
    gnb: Option<(u32, Ipv4Addr)>,
}

/// SMF runtime: a PFCP client toward one UPF plus the SM-context table.
pub struct SmfState {
    smf_ip: Ipv4Addr,
    /// Connected N4 socket. A mutex serializes PFCP request/response transactions.
    sock: tokio::sync::Mutex<UdpSocket>,
    seq: AtomicU32,
    cp_seid: AtomicU64,
    next_ref: AtomicU64,
    contexts: Mutex<HashMap<String, SmContext>>,
}

impl SmfState {
    /// Bind an N4 client socket and connect it to the UPF's PFCP endpoint.
    pub async fn connect(upf_n4: SocketAddr, smf_ip: Ipv4Addr) -> std::io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(upf_n4).await?;
        Ok(Self {
            smf_ip,
            sock: tokio::sync::Mutex::new(sock),
            seq: AtomicU32::new(1),
            cp_seid: AtomicU64::new(1),
            next_ref: AtomicU64::new(1),
            contexts: Mutex::new(HashMap::new()),
        })
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Send one PFCP request and await *its* response — correlated by sequence number
    /// (PFCP responses echo the request's), discarding any stale/mismatched datagram
    /// (e.g. a late response to a previously timed-out request). 2s overall.
    async fn transact(&self, req: &[u8], expect_seq: u32) -> Option<Vec<u8>> {
        let sock = self.sock.lock().await;
        sock.send(req).await.ok()?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let mut buf = vec![0u8; 2048];
                let n = sock.recv(&mut buf).await.ok()?;
                buf.truncate(n);
                if pfcp::sequence_of(&buf) == Some(expect_seq) {
                    return Some(buf);
                }
                // Sequence mismatch — not the response to this request; drop it.
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// PFCP Association Setup toward the UPF — required before any session.
    pub async fn associate(&self) -> anyhow::Result<()> {
        let seq = self.next_seq();
        let req = pfcp::association_setup_request(self.smf_ip, seq);
        let resp = self
            .transact(&req, seq)
            .await
            .ok_or_else(|| anyhow::anyhow!("no PFCP association response from UPF"))?;
        anyhow::ensure!(pfcp::response_accepted(&resp), "UPF rejected PFCP association");
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextCreateData {
    supi: String,
    pdu_session_id: u8,
    #[serde(default)]
    dnn: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextCreatedData {
    sm_context_ref: String,
    /// The UPF's N3 F-TEID — carried to the gNB in the N2 SM info.
    up_n3_teid: String,
    up_n3_addr: Ipv4Addr,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmContextUpdateData {
    /// The gNB's N3 F-TEID from the N2 PDU Session Resource Setup Response (hex).
    gnb_n3_teid: String,
    gnb_n3_addr: Ipv4Addr,
}

/// The `Nsmf_PDUSession` router.
pub fn router(state: Arc<SmfState>) -> Router {
    Router::new()
        .route("/nsmf-pdusession/v1/sm-contexts", post(create_sm_context))
        .route(
            "/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify",
            post(update_sm_context),
        )
        .with_state(state)
}

/// `Nsmf_PDUSession_CreateSMContext`: establish the N4 session, return the UPF N3 F-TEID.
async fn create_sm_context(
    State(smf): State<Arc<SmfState>>,
    Json(req): Json<SmContextCreateData>,
) -> Result<(StatusCode, Json<SmContextCreatedData>), StatusCode> {
    let cp_seid = smf.cp_seid.fetch_add(1, Ordering::Relaxed);
    let seq = smf.next_seq();
    let est_req = pfcp::session_establishment_request(cp_seid, seq, smf.smf_ip);
    let resp = smf.transact(&est_req, seq).await.ok_or(StatusCode::BAD_GATEWAY)?;
    let est = pfcp::parse_session_establishment_response(&resp).ok_or(StatusCode::BAD_GATEWAY)?;

    let sm_ref = smf.next_ref.fetch_add(1, Ordering::Relaxed).to_string();
    smf.contexts.lock().unwrap().insert(
        sm_ref.clone(),
        SmContext { up_seid: est.up_seid, n3_teid: est.n3_teid, gnb: None },
    );
    // SUPI is a permanent subscriber identifier (PII): log only a masked form.
    tracing::info!(
        supi = %masked_supi(&req.supi),
        pdu_session_id = req.pdu_session_id,
        dnn = %req.dnn,
        up_seid = est.up_seid,
        n3_teid = est.n3_teid,
        "created SM context; N4 session established"
    );
    Ok((
        StatusCode::CREATED,
        Json(SmContextCreatedData {
            sm_context_ref: sm_ref,
            up_n3_teid: format!("{:08x}", est.n3_teid),
            up_n3_addr: est.n3_addr,
        }),
    ))
}

/// `Nsmf_PDUSession_UpdateSMContext`: install the downlink path with the gNB's F-TEID.
async fn update_sm_context(
    State(smf): State<Arc<SmfState>>,
    Path(sm_ref): Path<String>,
    Json(req): Json<SmContextUpdateData>,
) -> StatusCode {
    let gnb_teid = match u32::from_str_radix(req.gnb_n3_teid.trim_start_matches("0x"), 16) {
        Ok(t) => t,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    // Defense-in-depth on the downlink sink: reject an obviously bogus gNB target. The
    // real protection is SBI authorization (only the AMF may call Nsmf) — OAuth2 is
    // deferred (TS 33.501), same posture as the rest of SBI; the gNB F-TEID legitimately
    // comes from the AMF (which learned it from the N2 PDU Session Resource Setup).
    if !valid_gnb_target(gnb_teid, req.gnb_n3_addr) {
        return StatusCode::BAD_REQUEST;
    }
    let up_seid = {
        let ctxs = smf.contexts.lock().unwrap();
        match ctxs.get(&sm_ref) {
            Some(c) => c.up_seid,
            None => return StatusCode::NOT_FOUND,
        }
    };

    let seq = smf.next_seq();
    let mod_req = pfcp::session_modification_request(up_seid, seq, FAR_ID, gnb_teid, req.gnb_n3_addr);
    let resp = match smf.transact(&mod_req, seq).await {
        Some(r) => r,
        None => return StatusCode::BAD_GATEWAY,
    };
    if !pfcp::response_accepted(&resp) {
        return StatusCode::BAD_GATEWAY;
    }

    if let Some(c) = smf.contexts.lock().unwrap().get_mut(&sm_ref) {
        c.gnb = Some((gnb_teid, req.gnb_n3_addr));
        tracing::info!(%sm_ref, uplink_teid = c.n3_teid, gnb_teid, "updated SM context; N4 downlink installed");
    }
    StatusCode::OK
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

/// Register this SMF's `nsmf-pdusession` service with the NRF so the AMF can discover it.
pub async fn register_with_nrf(nrf_base: &str, ip: Ipv4Addr, sbi_port: u16) -> anyhow::Result<()> {
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, NrfClient};
    let mut profile = NfProfile::new(sbi_core::new_nf_instance_id(), "SMF", ip.to_string());
    profile.nf_services = Some(vec![NfService {
        service_instance_id: "nsmf-pdusession-1".into(),
        service_name: "nsmf-pdusession".into(),
        scheme: "http".into(),
        ip_end_points: vec![IpEndPoint {
            ipv4_address: Some(ip.to_string()),
            port: Some(sbi_port),
        }],
    }]);
    NrfClient::new(nrf_base.to_string()).register(&profile).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Full Nsmf → N4 spine: an in-process UPF, the SMF as PFCP client + SBI server,
    /// driven over HTTP. CreateSMContext establishes the session (UPF allocates the
    /// uplink TEID); UpdateSMContext installs the gNB downlink target on the UPF.
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
                        pfcp::handle_n4(&buf[..n], upf_ip, &mut s)
                    };
                    if let Some(resp) = resp {
                        upf_sock.send_to(&resp, peer).await.unwrap();
                    }
                }
            });
        }

        // SMF: connect, associate, serve Nsmf.
        let smf = Arc::new(SmfState::connect(upf_addr, Ipv4Addr::new(127, 0, 0, 1)).await.unwrap());
        smf.associate().await.unwrap();
        let smf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_listener.local_addr().unwrap();
        tokio::spawn(async move { sbi_core::run_on(smf_listener, router(smf)).await.unwrap() });

        let client = sbi_core::h2c_client();
        let base = format!("http://{smf_addr}");

        // AMF → SMF: CreateSMContext.
        let created: SmContextCreatedData = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({"supi":"imsi-999700000000001","pduSessionId":5,"dnn":"internet"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(created.up_n3_teid, "00000001", "UPF allocated the first N3 TEID");
        assert_eq!(upf_state.lock().unwrap().session_count(), 1, "N4 session established");

        // AMF → SMF: UpdateSMContext with the gNB's downlink F-TEID (from N2 setup).
        let status = client
            .post(format!("{base}/nsmf-pdusession/v1/sm-contexts/{}/modify", created.sm_context_ref))
            .json(&serde_json::json!({"gnbN3Teid":"00005678","gnbN3Addr":"10.0.0.9"}))
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "UpdateSMContext succeeded");

        // The UPF now has the downlink installed for the session.
        assert_eq!(
            upf_state.lock().unwrap().downlink_for(1),
            Some((0x5678, Ipv4Addr::new(10, 0, 0, 9))),
            "N4 modification installed the gNB downlink target"
        );
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
