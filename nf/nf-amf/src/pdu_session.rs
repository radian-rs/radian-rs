//! The AMF side of the PDU-session call flow.
//!
//! When a UE sends a 5GMM **UL NAS Transport** carrying a NAS-SM container, the AMF
//! discovers the SMF (via the NRF) and calls **`Nsmf_PDUSession_CreateSMContext`**.
//! The SMF establishes the N4 session and returns the UPF's N3 F-TEID — which the AMF
//! will (a later slice) place in the N2 SM info of a PDU Session Resource Setup to the
//! gNB. The SM container is relayed opaquely (TS 29.502 multipart is a later slice).

use std::net::Ipv4Addr;

use sbi_core::nnrf::NrfClient;

/// The UPF's N3 F-TEID returned by CreateSMContext — for the N2 PDU Session Resource
/// Setup the AMF sends to the gNB — plus the subscribed session parameters the AMF
/// places in the N1 PDU Session Establishment Accept.
#[derive(Debug)]
pub struct SmContextCreated {
    pub sm_ref: String,
    pub up_n3_teid: u32,
    pub up_n3_addr: Ipv4Addr,
    /// The UE's assigned IPv4 address — placed in the N1 PDU Session Establishment Accept.
    pub ue_ip: Ipv4Addr,
    /// The subscribed slice (from the SMF's UDR sm-data lookup): SST + optional SD bytes.
    pub snssai_sst: u8,
    pub snssai_sd: Option<[u8; 3]>,
    /// The subscribed session AMBR, already in NAS wire form (falls back to the
    /// pre-subscription default when the SMF didn't supply one).
    pub ambr: nas::SessionAmbr,
}

/// Why CreateSMContext failed — drives which 5GSM cause the UE gets.
#[derive(Debug)]
pub enum CreateSmError {
    /// The SMF refused the session (`403`): the DNN is not in the subscription.
    Forbidden,
    /// Anything else (discovery, transport, upstream failure).
    Other(String),
}

impl std::fmt::Display for CreateSmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreateSmError::Forbidden => write!(f, "SMF refused: DNN not subscribed"),
            CreateSmError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl From<String> for CreateSmError {
    fn from(e: String) -> Self {
        CreateSmError::Other(e)
    }
}

impl From<&str> for CreateSmError {
    fn from(e: &str) -> Self {
        CreateSmError::Other(e.to_string())
    }
}

/// The AMF's client toward the SMF's `Nsmf_PDUSession` service.
pub struct AmfSmf {
    nrf: NrfClient,
    /// The serving PLMN this AMF passes in CreateSMContext (TS 29.502 `servingNetwork`).
    mcc: String,
    mnc: String,
}

impl AmfSmf {
    pub fn new(nrf_base: impl Into<String>, mcc: impl Into<String>, mnc: impl Into<String>) -> Self {
        Self { nrf: NrfClient::new(nrf_base.into()), mcc: mcc.into(), mnc: mnc.into() }
    }

    /// Discover the SMF and create an SM context; returns the UPF N3 F-TEID and the
    /// serving session parameters. `snssai` is the UE's requested slice, forwarded
    /// as TS 29.502 `sNssai`. `Forbidden` when the SMF refused the (slice, DNN)
    /// pair — the caller turns that into a 5GSM reject (cause #27, or #70 when a
    /// slice was requested).
    pub async fn create_sm_context(
        &self,
        supi: &str,
        pdu_session_id: u8,
        dnn: &str,
        snssai: Option<(u8, Option<[u8; 3]>)>,
    ) -> Result<SmContextCreated, CreateSmError> {
        let smf_base = self.discover_smf().await?;
        let mut body = serde_json::json!({
            "supi": supi,
            "pduSessionId": pdu_session_id,
            "dnn": dnn,
            "servingNetwork": { "mcc": self.mcc, "mnc": self.mnc },
        });
        if let Some((sst, sd)) = snssai {
            let mut slice = serde_json::json!({ "sst": sst });
            if let Some(sd) = sd {
                slice["sd"] = serde_json::Value::String(hex::encode(sd));
            }
            body["sNssai"] = slice;
        }
        let resp = sbi_core::h2c_client()
            .post(format!("{smf_base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Nsmf CreateSMContext request failed: {e}"))?;
        if resp.status().as_u16() == 403 {
            return Err(CreateSmError::Forbidden);
        }
        if !resp.status().is_success() {
            return Err(format!("Nsmf CreateSMContext returned {}", resp.status()).into());
        }
        let body: serde_json::Value =
            resp.json().await.map_err(|e| format!("CreateSMContext body: {e}"))?;
        let field = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_owned);
        let sm_ref = field("smContextRef").ok_or("response missing smContextRef")?;
        let teid_hex = field("upN3Teid").ok_or("response missing upN3Teid")?;
        let up_n3_teid =
            u32::from_str_radix(&teid_hex, 16).map_err(|e| format!("bad upN3Teid: {e}"))?;
        let up_n3_addr = field("upN3Addr")
            .ok_or("response missing upN3Addr")?
            .parse()
            .map_err(|_| "bad upN3Addr")?;
        let ue_ip = field("ueIpv4Addr")
            .ok_or("response missing ueIpv4Addr")?
            .parse()
            .map_err(|_| "bad ueIpv4Addr")?;

        // Subscribed session parameters for the N1 accept. Tolerate their absence
        // (defaults match the pre-subscription behaviour) so an older SMF still works.
        let snssai_sst = body
            .pointer("/sNssai/sst")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(1);
        let snssai_sd = body
            .pointer("/sNssai/sd")
            .and_then(|v| v.as_str())
            .and_then(|sd| hex::decode(sd).ok())
            .and_then(|b| <[u8; 3]>::try_from(b).ok());
        let ambr = body
            .get("sessionAmbr")
            .and_then(|a| {
                let ul = a.get("uplink")?.as_str()?;
                let dl = a.get("downlink")?.as_str()?;
                nas::session_ambr_from_bitrates(ul, dl)
            })
            .unwrap_or(nas::SessionAmbr::TEN_MBPS);
        Ok(SmContextCreated { sm_ref, up_n3_teid, up_n3_addr, ue_ip, snssai_sst, snssai_sd, ambr })
    }

    /// Release an SM context (TS 29.502) — the SMF tears the N4 session down at
    /// the UPF. Driven by deregistration.
    pub async fn release_sm_context(&self, sm_ref: &str) -> Result<(), String> {
        let smf_base = self.discover_smf().await?;
        let resp = sbi_core::h2c_client()
            .post(format!("{smf_base}/nsmf-pdusession/v1/sm-contexts/{sm_ref}/release"))
            .send()
            .await
            .map_err(|e| format!("Nsmf ReleaseSMContext request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("Nsmf ReleaseSMContext returned {}", resp.status()));
        }
        Ok(())
    }

    /// Update the SM context with the gNB's DL N3 F-TEID (from the N2 setup response),
    /// driving the SMF's N4 Session Modification (the downlink path).
    pub async fn update_sm_context(
        &self,
        sm_ref: &str,
        gnb_teid: u32,
        gnb_addr: Ipv4Addr,
    ) -> Result<(), String> {
        let smf_base = self.discover_smf().await?;
        let resp = sbi_core::h2c_client()
            .post(format!("{smf_base}/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify"))
            .json(&serde_json::json!({
                "gnbN3Teid": format!("{gnb_teid:08x}"),
                "gnbN3Addr": gnb_addr.to_string(),
            }))
            .send()
            .await
            .map_err(|e| format!("Nsmf UpdateSMContext request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("Nsmf UpdateSMContext returned {}", resp.status()));
        }
        Ok(())
    }

    async fn discover_smf(&self) -> Result<String, String> {
        let profile = self
            .nrf
            .discover("SMF", "AMF")
            .await
            .map_err(|e| format!("NRF discovery failed: {e}"))?
            .into_iter()
            .next()
            .ok_or("no SMF registered with the NRF")?;
        let endpoint = profile
            .nf_services
            .and_then(|s| s.into_iter().next())
            .and_then(|svc| svc.ip_end_points.into_iter().next())
            .ok_or("SMF profile has no service endpoint")?;
        let ip = endpoint.ipv4_address.ok_or("SMF endpoint missing IP")?;
        let port = endpoint.port.ok_or("SMF endpoint missing port")?;
        Ok(format!("http://{ip}:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};
    use sbi_core::nnrf::{IpEndPoint, NfProfile, NfService, NrfClient};

    /// The AMF discovers a (mock) SMF via the NRF and drives CreateSMContext over h2c.
    #[tokio::test]
    async fn amf_discovers_smf_and_creates_sm_context() {
        // Mock SMF: an Nsmf endpoint returning a CreateSMContext success.
        async fn mock_create(Json(req): Json<serde_json::Value>) -> (StatusCode, Json<serde_json::Value>) {
            // The AMF must identify its serving PLMN (TS 29.502 servingNetwork) and
            // forward the UE's requested slice (sNssai).
            assert_eq!(req.pointer("/servingNetwork/mcc").and_then(|v| v.as_str()), Some("999"));
            assert_eq!(req.pointer("/servingNetwork/mnc").and_then(|v| v.as_str()), Some("70"));
            assert_eq!(req.pointer("/sNssai/sst").and_then(|v| v.as_u64()), Some(1));
            assert_eq!(req.pointer("/sNssai/sd").and_then(|v| v.as_str()), Some("010203"));
            // The subscription gate: only "internet" is subscribed (mirrors the SMF's 403).
            if req.get("dnn").and_then(|v| v.as_str()) != Some("internet") {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({})));
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "smContextRef": "1", "upN3Teid": "00000001", "upN3Addr": "127.0.0.1",
                    "ueIpv4Addr": "10.45.0.2",
                    "sNssai": { "sst": 1, "sd": "010203" },
                    "sessionAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" }
                })),
            )
        }
        async fn mock_modify() -> StatusCode {
            StatusCode::OK
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = Router::new()
            .route("/nsmf-pdusession/v1/sm-contexts", post(mock_create))
            .route("/nsmf-pdusession/v1/sm-contexts/{sm_ref}/modify", post(mock_modify));
        tokio::spawn(async move { sbi_core::run_on(smf_l, smf_router).await.unwrap() });

        // NRF with the mock SMF registered.
        let nrf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nrf_addr = nrf_l.local_addr().unwrap();
        let store = sbi_core::nnrf::NrfStore::default();
        tokio::spawn(async move { sbi_core::run_on(nrf_l, sbi_core::nnrf::router(store)).await.unwrap() });
        let nrf_base = format!("http://{nrf_addr}");

        let mut profile = NfProfile::new("smf-mock", "SMF", smf_addr.ip().to_string());
        profile.nf_services = Some(vec![NfService {
            service_instance_id: "nsmf-pdusession-1".into(),
            service_name: "nsmf-pdusession".into(),
            scheme: "http".into(),
            ip_end_points: vec![IpEndPoint {
                ipv4_address: Some(smf_addr.ip().to_string()),
                port: Some(smf_addr.port()),
            }],
        }]);
        NrfClient::new(nrf_base.clone()).register(&profile).await.unwrap();

        let amf_smf = AmfSmf::new(nrf_base, "999", "70");
        let requested = Some((1, Some([1, 2, 3])));
        let created = amf_smf
            .create_sm_context("imsi-999700000000001", 5, "internet", requested)
            .await
            .expect("AMF creates SM context via discovered SMF");
        assert_eq!(created.up_n3_teid, 1, "UPF N3 F-TEID parsed from the response");
        // Subscribed session parameters parsed for the N1 accept.
        assert_eq!((created.snssai_sst, created.snssai_sd), (1, Some([1, 2, 3])));
        assert_eq!(
            created.ambr,
            nas::SessionAmbr { dl_unit: 0x0B, dl: 2, ul_unit: 0x0B, ul: 1 }
        );

        // The gNB F-TEID (from N2 setup) drives UpdateSMContext.
        amf_smf
            .update_sm_context(&created.sm_ref, 0x5678, Ipv4Addr::new(10, 0, 0, 9))
            .await
            .expect("AMF updates SM context with the gNB F-TEID");

        // An SMF 403 (denied pair) surfaces as the typed Forbidden error — the
        // signal for the AMF to send a 5GSM reject (#27, or #70 with a slice).
        let err = amf_smf
            .create_sm_context("imsi-999700000000001", 5, "corporate", requested)
            .await
            .expect_err("unsubscribed DNN must be refused");
        assert!(matches!(err, CreateSmError::Forbidden), "got {err:?}");
    }
}
