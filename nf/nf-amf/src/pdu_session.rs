//! The AMF side of the PDU-session call flow.
//!
//! When a UE sends a 5GMM **UL NAS Transport** carrying a NAS-SM container, the AMF
//! discovers the SMF (via the NRF) and calls **`Nsmf_PDUSession_CreateSMContext`**.
//! The SMF establishes the N4 session and returns the UPF's N3 F-TEID — which the AMF
//! will (a later slice) place in the N2 SM info of a PDU Session Resource Setup to the
//! gNB. The SM container is relayed opaquely (TS 29.502 multipart is a later slice).

use sbi_core::nnrf::NrfClient;

/// The AMF's client toward the SMF's `Nsmf_PDUSession` service.
pub struct AmfSmf {
    nrf: NrfClient,
}

impl AmfSmf {
    pub fn new(nrf_base: impl Into<String>) -> Self {
        Self { nrf: NrfClient::new(nrf_base.into()) }
    }

    /// Discover the SMF and create an SM context for a UE's PDU session.
    pub async fn create_sm_context(
        &self,
        supi: &str,
        pdu_session_id: u8,
        dnn: &str,
    ) -> Result<(), String> {
        let smf_base = self.discover_smf().await?;
        let resp = sbi_core::h2c_client()
            .post(format!("{smf_base}/nsmf-pdusession/v1/sm-contexts"))
            .json(&serde_json::json!({
                "supi": supi,
                "pduSessionId": pdu_session_id,
                "dnn": dnn,
            }))
            .send()
            .await
            .map_err(|e| format!("Nsmf CreateSMContext request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("Nsmf CreateSMContext returned {}", resp.status()));
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
        async fn mock_create() -> (StatusCode, Json<serde_json::Value>) {
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "smContextRef": "1", "upN3Teid": "00000001", "upN3Addr": "127.0.0.1"
                })),
            )
        }
        let smf_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf_l.local_addr().unwrap();
        let smf_router = Router::new().route("/nsmf-pdusession/v1/sm-contexts", post(mock_create));
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

        let amf_smf = AmfSmf::new(nrf_base);
        amf_smf
            .create_sm_context("imsi-999700000000001", 5, "internet")
            .await
            .expect("AMF creates SM context via discovered SMF");
    }
}
