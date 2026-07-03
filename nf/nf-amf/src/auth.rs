//! AMF authentication orchestration (the SEAF role, TS 33.501 §6.1.3.2).
//!
//! Discovers the AUSF via the NRF, runs `Nausf_UEAuthentication` to obtain a
//! challenge (RAND/AUTN) and HXRES*, then — after the UE answers — verifies the
//! UE's RES* (HRES* == HXRES*) before confirming with the AUSF.

use sbi_core::nausf::AusfClient;
use sbi_core::nnrf::NrfClient;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("sbi: {0}")]
    Sbi(#[from] sbi_core::SbiError),
    #[error("no AUSF registered in NRF")]
    NoAusf,
    #[error("malformed authentication vector from AUSF")]
    BadAv,
}

/// Per-UE authentication state held between Authentication Request and Response.
#[derive(Debug, Clone)]
pub struct PendingAuth {
    ausf_base: String,
    ctx_id: String,
    rand: [u8; 16],
    hxres: [u8; 16],
}

/// Outcome of confirming the UE's RES*.
#[derive(Debug)]
pub struct AuthOutcome {
    pub success: bool,
    pub kseaf: Option<String>,
    pub supi: Option<String>,
}

/// AMF/SEAF authentication helper: knows the NRF and the serving network.
pub struct AmfAuth {
    nrf: NrfClient,
    mcc: String,
    mnc: String,
}

impl AmfAuth {
    pub fn new(
        nrf_base: impl Into<String>,
        mcc: impl Into<String>,
        mnc: impl Into<String>,
    ) -> Self {
        Self {
            nrf: NrfClient::new(nrf_base),
            mcc: mcc.into(),
            mnc: mnc.into(),
        }
    }

    /// Begin authentication: discover the AUSF, request a challenge, and build the
    /// NAS Authentication Request to send to the UE.
    pub async fn begin(&self, supi_or_suci: &str) -> Result<(PendingAuth, Vec<u8>), AuthError> {
        let ausf_base = self.discover_ausf().await?;
        let snn = aka::serving_network_name(&self.mcc, &self.mnc);
        let ctx = AusfClient::new(ausf_base.clone())
            .authenticate(supi_or_suci, &snn)
            .await?;

        let rand = hex16(&ctx.fiveg_auth_data.rand).ok_or(AuthError::BadAv)?;
        let autn = hex16(&ctx.fiveg_auth_data.autn).ok_or(AuthError::BadAv)?;
        let hxres = hex16(&ctx.fiveg_auth_data.hxres_star).ok_or(AuthError::BadAv)?;

        let nas = nas::authentication_request(0, &rand, &autn);
        Ok((
            PendingAuth {
                ausf_base,
                ctx_id: ctx.auth_ctx_id,
                rand,
                hxres,
            },
            nas,
        ))
    }

    /// Finish authentication: SEAF-verify the UE's RES* (HRES* == HXRES*), then
    /// confirm with the AUSF (which compares RES* to XRES* and returns K_SEAF).
    pub async fn finish(
        &self,
        pending: &PendingAuth,
        res_star: &[u8],
    ) -> Result<AuthOutcome, AuthError> {
        let Ok(res16) = <[u8; 16]>::try_from(res_star) else {
            return Ok(AuthOutcome {
                success: false,
                kseaf: None,
                supi: None,
            });
        };
        // SEAF check — reject without troubling the AUSF if HRES* mismatches.
        if aka::hxres_star(&pending.rand, &res16) != pending.hxres {
            return Ok(AuthOutcome {
                success: false,
                kseaf: None,
                supi: None,
            });
        }

        let conf = AusfClient::new(pending.ausf_base.clone())
            .confirm(&pending.ctx_id, &hex::encode(res_star))
            .await?;
        Ok(AuthOutcome {
            success: conf.auth_result == "AUTHENTICATION_SUCCESS",
            kseaf: conf.kseaf,
            supi: conf.supi,
        })
    }

    /// NFDiscovery for an AUSF, returning its base URL from the advertised endpoint.
    async fn discover_ausf(&self) -> Result<String, AuthError> {
        let profile = self
            .nrf
            .discover("AUSF", "AMF")
            .await?
            .into_iter()
            .next()
            .ok_or(AuthError::NoAusf)?;
        // Dial the AUSF on the transport it advertises (`https` under mTLS).
        profile.service_base().ok_or(AuthError::NoAusf)
    }
}

fn hex16(s: &str) -> Option<[u8; 16]> {
    hex::decode(s).ok()?.try_into().ok()
}
