//! SBI OAuth2 access tokens (TS 33.501 §13.4 / TS 29.510 §6.3) — the "Token"
//! half of SBI security. The **NRF is the authorization server**: an NF client
//! requests an access token for a target NF (Nnrf_AccessTokenRequest), and the
//! target NF (resource server) validates it before serving.
//!
//! # Trust model (and its limit)
//!
//! Tokens are **HS256 JWTs** signed with a shared secret (`RADIAN_SBI_SECRET`)
//! held by the NRF and the resource servers. This authenticates *membership in
//! the trusted core* (holding the secret) and enforces **audience / scope /
//! expiry** — a request without a valid token for the right target NF is
//! rejected. It does **not** give per-NF unforgeable identity: any secret holder
//! could mint a token. True per-NF identity needs asymmetric signing (the NRF
//! holds a private key, NFs verify with its public key) plus mutual **TLS** for
//! confidentiality — the next hardening slices. Clients here are **secretless**:
//! they only relay NRF-issued tokens.
//!
//! **Opt-in:** with no secret configured, [`sbi_secret`] is `None` and
//! [`protect`] adds no layer — the SBI is open (the documented dev-phase
//! posture). Setting `RADIAN_SBI_SECRET` turns enforcement on everywhere it is
//! applied.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{middleware, Router};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_TTL_SECS: u64 = 3600;
const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The shared SBI signing secret from `RADIAN_SBI_SECRET` (hex). `None` disables
/// OAuth2 enforcement (open SBI — the dev-phase default).
pub fn sbi_secret() -> Option<Vec<u8>> {
    std::env::var("RADIAN_SBI_SECRET").ok().and_then(|h| hex::decode(h.trim()).ok())
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Access-token claims (TS 29.510 §6.3.5.2.4 `AccessTokenClaims`, trimmed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Issuer — the NRF's NF instance id.
    pub iss: String,
    /// Subject — the requesting NF's instance id.
    pub sub: String,
    /// Audience — the target NF type (e.g. `"UDR"`).
    pub aud: String,
    /// Space-separated authorized service names.
    pub scope: String,
    pub iat: u64,
    pub exp: u64,
}

/// Sign an access token (HS256 JWT) with `secret`.
pub fn mint(secret: &[u8], claims: &AccessTokenClaims) -> String {
    let header = B64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = B64.encode(serde_json::to_vec(claims).expect("serialize claims"));
    let signing_input = format!("{header}.{payload}");
    let sig = B64.encode(hmac_sha256(secret, signing_input.as_bytes()));
    format!("{signing_input}.{sig}")
}

fn hmac_sha256(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Why an access token was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    BadSignature,
    Expired,
    WrongAudience,
}

/// Verify a token's signature, expiry, and audience against `secret`.
pub fn validate(
    secret: &[u8],
    token: &str,
    expected_aud: &str,
    now: u64,
) -> Result<AccessTokenClaims, TokenError> {
    let mut parts = token.split('.');
    let (header, payload, sig) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(TokenError::Malformed),
    };
    // Constant-time MAC verification over "<header>.<payload>".
    let signing_input = format!("{header}.{payload}");
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| TokenError::Malformed)?;
    mac.update(signing_input.as_bytes());
    let sig_bytes = B64.decode(sig).map_err(|_| TokenError::Malformed)?;
    mac.verify_slice(&sig_bytes).map_err(|_| TokenError::BadSignature)?;

    let claims: AccessTokenClaims =
        serde_json::from_slice(&B64.decode(payload).map_err(|_| TokenError::Malformed)?)
            .map_err(|_| TokenError::Malformed)?;
    if now >= claims.exp {
        return Err(TokenError::Expired);
    }
    if !claims.aud.eq_ignore_ascii_case(expected_aud) {
        return Err(TokenError::WrongAudience);
    }
    Ok(claims)
}

// ── Authorization server (NRF) ────────────────────────────────────────────────

/// Nnrf_AccessTokenRequest body (TS 29.510 §6.3.5.2.2), trimmed.
#[derive(Debug, Deserialize)]
pub struct AccessTokenReq {
    pub grant_type: String,
    #[serde(rename = "nfInstanceId")]
    pub nf_instance_id: String,
    #[serde(rename = "targetNfType")]
    pub target_nf_type: String,
    #[serde(default)]
    pub scope: String,
}

/// Nnrf_AccessTokenResponse (TS 29.510 §6.3.5.2.3).
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenRsp {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Mint an access token for a `client_credentials` request. The NRF calls this
/// once it has validated the request (e.g. the client is registered).
pub fn issue_token(secret: &[u8], nrf_id: &str, req: &AccessTokenReq) -> AccessTokenRsp {
    let now = now_secs();
    let claims = AccessTokenClaims {
        iss: nrf_id.to_string(),
        sub: req.nf_instance_id.clone(),
        aud: req.target_nf_type.clone(),
        scope: req.scope.clone(),
        iat: now,
        exp: now + TOKEN_TTL_SECS,
    };
    AccessTokenRsp {
        access_token: mint(secret, &claims),
        token_type: "Bearer".to_string(),
        expires_in: TOKEN_TTL_SECS,
    }
}

// ── Resource server (any protected NF) ────────────────────────────────────────

#[derive(Clone)]
struct AuthConfig {
    nf_type: String,
    secret: Vec<u8>,
}

/// Wrap `router` so every request must carry a valid Bearer access token whose
/// audience is `nf_type` — **when `secret` is `Some`**. With `None`, the router
/// is returned unchanged (open SBI). Pass `oauth::sbi_secret()` as `secret`.
pub fn protect(router: Router, nf_type: &str, secret: Option<Vec<u8>>) -> Router {
    match secret {
        None => router,
        Some(secret) => router.layer(middleware::from_fn_with_state(
            AuthConfig { nf_type: nf_type.to_string(), secret },
            require_token,
        )),
    }
}

async fn require_token(State(cfg): State<AuthConfig>, req: Request, next: Next) -> Response {
    let bearer = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    match bearer.map(|t| validate(&cfg.secret, t, &cfg.nf_type, now_secs())) {
        Some(Ok(_)) => next.run(req).await,
        other => {
            let detail = match other {
                None => "missing Bearer access token",
                Some(Err(TokenError::Expired)) => "access token expired",
                Some(Err(TokenError::WrongAudience)) => "access token audience mismatch",
                Some(Err(TokenError::BadSignature)) => "access token signature invalid",
                _ => "malformed access token",
            };
            tracing::warn!(nf_type = %cfg.nf_type, "SBI request rejected: {detail}");
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(crate::ProblemDetails {
                    status: Some(401),
                    title: Some("Unauthorized".into()),
                    cause: Some("UNAUTHORIZED".into()),
                    detail: Some(detail.into()),
                    ..Default::default()
                }),
            )
                .into_response()
        }
    }
}

// ── Client (any NF that calls a protected service) ────────────────────────────

/// A secretless token source: fetches (and caches) access tokens from the NRF's
/// `/oauth2/token` endpoint on behalf of a client NF. Attach the result as
/// `Authorization: Bearer <token>` when calling a protected NF.
pub struct TokenSource {
    nrf_base: String,
    client_id: String,
    http: reqwest::Client,
    /// target NF type → (token, expiry secs).
    cache: Mutex<std::collections::HashMap<String, (String, u64)>>,
}

impl TokenSource {
    /// A source for client NF `client_id`, requesting tokens from `nrf_base`.
    pub fn new(nrf_base: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            nrf_base: nrf_base.into(),
            client_id: client_id.into(),
            http: crate::h2c_client(),
            cache: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// A valid access token for `target_nf_type` (with `scope`), cached until it
    /// nears expiry. `None` if the NRF token endpoint is unreachable/disabled —
    /// the caller then sends no token (and a protected server will 401).
    pub async fn token_for(&self, target_nf_type: &str, scope: &str) -> Option<String> {
        let now = now_secs();
        if let Some((tok, exp)) = self.cache.lock().unwrap().get(target_nf_type) {
            if now + 30 < *exp {
                return Some(tok.clone());
            }
        }
        let rsp: AccessTokenRsp = self
            .http
            .post(format!("{}/oauth2/token", self.nrf_base))
            .json(&serde_json::json!({
                "grant_type": "client_credentials",
                "nfInstanceId": self.client_id,
                "targetNfType": target_nf_type,
                "scope": scope,
            }))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json()
            .await
            .ok()?;
        self.cache
            .lock()
            .unwrap()
            .insert(target_nf_type.to_string(), (rsp.access_token.clone(), now + rsp.expires_in));
        Some(rsp.access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a-shared-sbi-secret-32-bytes-long";

    fn claims(aud: &str, exp: u64) -> AccessTokenClaims {
        AccessTokenClaims {
            iss: "nrf-1".into(),
            sub: "udm-1".into(),
            aud: aud.into(),
            scope: "nudr-dr".into(),
            iat: 1000,
            exp,
        }
    }

    #[test]
    fn mint_then_validate_roundtrips() {
        let token = mint(SECRET, &claims("UDR", 5000));
        let got = validate(SECRET, &token, "UDR", 2000).expect("valid");
        assert_eq!(got.sub, "udm-1");
        assert_eq!(got.aud, "UDR");
        // Audience is case-insensitive.
        assert!(validate(SECRET, &token, "udr", 2000).is_ok());
    }

    #[test]
    fn validate_rejects_expiry_audience_and_tampering() {
        let token = mint(SECRET, &claims("UDR", 5000));
        assert_eq!(validate(SECRET, &token, "UDR", 5000), Err(TokenError::Expired));
        assert_eq!(validate(SECRET, &token, "UDM", 2000), Err(TokenError::WrongAudience));
        // A different secret → signature mismatch (not accepted).
        assert_eq!(validate(b"other-secret", &token, "UDR", 2000), Err(TokenError::BadSignature));
        // Tampered payload → signature mismatch.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = mint(b"attacker", &claims("UDR", 9999));
        let forged_payload = forged.split('.').nth(1).unwrap();
        parts[1] = forged_payload;
        let tampered = parts.join(".");
        assert!(validate(SECRET, &tampered, "UDR", 2000).is_err());
        // Not three parts → malformed.
        assert_eq!(validate(SECRET, "a.b", "UDR", 2000), Err(TokenError::Malformed));
    }

    #[test]
    fn issue_token_targets_the_requested_nf() {
        let req = AccessTokenReq {
            grant_type: "client_credentials".into(),
            nf_instance_id: "udm-1".into(),
            target_nf_type: "UDR".into(),
            scope: "nudr-dr".into(),
        };
        let rsp = issue_token(SECRET, "nrf-1", &req);
        assert_eq!(rsp.token_type, "Bearer");
        let claims = validate(SECRET, &rsp.access_token, "UDR", now_secs()).expect("valid now");
        assert_eq!((claims.iss.as_str(), claims.sub.as_str()), ("nrf-1", "udm-1"));
    }
}
