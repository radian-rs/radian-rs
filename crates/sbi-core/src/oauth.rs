//! SBI OAuth2 access tokens (TS 33.501 §13.4 / TS 29.510 §6.3) — the "Token"
//! half of SBI security. The **NRF is the authorization server**: an NF client
//! requests an access token for a target NF (Nnrf_AccessTokenRequest), and the
//! target NF (resource server) validates it before serving.
//!
//! # Trust models
//!
//! Two signing modes, selected by config:
//!
//! - **Shared secret (HS256)** — tokens are signed with `RADIAN_SBI_SECRET`, held
//!   by the NRF and the resource servers. Authenticates *membership in the trusted
//!   core* and enforces audience / scope / expiry, but gives no per-NF
//!   *unforgeable* identity: any secret holder could mint a token.
//! - **Asymmetric (ES256 + JWKS)** — set `RADIAN_SBI_OAUTH=asymmetric`. The NRF
//!   signs with a **private** P-256 key and publishes the matching **public** key
//!   at `GET /oauth2/jwks`; resource servers fetch it and verify. A resource server
//!   (e.g. a compromised UDR) **cannot mint** tokens — only the NRF's private key
//!   can. This is the TS 33.501 §13.4 posture. Confidentiality still needs mutual
//!   **TLS** (the remaining hardening slice).
//!
//! Clients are **secretless** either way: they only relay NRF-issued tokens.
//!
//! **Opt-in:** with neither configured, [`verifier`] is `None` and [`protect`]
//! adds no layer — the SBI is open (the documented dev-phase posture).

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{middleware, Router};
use base64::Engine;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_TTL_SECS: u64 = 3600;
const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The shared SBI signing secret from `RADIAN_SBI_SECRET` (hex). `None` disables
/// HS256 enforcement.
pub fn sbi_secret() -> Option<Vec<u8>> {
    std::env::var("RADIAN_SBI_SECRET").ok().and_then(|h| hex::decode(h.trim()).ok())
}

/// Whether asymmetric (ES256 + JWKS) mode is enabled (`RADIAN_SBI_OAUTH=asymmetric`).
/// Takes precedence over the shared secret.
pub fn asymmetric_enabled() -> bool {
    std::env::var("RADIAN_SBI_OAUTH").is_ok_and(|v| v.eq_ignore_ascii_case("asymmetric"))
}

/// Whether a client NF should attach access tokens (either OAuth mode is on) — the
/// token is opaque to the client, fetched from the NRF regardless of signing mode.
pub fn client_tokens_enabled() -> bool {
    asymmetric_enabled() || sbi_secret().is_some()
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

// ── Asymmetric signing (ES256 / ECDSA P-256 + JWKS) ───────────────────────────

/// The NRF's ES256 signing key (private). NFs verify tokens against its public JWK
/// — so a resource server cannot forge tokens.
pub struct Es256Key {
    signing: SigningKey,
    kid: String,
}

impl Es256Key {
    /// Generate a fresh P-256 signing key; the key id is derived from its public key.
    pub fn generate() -> Self {
        let signing = loop {
            let mut scalar = [0u8; 32];
            getrandom::getrandom(&mut scalar).expect("getrandom P-256 scalar");
            if let Ok(k) = SigningKey::from_slice(&scalar) {
                break k;
            }
        };
        let kid = key_id(signing.verifying_key());
        Self { signing, kid }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Sign an access token as an ES256 JWT (JOSE-format 64-byte r‖s signature).
    pub fn mint(&self, claims: &AccessTokenClaims) -> String {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let h = B64.encode(serde_json::to_vec(&header).expect("serialize header"));
        let p = B64.encode(serde_json::to_vec(claims).expect("serialize claims"));
        let signing_input = format!("{h}.{p}");
        let sig: Signature = self.signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
    }

    /// The public key as a JWK, for the NRF's JWKS endpoint.
    pub fn public_jwk(&self) -> Jwk {
        let point = self.signing.verifying_key().to_encoded_point(false);
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: B64.encode(point.x().expect("EC x coordinate")),
            y: B64.encode(point.y().expect("EC y coordinate")),
            kid: self.kid.clone(),
            alg: "ES256".into(),
            use_: "sig".into(),
        }
    }

    /// The JWK set (one key) the NRF publishes.
    pub fn jwks(&self) -> Jwks {
        Jwks { keys: vec![self.public_jwk()] }
    }
}

/// A short key id: hex of the first 8 bytes of SHA-256 over the SEC1 public point.
fn key_id(vk: &VerifyingKey) -> String {
    use sha2::Digest;
    let digest = Sha256::digest(vk.to_encoded_point(false).as_bytes());
    hex::encode(&digest[..8])
}

/// A JSON Web Key — a public EC key (TS 29.510 JWKS / RFC 7517).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
    #[serde(default)]
    pub alg: String,
    #[serde(rename = "use", default)]
    pub use_: String,
}

impl Jwk {
    /// Reconstruct the P-256 verifying key from the JWK's `(x, y)`.
    fn verifying_key(&self) -> Option<VerifyingKey> {
        if self.kty != "EC" || self.crv != "P-256" {
            return None;
        }
        let (x, y) = (B64.decode(&self.x).ok()?, B64.decode(&self.y).ok()?);
        if x.len() != 32 || y.len() != 32 {
            return None;
        }
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04); // uncompressed SEC1 point
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&sec1).ok()
    }
}

/// A JWK set — the NRF's public signing keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Verify an ES256 token against a JWKS: signature (by `kid`), then expiry and
/// audience. The key is selected by the header's `kid` (else the first key).
pub fn validate_es256(
    token: &str,
    expected_aud: &str,
    jwks: &Jwks,
    now: u64,
) -> Result<AccessTokenClaims, TokenError> {
    let mut parts = token.split('.');
    let (header, payload, sig) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(TokenError::Malformed),
    };
    let hdr: serde_json::Value =
        serde_json::from_slice(&B64.decode(header).map_err(|_| TokenError::Malformed)?)
            .map_err(|_| TokenError::Malformed)?;
    let kid = hdr.get("kid").and_then(|v| v.as_str());
    let jwk = jwks
        .keys
        .iter()
        .find(|k| kid == Some(k.kid.as_str()))
        .or_else(|| jwks.keys.first())
        .ok_or(TokenError::BadSignature)?;
    let vk = jwk.verifying_key().ok_or(TokenError::BadSignature)?;
    let sig_bytes = B64.decode(sig).map_err(|_| TokenError::Malformed)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| TokenError::Malformed)?;
    let signing_input = format!("{header}.{payload}");
    vk.verify(signing_input.as_bytes(), &signature).map_err(|_| TokenError::BadSignature)?;

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

/// The claims for a `client_credentials` request (issuer = NRF, subject = client,
/// audience = target NF type).
fn token_claims(nrf_id: &str, req: &AccessTokenReq) -> AccessTokenClaims {
    let now = now_secs();
    AccessTokenClaims {
        iss: nrf_id.to_string(),
        sub: req.nf_instance_id.clone(),
        aud: req.target_nf_type.clone(),
        scope: req.scope.clone(),
        iat: now,
        exp: now + TOKEN_TTL_SECS,
    }
}

fn token_rsp(access_token: String) -> AccessTokenRsp {
    AccessTokenRsp { access_token, token_type: "Bearer".to_string(), expires_in: TOKEN_TTL_SECS }
}

/// Mint an HS256 access token (shared-secret mode). The NRF calls this once it has
/// validated the request (e.g. the client is registered).
pub fn issue_token(secret: &[u8], nrf_id: &str, req: &AccessTokenReq) -> AccessTokenRsp {
    token_rsp(mint(secret, &token_claims(nrf_id, req)))
}

/// Mint an ES256 access token (asymmetric mode), signed with the NRF's private key.
pub fn issue_token_es256(key: &Es256Key, nrf_id: &str, req: &AccessTokenReq) -> AccessTokenRsp {
    token_rsp(key.mint(&token_claims(nrf_id, req)))
}

// ── Resource server (any protected NF) ────────────────────────────────────────

/// How a protected NF verifies access tokens.
#[derive(Clone)]
pub enum TokenVerifier {
    /// HS256 with a shared secret.
    Shared(Vec<u8>),
    /// ES256 against the NRF's JWKS, fetched from its base URL and cached.
    Jwks(Arc<JwksCache>),
}

/// Fetches and caches the NRF's JWKS (`GET {nrf_base}/oauth2/jwks`) for ES256
/// verification.
pub struct JwksCache {
    nrf_base: String,
    http: reqwest::Client,
    cache: Mutex<Option<Jwks>>,
}

impl JwksCache {
    pub fn new(nrf_base: impl Into<String>) -> Self {
        Self { nrf_base: nrf_base.into(), http: crate::h2c_client(), cache: Mutex::new(None) }
    }

    /// The cached JWKS, fetching from the NRF on a miss (or when `force`d, e.g.
    /// after a signature failure that may be a key rotation).
    async fn jwks(&self, force: bool) -> Option<Jwks> {
        if !force {
            if let Some(j) = self.cache.lock().unwrap().clone() {
                return Some(j);
            }
        }
        let jwks: Jwks = self
            .http
            .get(format!("{}/oauth2/jwks", self.nrf_base))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json()
            .await
            .ok()?;
        *self.cache.lock().unwrap() = Some(jwks.clone());
        Some(jwks)
    }
}

impl TokenVerifier {
    async fn verify(
        &self,
        token: &str,
        aud: &str,
        now: u64,
    ) -> Result<AccessTokenClaims, TokenError> {
        match self {
            TokenVerifier::Shared(secret) => validate(secret, token, aud, now),
            TokenVerifier::Jwks(cache) => {
                let jwks = cache.jwks(false).await.ok_or(TokenError::BadSignature)?;
                match validate_es256(token, aud, &jwks, now) {
                    // A bad signature may mean the NRF rotated keys — refetch once.
                    Err(TokenError::BadSignature) => {
                        let fresh = cache.jwks(true).await.ok_or(TokenError::BadSignature)?;
                        validate_es256(token, aud, &fresh, now)
                    }
                    other => other,
                }
            }
        }
    }
}

/// Build a token verifier from config: asymmetric (ES256 via the NRF's JWKS at
/// `nrf_base`) when `RADIAN_SBI_OAUTH=asymmetric`, else the shared secret, else
/// `None` (open SBI).
pub fn verifier(nrf_base: &str) -> Option<TokenVerifier> {
    if asymmetric_enabled() {
        Some(TokenVerifier::Jwks(Arc::new(JwksCache::new(nrf_base))))
    } else {
        sbi_secret().map(TokenVerifier::Shared)
    }
}

#[derive(Clone)]
struct AuthConfig {
    nf_type: String,
    verifier: TokenVerifier,
}

/// Wrap `router` so every request must carry a valid Bearer access token whose
/// audience is `nf_type` — **when `verifier` is `Some`**. With `None`, the router
/// is returned unchanged (open SBI). Pass `oauth::verifier(nrf_base)`.
pub fn protect(router: Router, nf_type: &str, verifier: Option<TokenVerifier>) -> Router {
    match verifier {
        None => router,
        Some(verifier) => router.layer(middleware::from_fn_with_state(
            AuthConfig { nf_type: nf_type.to_string(), verifier },
            require_token,
        )),
    }
}

async fn require_token(State(cfg): State<AuthConfig>, req: Request, next: Next) -> Response {
    let bearer = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_owned);
    let result = match &bearer {
        Some(t) => Some(cfg.verifier.verify(t, &cfg.nf_type, now_secs()).await),
        None => None,
    };
    match result {
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
    fn es256_mint_then_validate_roundtrips() {
        let key = Es256Key::generate();
        let jwks = key.jwks();
        let token = key.mint(&claims("UDR", 5000));
        let got = validate_es256(&token, "UDR", &jwks, 2000).expect("valid");
        assert_eq!(got.sub, "udm-1");
        assert!(validate_es256(&token, "udr", &jwks, 2000).is_ok(), "case-insensitive audience");
        assert_eq!(validate_es256(&token, "UDR", &jwks, 5000), Err(TokenError::Expired));
        assert_eq!(validate_es256(&token, "UDM", &jwks, 2000), Err(TokenError::WrongAudience));
        // The JWK round-trips through JSON (the JWKS wire format).
        let back: Jwks = serde_json::from_str(&serde_json::to_string(&jwks).unwrap()).unwrap();
        assert!(validate_es256(&token, "UDR", &back, 2000).is_ok());
    }

    #[test]
    fn es256_rejects_another_keys_signature() {
        // The property a shared secret lacks: a token minted by one key does NOT
        // verify against a different key — a resource server can't forge NRF tokens.
        let nrf = Es256Key::generate();
        let attacker = Es256Key::generate();
        let token = nrf.mint(&claims("UDR", 5000));
        assert!(validate_es256(&token, "UDR", &nrf.jwks(), 2000).is_ok());
        assert_eq!(
            validate_es256(&token, "UDR", &attacker.jwks(), 2000),
            Err(TokenError::BadSignature)
        );
        // Tampered payload → signature fails.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = attacker.mint(&claims("UDR", 9999));
        parts[1] = forged.split('.').nth(1).unwrap();
        assert!(validate_es256(&parts.join("."), "UDR", &nrf.jwks(), 2000).is_err());
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
