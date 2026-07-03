# SBI OAuth2 — Asymmetric Token Signing (ES256 + JWKS) — Implementation Notes

> Built 2026-07-03 on branch `feat/sbi-asymmetric-oauth`. The hardening slice
> [46](46-sbi-oauth.md) explicitly deferred: the NRF signs access tokens with a
> **private key** and NFs verify with its **public key via a JWKS endpoint**, so a
> compromised resource server can no longer mint tokens. The shared-secret (HS256)
> mode from design/46 stays; the two are selected by config.

## What was built

### `sbi_core::oauth` — ES256 primitives

- **`Es256Key`** (P-256 / `p256` crate) — the NRF's private signing key.
  `generate()` (random scalar via `getrandom`; `kid` = hex of SHA-256 over the
  public point), `mint(claims)` → an **ES256 JWT** (JOSE 64-byte r‖s signature),
  `public_jwk()` / `jwks()`.
- **`Jwk` / `Jwks`** — the public EC key wire format (`kty:EC, crv:P-256, x, y, kid,
  alg:ES256, use:sig`); `Jwk::verifying_key()` reconstructs the P-256 key.
- **`validate_es256(token, aud, jwks, now)`** — select the key by header `kid`,
  verify the ES256 signature, then expiry + audience (shares `AccessTokenClaims` /
  `TokenError` with HS256).
- **`issue_token_es256`** mirrors `issue_token`, sharing `token_claims`.

### Authorization server (NRF, `nnrf`)

- `NrfStore` gains **`with_signing_key(Es256Key)`**; the token endpoint prefers
  ES256 when a key is set (`issue_token_es256`), else HS256. New **`GET /oauth2/jwks`**
  serves the NRF's public JWKS (empty otherwise).
- `nf-nrf`: `RADIAN_SBI_OAUTH=asymmetric` → generate a keypair + sign ES256 + serve
  JWKS; else `RADIAN_SBI_SECRET` → HS256; else open.

### Resource server (`oauth::protect`)

- **`TokenVerifier`** = `Shared(secret)` (HS256) | `Jwks(JwksCache)` (ES256). The
  **`JwksCache`** fetches the NRF's JWKS lazily and caches it, refetching once on a
  signature failure (key rotation). `protect` now takes an `Option<TokenVerifier>`
  and verifies **async**.
- **`verifier(nrf_base)`** builds it from config (asymmetric → JWKS, else shared,
  else `None`). The `protect` layer moved out of `nudr::router` into **`nf-udr`**
  (where the NRF base for JWKS is configured); `nf-udr` applies it at deployment.

### Clients

- Unchanged — `TokenSource` relays NRF-issued tokens (opaque to the client).
  `client_tokens_enabled()` (either mode on) replaces the shared-secret-only check
  so the UDM attaches tokens in asymmetric mode too.

## Why it matters

HS256's shared secret authenticates *membership in the core* but any holder — every
resource server — could **mint** a token. With ES256 the signing key lives only at
the NRF; a resource server holds only the **public** key (via JWKS) and can verify
but not forge. This is the TS 33.501 §13.4 posture. **Confidentiality** still rides
cleartext until **mutual TLS** — the remaining hardening slice.

## Verification

- `cargo test --workspace --exclude bdd` — green (114 tests). New:
  - `oauth::es256_mint_then_validate_roundtrips` — ES256 mint ↔ verify (+ JWK JSON
    round trip, expiry, audience).
  - `oauth::es256_rejects_another_keys_signature` — a token minted by one key fails
    against a different key's JWKS (the property a shared secret lacks); tamper → fail.
  - `nudr::asymmetric_udr_verifies_against_nrf_jwks` — **env-free end-to-end**: a real
    NRF (ES256 key, `/oauth2/token` + `/oauth2/jwks`) + a UDR verifying via
    `JwksCache`; a tokenless client 401s, an NRF-token-bearing client is authorized,
    and a **self-signed** (UDR-forged) token is rejected.
  - design/46's HS256 `protected_udr_requires_a_valid_access_token` still green.
- **BDD 5 scenarios / 25 steps green** — default open SBI, unaffected.
- **Live (real binaries, asymmetric mode)**: the NRF serves an EC P-256 JWKS; a
  tokenless UDR call → **401**; an NRF-minted **ES256** token (`kid` matching the
  JWKS) → **404** (authorized through the JWKS-verifying layer, no record). Confirms
  the private-sign / public-verify chain across the real NF binaries.

## Known limitations / next steps

- **Mutual TLS** — tokens (and everything) still ride cleartext h2c; asymmetric
  signing gives integrity/identity, not confidentiality.
- **Key rotation / multiple kids** — the NRF holds one key generated at startup (a
  restart invalidates outstanding tokens; TTL is 1 h). A rollover set + persisted
  keys are follow-ups.
- **Only the UDR is protected** (the exemplar) — extending `protect` to the UDM /
  NRF-mgmt / AUSF / SMF / AMF-callback is mechanical.
