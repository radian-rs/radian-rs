# SBI OAuth2 Access Tokens — Implementation Notes

> Built 2026-07-03 on branch `feat/sbi-oauth`. First slice of **SBI security
> hardening** (TS 33.501 §13), the item every prior `# Security` note deferred.
> The SBI has been cleartext-h2c and **unauthenticated** since [04](04-sbi-spine-nrf.md);
> this adds OAuth2 access-token authorization with the **NRF as the authorization
> server**, enforced on the UDR.

Note: this is the intra-core SBI — free-ran-ue speaks only N2/N3, so hardening
SBI does not touch the live interop (the `@sim` ping is unaffected).

## What was built

- **`sbi_core::oauth`** — HS256 JWTs (hand-rolled over `hmac`/`sha2`/`base64`):
  `AccessTokenClaims {iss, sub, aud, scope, iat, exp}`, `mint` / `validate`
  (signature, expiry, audience). `TokenError` distinguishes malformed / bad-sig /
  expired / wrong-audience.
- **Authorization server** (`nnrf`): `POST /oauth2/token` (Nnrf_AccessTokenRequest,
  TS 29.510 §6.3) — `client_credentials` grant; issues a token only to a
  **registered** NF (ties issuance to the registry). The signing secret lives on
  the `NrfStore` (`with_secret`, from `oauth::sbi_secret()`); absent → the
  endpoint is disabled (`404`).
- **Resource-server guard** (`oauth::protect(router, nf_type, secret)`): an axum
  layer that requires a valid Bearer token with audience `nf_type` — added only
  when a secret is configured (otherwise the router is returned unchanged: open
  SBI). Applied to the **UDR** (audience `UDR`).
- **Secretless client** (`oauth::TokenSource`): fetches + caches NRF-issued
  tokens for a target NF; `UdrClient::with_tokens` attaches a `UDR` token to
  every Nudr call. The UDM uses it (with a stable instance id shared between its
  NRF registration and its token requests) when a secret is configured.

## Trust model (and its deliberate limits)

The token is signed with a **shared secret** (`RADIAN_SBI_SECRET`) held by the
NRF (signer) and the UDR (verifier); clients are secretless. This authenticates
**membership in the trusted core** and enforces **audience / scope / expiry** — a
request without a valid `UDR` token is rejected. It does **not** provide per-NF
*unforgeable* identity (any secret holder could mint a token) and tokens ride
**cleartext** until TLS. The next hardening slices: **asymmetric signing** (NRF
private key, NFs verify via its public key / JWKS) and **mutual TLS**. Documented
in `sbi_core::oauth`'s module header.

**Opt-in.** No secret → `sbi_secret()` is `None`, `protect` adds no layer, the
token endpoint 404s: the SBI is open, exactly as before. Set `RADIAN_SBI_SECRET`
(shared across NRF + protected NFs) to turn enforcement on.

## Verification

- `cargo test --workspace --exclude bdd` — green (26 suites). New:
  - `oauth`: mint↔validate round trip (case-insensitive audience); rejects
    expiry / wrong-audience / wrong-secret / tampered payload / malformed;
    `issue_token` targets the requested NF.
  - `nudr::protected_udr_requires_a_valid_access_token` — env-free, end-to-end: a
    UDR protected with an injected secret **401s a tokenless client**, a
    `UdrClient` carrying an **NRF-issued token succeeds** (404/None and a real AV
    read), and an **unregistered client is refused a token** (→ 401).
- **BDD, 5 scenarios / 25 steps green** — no secret set, SBI open, unchanged.
- **Live secured run** (`RADIAN_SBI_SECRET` set on NRF/UDR/UDM): a tokenless
  `curl` to the protected UDR returns **401** (UDR logs "missing Bearer access
  token nf_type=UDR"); the NRF logs "issued SBI access token … target=UDR"; and
  the **full free-ran-ue registration + PDU session completes** — the UDM's AV /
  SDM / UECM calls through the *protected* UDR all carried valid tokens.

## Known limitations / next steps

- **Only the UDR is protected** — the exemplar (subscriber data + the withdrawal
  SSRF vector). Extending `protect` + token-bearing clients to the UDM, NRF-mgmt,
  AUSF, SMF, and the AMF callback is mechanical follow-up.
- **Shared-secret / no TLS** — see the trust-model limits above; asymmetric
  signing and mutual TLS are the remaining hardening slices.
- **Coarse scope check** — validation checks audience (target NF type), not
  per-service scope granularity.
