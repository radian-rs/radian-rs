# Secured-mesh BDD: asymmetric mode, and the bug it caught (design/138 G1)

> Built 2026-08-11 on branch `sbi-security-asymmetric`. Extends the secured-mesh BDD
> ([152](152-sbi-security-bdd.md)) to run in **both** SBI signing modes — shared
> secret (HS256) and asymmetric (ES256 + JWKS) — closing the last G1 nicety. The
> asymmetric run immediately paid for itself: it caught a real consumer bug
> (§The bug) that the HS256 run structurally could not.

## What this slice does

The `@sbi_security` feature becomes a **Scenario Outline** over `mode ∈ {shared,
asymmetric}`, so the full register + PDU-session flow runs once per mode. A single
`AtomicU8` `SBI_MODE` (0 = off, 1 = shared, 2 = asymmetric) replaces the earlier
`SBI_SECURED` bool; `spawn_core_as` maps it to the per-NF env:

- **shared** → `RADIAN_SBI_SECRET=<hex>` on every NF (as before);
- **asymmetric** → `RADIAN_SBI_OAUTH=asymmetric` on every NF. No secret is
  distributed: the NRF generates its own ES256 key and publishes the public half
  at `/oauth2/jwks`; each resource server fetches it (`JwksCache`) and verifies
  ES256 signatures. This is the TS 33.501 §13.4 posture — a compromised resource
  server cannot mint tokens.

The step is now `When I start the radian core with SBI security "(shared|asymmetric)"`.
Both modes reuse the identical flow and the per-scope enforcement from
[154](154-oauth-per-scope-authz.md); the asymmetric token carries the same claims
(both issuance paths share `token_claims`), so audience + scope enforcement is
signing-mode agnostic.

## The bug (why asymmetric earned its keep)

The asymmetric run failed at the AM-policy step: the UE's RFSP came back `3` (the
PCF's local default) instead of `5` (the UDR-provisioned value). The logs showed
the PCF's `Nudr am-policy-data` fetch going out **without a Bearer token** and the
UDR rejecting it `401`, so the PCF fell back to local policy.

Root cause: `nf-pcf` built its token-aware UDR client only
`if oauth::sbi_secret().is_some()` — i.e. it keyed "should I attach tokens?" on the
**shared secret specifically**, not on "is SBI security on?". In asymmetric mode
there is no shared secret (`RADIAN_SBI_OAUTH=asymmetric` sets none), so the PCF
silently used a tokenless UDR client and every UDR call 401'd.

The HS256 run could never surface this — with a secret set, `sbi_secret().is_some()`
is true and the client is token-aware. Only the asymmetric run, which is exactly
"SBI security on but no shared secret", exposed the wrong predicate.

Fix: gate on `oauth::client_tokens_enabled()` (`asymmetric_enabled() ||
sbi_secret().is_some()`) — the canonical "a client should attach tokens" test that
every other consumer already used (AMF/AUSF/UDM/SMF). One-line change; the PCF now
tokens its UDR calls in both modes.

## Decisions

- **D1 — Scenario Outline, not a second feature.** One flow, two `Examples` rows;
  each row is an independent scenario that `clean`s first (serial suite, fixed
  ports). No step duplication, and adding a third mode later is one row.
- **D2 — keep the bugfix in this slice.** The asymmetric test and the fix that
  makes it pass belong together: the test is the fix's regression guard, and
  landing the test without the fix would knowingly ship red.
- **D3 — `client_tokens_enabled()` is the one true predicate.** `sbi_secret()`
  answers "is HS256 configured?", which is not the same question as "should a
  client present tokens?". The audit of `grep sbi_secret().is_some()` found only
  the PCF misusing it for client behaviour (the NRF's use is a server-side log
  guard in its HS256 branch — correct).

## Tests

- `@sbi_security` is now **3 scenarios** (shared, asymmetric, teardown); full BDD
  **48/48 scenarios, 532/532 steps** (was 47/518). The asymmetric run logs
  `SBI security enabled (asymmetric ES256) — JWKS at /oauth2/jwks` and no longer
  logs the am-policy 401 fallback.
- `nf-pcf` clippy clean; `cargo test --workspace --exclude bdd` green.

## Follow-ups

- A **negative** secured scenario (a wrong-scope / unregistered NF refused
  end-to-end) — the unit tests cover it; a process-level check would be
  belt-and-braces.
- Audit remaining `sbi_secret()` call sites periodically as new consumers land, to
  keep the `client_tokens_enabled()` invariant (a lint or a shared helper could
  enforce it).
