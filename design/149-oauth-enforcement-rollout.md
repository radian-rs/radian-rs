# SBI OAuth2 enforcement: rollout to the remaining producers (design/138 G1)

> Built 2026-08-11 on branch `g1-enforcement`. Advances **G1** from
> [138](138-open5gs-gap-survey.md). The OAuth2 **mechanism** already landed on
> `main` (design/46/55 — `oauth::protect`, `TokenSource`, HS256 + ES256/JWKS
> validation), but server-side enforcement was wired into **only the UDM and
> UDR**. This slice extends `protect` to the six remaining producer NFs. The
> **consumer-side** token attachment for the newly-protected edges is the
> companion follow-up (§Follow-ups) — enumerated, not yet wired.

## The gap

`oauth::protect(router, nf_type, verifier)` rejects any request without a valid
NRF-issued Bearer token whose audience is `nf_type` — **when a verifier is
configured**; with SBI security off it returns the router unchanged (open SBI,
the dev-phase default). On `main` only the subscriber-data path enforced it:

| NF | `oauth::protect` on `main` |
|----|:--:|
| UDM, UDR | ✅ |
| **AMF, SMF, AUSF, PCF, CHF, NSSF** | ❌ |
| NRF, NEF | intentionally open (see D2) |

So with SBI security enabled, the AMF callback surface, the SMF's
Nsmf_PDUSession, the AUSF's Nausf_UEAuthentication (which returns Kseaf), and the
PCF/CHF/NSSF services would all still answer **unauthenticated** callers — the
token mechanism existed but guarded almost nothing.

## What this slice does

Wraps each of the six producers' routers with `oauth::protect(..., "<NF>",
oauth::verifier(&nrf_base))`, mirroring the UDM exactly:

- **AUSF** — audience `AUSF` (drives 5G-AKA, returns Kseaf).
- **SMF** — audience `SMF` (Nsmf_PDUSession; the AMF is the caller).
- **PCF** — audience `PCF` (Npcf SM- and AM-policy).
- **CHF** — audience `CHF` (Nchf converged charging).
- **NSSF** — audience `NSSF` (Nnssf slice selection).
- **AMF** — audience `AMF` (the namf-callback surface).

Each is backward-safe: `verifier(&nrf_base)` is `None` unless `RADIAN_SBI_SECRET`
(HS256) or `RADIAN_SBI_OAUTH=asymmetric` (ES256) is set, so with SBI security off
the router is untouched — proven by BDD staying 45/45.

## Decisions

- **D1 — audience-only enforcement**, matching the `protect` the audit work
  shipped. `require_token` validates signature + expiry + audience; it does not
  yet check per-service **scope**. Introducing scope granularity would change the
  `protect` signature and the token-claim contract for all NFs at once, so it is
  deferred to its own slice rather than diverging one NF here (§Follow-ups).
- **D2 — NRF and NEF stay open.** The NRF's `/oauth2/token` endpoint *is* how a
  client obtains a token — protecting it would be circular; its discovery surface
  is a separate hardening decision. The NEF is the northbound (AF-facing) edge
  with its own auth story. Both are deliberately out of this slice.
- **D3 — an HTTP-level test of `protect` itself.** The existing tests covered the
  token primitives (`mint`/`validate`/`validate_es256`); none drove the actual
  middleware. `protect_enforces_audience_and_is_open_without_a_verifier` wraps a
  trivial router and asserts: no token → 401, wrong-audience token → 401,
  correct-audience token → 200, and **no verifier → open (200)**. This proves the
  primitive the whole rollout leans on, including the backward-safe path.

## Tests

- `sbi-core` — `protect_enforces_audience_and_is_open_without_a_verifier` (new,
  the middleware end-to-end via `oneshot`); the existing token/JWKS tests
  unchanged. `sbi-core` 56 green.
- `cargo test --workspace --exclude bdd` — all green, no new warnings; clippy
  clean on `sbi-core` + all six NFs (remaining warnings are pre-existing dep code).
- **BDD 45/45, 501/501** — the rollout is a no-op under open SBI (the default and
  the BDD path), so the full datapath/registration mesh is unaffected.

## Follow-ups (the rest of G1)

- **Consumer-side token attachment** — the balancing half. With SBI security on,
  every caller of a now-protected producer must present a token, or the secured
  mesh half-opens. Today only some edges attach one (AUSF→UDM, UDM→UDR, PCF→UDR,
  AMF→UDM). Still needed:
  - **AMF → AUSF** (`auth::AmfAuth`), **AMF → SMF** (`pdu_session::AmfSmf`),
    **AMF → PCF** (AM-policy), **AMF → NSSF**.
  - **SMF → PCF** (SM-policy), **SMF → CHF** (charging).
  This needs `with_tokens` constructors on the `nausf` / `nsmf` / `npcf` / `nchf`
  / `nnssf` clients, wired from each consumer's `TokenSource`. Only once this
  lands is `RADIAN_SBI_SECRET`-on an end-to-end working configuration — worth a
  BDD scenario that runs the whole flow **with** security on.
- **Per-scope authorization** (D1) — validate the token's `scope` against the
  invoked service operation, not just the audience.
