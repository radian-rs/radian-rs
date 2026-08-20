# SBI OAuth2: consumer-side token attachment (design/138 G1)

> Built 2026-08-11 on branch `g1-consumer-tokens`. The balancing half of
> [149](149-oauth-enforcement-rollout.md): that slice made six producers **reject**
> untokened calls under SBI security; this one makes their **callers attach** a
> token, so `RADIAN_SBI_SECRET`-on is a working end-to-end configuration rather
> than a half-open mesh. Closes the consumer half of **G1**
> ([138](138-open5gs-gap-survey.md)).

## The gap

After [149](149-oauth-enforcement-rollout.md), a producer with SBI security on
401s any caller without a valid `<NF>`-audience token. But most callers weren't
attaching one — only the UDM/UDR edges were tokened (design/137 F3). So enabling
`RADIAN_SBI_SECRET` would have **broken** the AMF→{AUSF,SMF,PCF,NSSF} and
SMF→{PCF,CHF} calls: the enforcement was in place, the credentials weren't.

Every producer client already had the `NudmClient` template — a `tokens:
Option<Arc<TokenSource>>` field, a `with_tokens` constructor, and a `bearer`
helper that requests an `<audience>`-scoped token from the NRF and attaches it.
The five other clients just hadn't grown it.

## What this slice does

**1. The five producer clients** (`sbi-core`) gain the same three things as
`NudmClient` — a `tokens` field, `with_tokens`, and an `async fn bearer` that
wraps each request builder — for their audience/scope:

| client | audience | scope |
|--------|----------|-------|
| `AusfClient` | AUSF | `nausf-auth` |
| `ChfClient` | CHF | `nchf-convergedcharging` |
| `NssfClient` | NSSF | `nnssf-nsselection nnssf-nssaiavailability` |
| `PcfClient` (SM-policy) | PCF | `npcf-smpolicycontrol` |
| `AmPolicyClient` (AM-policy) | PCF | `npcf-am-policy-control` |

**2. The consumers** thread a `TokenSource` into every construction of those
clients, via a small token-aware helper per edge (mirroring the existing
`udm_client`):

- **AMF** — one shared `AMF_TOKENS` source (generalised from the former
  `AMF_UDM_TOKENS`; one source caches a token per target) feeds `ausf_client`
  (auth.rs), `am_policy_client`, and `nssf_client`. The **AMF→SMF** path builds
  requests inline (not through a typed client), so it uses a new
  `oauth::with_bearer(rb, &tokens, aud, scope)` helper that attaches a token to a
  `reqwest::RequestBuilder` — which nf-amf cannot name in a signature, having no
  direct `reqwest` dependency.
- **SMF** — `pcf_client` / `chf_client` helpers (mirroring `udm_client`) build a
  per-call `TokenSource` from `nrf_base` + `SMF_INSTANCE_ID`. For the two
  best-effort spawned tasks (charging release, SM-policy delete) the token-aware
  client is built **before** `tokio::spawn` and moved in, so the spawned future
  needs no `nrf_base`.

All of it is a no-op with SBI security off: `client_tokens_enabled()` is false,
so every helper returns a plain `new()` client and no token is fetched.

## Decisions

- **D1 — one `TokenSource` per consumer, not per edge.** A `TokenSource` caches a
  separate token per (target NF, scope), so a single AMF source serves UDM, AUSF,
  SMF, PCF, NSSF. Fewer moving parts, one NRF client-identity.
- **D2 — `oauth::with_bearer` for the inline AMF→SMF path.** The typed clients own
  a `bearer` method, but `AmfSmf` posts inline through `sbi_core::sbi_client()`.
  Rather than give nf-amf a `reqwest` dependency just to name `RequestBuilder`, a
  sbi-core free function wraps the builder — the client-side dual of `protect`.
- **D3 — build-before-spawn for the SMF's best-effort tasks.** The charging-release
  and policy-delete tasks only carried the target base. Building the token-aware
  client before `spawn` (it is `Send`) keeps `nrf_base` out of the spawned future
  and avoids threading it through call chains.
- **D4 — verified end-to-end at the crate level, not (yet) in BDD.** A full
  security-on BDD run means injecting a shared secret into every NF spawn — a
  harness-wide change worth its own slice (§Follow-ups). The token→enforcement
  flow is proven here by a focused integration test instead.

## Tests

- `sbi-core` `protected_nssf_requires_a_valid_access_token` (new) — stands up an
  NRF (secret + a registered `amf-1`) and a `protect`-ed NSSF, then asserts a
  tokenless `NssfClient::new` is **401** and a `NssfClient::with_tokens("amf-1")`
  is **authorized**. The end-to-end proof that a consumer's attached token clears
  the producer's enforcement, over the same flow the existing
  `protected_udm_requires_a_valid_access_token` covers for the UDM.
- `sbi-core` 61 green (incl. the four agents' client edits, exercised by the
  existing client tests); `cargo test --workspace --exclude bdd` green, no new
  warnings; clippy clean on `sbi-core`, `nf-amf`, `nf-smf`.
- **BDD 45/45, 501/501** — unchanged: with SBI security off every helper returns a
  plain client, so the mesh is byte-for-byte as before.

## Follow-ups

- **A security-on BDD scenario** (D4) — set `RADIAN_SBI_SECRET` on every NF spawn
  in the harness and run the full registration + PDU-session flow, the first test
  of the secured mesh end-to-end across processes. Now unblocked: producers
  enforce (149) and consumers attach (this slice).
- **Per-scope authorization** — validate the token's `scope` against the invoked
  operation, not just the audience ([149](149-oauth-enforcement-rollout.md) D1).
- **Asymmetric (ES256) mode** across the mesh — the clients are signing-mode
  agnostic (they relay opaque NRF tokens), so this is a deployment/config matter,
  but worth an explicit test.
