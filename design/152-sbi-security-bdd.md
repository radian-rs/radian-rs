# Secured-mesh BDD: OAuth2 end-to-end across processes (design/138 G1)

> Built 2026-08-11 on branch `bdd-sbi-security`. Closes the headline follow-up of
> [150](150-oauth-consumer-tokens.md): the **first cross-process test of the
> secured SBI mesh**. Producers enforcing tokens ([149](149-oauth-enforcement-rollout.md))
> and consumers attaching them ([150](150-oauth-consumer-tokens.md)) were each
> unit-tested; nothing had run the two **together**, over real NF processes, with
> SBI security actually on.

## The gap

`RADIAN_SBI_SECRET`-on was an untested configuration ([150](150-oauth-consumer-tokens.md)
D4). The unit tests prove `protect` 401s an untokened call and a `with_tokens`
client is authorized against one producer — but not that the *whole* control
plane still completes when **every** NF enforces and every caller must present a
token. A single missing token-attachment on any edge would 401 mid-registration,
and no test would have caught it.

## What this slice does

A `@sbi_security` BDD feature that brings the (scripted, loopback) core up with
SBI security on and runs a full **registration + PDU-session establishment** —
reaching an assigned UE IP. That path exercises every protected edge:

```
AMF→AUSF   AMF→UDM   AMF→NSSF   AMF→SMF   AMF→PCF(AM)
SMF→PCF(SM)   SMF→CHF   SMF→UDM   AUSF→UDM   UDM→UDR
```

so reaching an IP is proof the token flow closes on all of them.

### The mechanism

Security is injected at the one chokepoint every NF spawn already funnels through,
`spawn_core_as`: when a serial-safe `SBI_SECURED` flag is set, it appends
`RADIAN_SBI_SECRET=<shared hex>` to that NF's environment. The flag is set by a new
`When I start the secured radian core` step and cleared by `a clean test
environment`, the plain `I start the radian core`, and `I stop the radian core` —
so a secured core can never leak into another feature. The suite is serial
(`max_concurrent_scenarios(1)`), so a process-global flag is safe. No per-NF spawn
call site changed.

With the secret set on all of them: the **NRF** enables `/oauth2/token` and issues
HS256 tokens to any registered NF; each **producer**'s `oauth::verifier` becomes
`Some`, so `protect` enforces; each **consumer**'s `client_tokens_enabled()` turns
true, so it fetches and attaches a token. (The NRF's mTLS cert-binding check is
skipped under cleartext SBI, which is how BDD runs — the shared secret is the
whole trust basis here.) The UPF has no SBI and ignores the variable.

The run's logs confirm it was genuinely secured, not silently open: the NRF logs
`SBI security enabled … tokens at /oauth2/token`, all eight producers log
`… protected by OAuth2 (audience …)`, and no call 401s.

## Decisions

- **D1 — shared-secret (HS256), not asymmetric.** One env var, no key
  distribution — the minimal thing that turns the whole mesh secured. The clients
  and `protect` are signing-mode agnostic (they relay/verify opaque NRF tokens),
  so ES256/JWKS is a config-only variant worth its own scenario later, not a
  reason to complicate this one.
- **D2 — inject at `spawn_core_as`, gated by a flag.** The alternative — threading
  a `secret: Option<&str>` through `start_core_inner` and its ~13 spawn calls —
  touches every call site for no behavioural gain. One guarded `env.push` at the
  shared chokepoint covers all NFs and keeps the diff to the harness seam.
- **D3 — the scripted (loopback) tier, ending at IP assignment.** The scripted
  core needs no netns and no external UE, so the secured scenario is fast and
  hermetic. The datapath ping (UPF N6 TUN) exercises no additional SBI edge, so
  the scenario stops at "assigned an IP in 10.45.0.0/16" — the point at which
  every protected control-plane edge has already succeeded.
- **D4 — flag reset in three places.** `clean test environment` (authoritative,
  every feature opens with it), plus the plain start and stop steps, guarantee no
  secured state bleeds into an unsecured feature regardless of run order.

## Tests

- New feature `bdd/tests/features/sbi_security.feature` (`@sbi_security`,
  2 scenarios: the secured register+session, and teardown).
- Full BDD suite **47/47 scenarios, 518/518 steps** (was 45/501) — the new
  feature passes and nothing regressed; the open-SBI features are untouched
  because `SBI_SECURED` defaults off.

## Follow-ups

- **Asymmetric (ES256/JWKS) variant** (D1) — a second scenario with
  `RADIAN_SBI_OAUTH=asymmetric`, proving the JWKS-fetch verification path across
  processes.
- **A negative scenario** — assert that a deliberately *unregistered* or
  secret-mismatched NF is refused, so the test also proves enforcement bites (the
  unit tests cover this per-client; a process-level version would be belt-and-braces).
- **Per-scope authorization** ([149](149-oauth-enforcement-rollout.md) D1) — once
  `protect` checks scope, extend this feature to prove a wrong-scope token is
  refused end-to-end.
