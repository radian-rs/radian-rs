# SBI OAuth2: per-scope authorization (design/138 G1)

> Built 2026-08-11 on branch `oauth-per-scope`. Completes the **G1 authorization
> model**: [149](149-oauth-enforcement-rollout.md) made producers check a token's
> **audience**, but not its **scope** — so a `UDM`-audience token authorized *any*
> Nudm operation regardless of what the NRF actually granted. This closes the last
> named G1 gap ([138](138-open5gs-gap-survey.md) §first-wave-status), and the
> secured-mesh BDD ([152](152-sbi-security-bdd.md)) now proves the full model —
> audience **and** scope — end-to-end across processes.

## The gap

`oauth::protect` validated signature + expiry + audience. The token's `scope`
claim — the space-separated list of service names the NRF granted the client
(e.g. `nudm-ueau nudm-sdm nudm-uecm`) — was carried through issuance and
validation but **never enforced**. So a client granted only `nudm-sdm` could call
`/nudm-uecm/...` on the same UDM: audience-correct, scope-ignored. The whole point
of scoped tokens (least privilege per service) was unrealised.

## What this slice does

One check added to the `require_token` middleware, after audience (and the F4
`cnf` binding): the **first path segment must appear in the token's scope**.

```
service = first segment of the request path        // e.g. "/nudm-sdm/v2/…" → "nudm-sdm"
reject unless  service ∈ claims.scope              // space-separated granted service names
```

This is general and needs no per-route configuration, because SBI service APIs
are uniformly `/{serviceName}/v{n}/...` (TS 29.501) and the scope the NRF grants
*is* the list of `serviceName`s — the path segment and the scope entry are the
same token. A client that asked for `nsmf-pdusession` gets a token scoped to it,
and only `/nsmf-pdusession/...` paths clear the check.

The consumers already request the right scopes (design/150): each typed client's
`bearer` requests a token whose scope lists exactly the services it calls
(`NssfClient` → `nnssf-nsselection nnssf-nssaiavailability`, `NudmClient` → all
three `nudm-*`, etc.), so no consumer change was needed — the enforcement simply
started biting on the existing grants.

## Decisions

- **D1 — derive the required scope from the path, don't configure it.** The
  alternative (a scope annotation per route) is redundant: the URL's service
  segment already names the service, and TS 29.510 scopes are service names. One
  rule covers every NF and every route, present and future.
- **D2 — callback surfaces are audience-only (exempt from the scope check).** A
  producer's `n<nf>-callback` routes receive *notifications*, not service
  operations; their senders (a notifying PCF/UDR) don't request a per-service
  scope. Enforcing a service scope there would demand a callback-scope grant the
  callers don't carry, breaking notifications for no security gain — the audience
  check still guards them. Segments ending `-callback` are skipped.
- **D3 — case-insensitive membership, empty-path allowed.** Matches the existing
  case-insensitive audience comparison; a root/empty path (no service segment)
  isn't a service call and isn't scope-checked.
- **D4 — proven through the secured BDD, not just units.** The
  [152](152-sbi-security-bdd.md) run now exercises scope enforcement on every
  edge: it still reaches an assigned IP, and no call logs
  `scope does not authorize` — so every consumer's grant genuinely covers the
  producer path it hits, across real processes.

## Tests

- `sbi-core` `protect_enforces_audience_scope_and_is_open_without_a_verifier`
  (extended): over a realistic `/nausf-auth/v1/...` path — no token → 401, wrong
  audience → 401, **right audience + non-covering scope (`nudm-sdm`) → 401**,
  right audience + covering scope → 200, multi-service scope including it → 200,
  no verifier → open. Main's F4 `cnf` test repointed to a real `/nudr-dr/...` path
  so it exercises only the binding.
- The producer token tests (`protected_{udm,udr,nssf}_...`) still pass unchanged —
  their client scopes already cover their paths.
- `sbi-core` 65 green; `--workspace --exclude bdd` green, clippy clean on
  `oauth.rs`; **secured BDD 152 still 47/47, 518/518** with scope now enforced.

## Follow-ups

- **Asymmetric (ES256/JWKS) variant** of the secured BDD — scope is signing-mode
  agnostic (it reads the validated claims either way), so this only adds coverage
  of the JWKS path, not new scope logic.
- **A negative secured scenario** — a deliberately wrong-scope token refused
  end-to-end across processes (the unit test covers it; a process-level version
  would be belt-and-braces).
