# Security Audit — Findings

> Audited 2026-08-08 on branch `audit` (identical to `main` at merge of #135).
> A full-codebase security review of the radian-rs 5GC (~65k LOC, 63 Rust
> files) across five domains — crypto/auth, untrusted-input parsers,
> SBI/TLS/OAuth, AMF/CBL admission control, and the user-plane/session
> datapath. This doc records the findings; it is a review artifact, not a
> design. Each **HIGH** was verified by hand against the cited code.

## Overall posture

The **foundations are sound**, and that shapes where the risk actually lives:

- **No `unsafe`** anywhere in the tree.
- **CSPRNG (`getrandom`)** for every security-relevant value — RAND
  (`sbi-core/src/lib.rs:162`), GCM nonces + KEK (`subscriber-db/src/lib.rs:468,187`),
  P-256 scalars (`oauth.rs:152`). No predictable PRNG for secrets.
- **Credentials sealed at rest** — K/OPc under AES-256-GCM, SUPI bound as AAD,
  random 12-byte nonce, 0600 file; K never crosses the SBI wire (ARPF co-hosted
  in UDR).
- **Real mutual TLS** — rustls/ring with `WebPki{Client,Server}Verifier`, a real
  root store, required+verified client certs, CRL enforcement, no accept-all
  verifier, no `alg:none` path.
- **The parsers are clean** — the single largest attack surface (NGAP / NAS /
  F1AP / RRC / GTP-U / PFCP / PDCP decode of attacker-controlled bytes) has
  **no reachable memory-safety or panic-DoS bug**, verified site-by-site; the
  generated PER decoders delegate to `asn1-codecs 0.7.2`, which returns `Err`
  (never panics) and bounds its allocations.

The exposure is therefore **not** memory corruption or broken primitives. It is
(a) missing protocol-security controls (replay/freshness), (b) incomplete SBI
authorization coverage, (c) user-plane anti-spoofing gaps, and (d) unbounded
state and predictable identifiers on unauthenticated network segments.

## Findings summary

| # | Sev | Finding | Location | Reachability |
|---|-----|---------|----------|--------------|
| F1 | **HIGH** ✅ | NAS integrity has no COUNT monotonicity → message replay | `nas/src/lib.rs:1790` | Malicious gNB / on-path N2 |
| F2 | **HIGH** ✅ | NEF northbound fully unauthenticated (external trust boundary) | `nf-nef/src/main.rs:76`, `nnef.rs:266` | External AF / anyone reachable |
| F3 | **HIGH** ✅ | UDM serves auth vectors (K_AUSF) + subscriber data with no token check | `nf-udm/src/main.rs:55`, `nudm.rs:383` | Plaintext: network; mTLS: any core cert |
| F4 | **HIGH** ✅ | NRF issues OAuth tokens not bound to caller; scope never enforced | `nnrf.rs:308`, `oauth.rs:305,434` | Any registrable/core peer |
| F5 | **HIGH** ✅ | User-plane anti-spoofing is family-conditional → source spoof onto N6 | `n6/src/lib.rs:98-109` | **Any ordinary subscriber** |
| F6 | **HIGH** ✅ | AMF `UeContext` map unbounded; abandoned registrations never evicted → OOM | `nf-amf/src/main.rs:758,3084` | Unauthenticated N2 peer |
| F7 | **HIGH** ◐ | N3 GTP-U + N4 PFCP trust the network; predictable TEID/SEID → cross-session injection, downlink hijack | `nf-upf/src/main.rs:277`, `pfcp/src/lib.rs:838,1568` | N3/N4 reachability (isolation assumption) |
| F8 | MED | AKA SQN rollback via replayed AUTS (no freshness/monotonicity check) | `subscriber-db/src/lib.rs:277,624`, `aka/src/lib.rs:191` | Reach UDM/UDR resync |
| F9 | MED | Non-constant-time compare of RES*/XRES*/HXRES*/MAC-S | `nausf.rs:180`, `amf/auth.rs:128`, `aka/src/lib.rs:196` | Timing side channel |
| F10 | MED | AUSF auth context not invalidated on failed RES* → AV reuse / online guessing | `nausf.rs:171-196` | Amplifies F9 |
| F11 | MED | SUPI confidentiality absent — only null-scheme SUCI; UDM never deconceals | `nudm.rs:388`, `nas/src/lib.rs:1625` | Passive IMSI capture |
| F12 | MED | Insecure-by-default transport: cleartext h2c, no auth, bound `0.0.0.0` | `sbi-core/src/lib.rs:109`, `tls.rs:41` | Zero-config default |
| F13 | MED | SSRF: PCF/UDM notification fan-out follows redirects, URIs unvalidated | `npcf.rs:761`, `npcf_am.rs:265`, `nudm.rs:229` | Reach unprotected NF |
| F14 | MED | PCF/AUSF/CHF/NSSF/SMF routers unprotected; PCF token-gating bug | `nf-{pcf,ausf,chf,nssf,smf}/src/main.rs`; `nf-pcf/src/main.rs:51` | Network / core |
| F15 | MED | Predictable sequential 5G-TMSI/GUTI (= counter, cleartext) → UE tracking | `nf-amf/src/main.rs:107,3842` | Passive observer |
| F16 | MED | No egress/destination filtering on uplink → UE can reach core/mgmt IPs | `n6/src/lib.rs:82-123` | Any subscriber |
| F17 | MED | UE IPs allocated sequentially, never released → exhaustion, restart collisions | `smf/pdu_session.rs:532,1873` | Any subscriber |
| F18 | MED | Auth-flood amplification: one InitialUEMessage → NRF+AUSF+UDM+UDR work | `nf-amf/src/main.rs:1710`, `auth.rs:59` | Unauthenticated N2 |
| F19 | MED | CBL decay under-counts live work under overload; no per-source fairness → starvation | `cbl.rs:210-243`, `nf-amf/src/main.rs:1665` | Malicious gNB |
| F20 | LOW | NEA0 offered as cipher fallback; no defensive `nia != 0` assert | `nf-amf/src/main.rs:87`, `nas/src/lib.rs:1745` | Policy/config |
| F21 | LOW | Long-term keys (K/OPc/KEK/derived) not zeroized | `aka/src/lib.rs:20`, `subscriber-db/src/lib.rs` | Core dump / swap |
| F22 | LOW | `GNB_LINKS` leaks per association; lock-poisoning fragility; CBL timer accumulation | `nf-amf/src/main.rs:342,824`; ~60 `lock().unwrap()` | Unauthenticated N2 |
| F23 | LOW | ES256 verify falls back to first JWK on unknown `kid`; HS256 mode + no `iss` check | `oauth.rs:257,108` | Latent on key rotation |
| F24 | LOW | No `catch_unwind` barrier at decode ingress (panic-safety inherited from ext. codecs) | decode wrappers | Latent / dep bump |

## Remediation status

Fixes land on branch `audit`; each finding's detail section carries its own status
line. Progress so far:

| # | Status | Where |
|---|--------|-------|
| F1 | **FIXED** | `crates/nas/src/lib.rs` `unprotect` — estimate-closest COUNT + reject any at/below one consumed; tests `nas_security_rejects_replay`, `nas_security_count_wraps_past_the_sn_block_boundary` |
| F6 | **FIXED** | `nf/nf-amf/src/main.rs` — registration guard timer, re-armed from last progress (T3550/T3560-style), evicts stalled in-progress contexts (releasing the CBL slot via RAII); test `registration_guard_evicts_stalled_registrations` |
| F5 | **FIXED** | `crates/n6/src/lib.rs` `uplink` — fail closed: an address-assigned session accepts only its assigned families; an unassigned-family or non-IP packet is dropped (`Uplink::UnassignedFamily`), address-less forwarding tunnels untouched; tests `uplink_drops_the_unassigned_family_on_a_single_family_session`, `uplink_dual_stack_session_accepts_both_families`; full BDD 45/501 green |
| F7 | **PARTIAL** | `crates/pfcp/src/lib.rs` — DoS sub-issue closed: the session table is capped (`DEFAULT_MAX_SESSIONS`, `set_max_sessions`, `RADIAN_UPF_MAX_SESSIONS`), a full UPF rejects further establishment with `NoResourcesAvailable`; test `session_table_is_capped_against_an_establishment_flood`. **Deferred** (see detail): unpredictable TEID/SEID, N3/N4 peer-source validation, `valid_gnb_target` RAN-prefix allowlist |
| F3 | **FIXED** | `nf/nf-udm/src/main.rs` wraps `nudm::router` in `oauth::protect(_, "UDM", verifier)`; the UDM's clients (AUSF, AMF, SMF) attach an NRF-issued `UDM` token when SBI security is on (`NudmClient::with_tokens`, `AusfState::with_tokens`). Opt-in — no change when OAuth is off. Test `protected_udm_requires_a_valid_access_token`; BDD 45/501 green |
| F4 | **FIXED** | mTLS cert-binding (RFC 8705): `tls.rs` surfaces the peer cert thumbprint; the NRF binds each registration to it and refuses to issue a token — or re-register — under a different certificate. **Plus the two deferred items:** (a) *per-consumer authorization* — `RADIAN_NRF_AUTHZ` / `with_authz_policy` / `parse_authz_policy`; `access_token` issues a token only if the requesting NF's **registered** type may target the requested `targetNfType` (deny-by-default; consumer type read from the registry, never the request body). (b) *sender-constrained tokens* — the NRF stamps the caller's cert thumbprint as the token `cnf` (`x5t#S256`), and every protected NF (`oauth::require_token`) refuses a `cnf`-bearing token unless the presenting client cert matches, so a captured token can't be replayed by a different NF. Opt-in (cleartext ⇒ no cnf, no policy). Tests `authz_policy_confines_a_consumer_to_its_targets`, `cnf_binds_a_token_to_the_presenting_certificate`, `parse_authz_policy_reads_the_grammar`, `nrf_binds_tokens_to_the_registering_client_certificate`. **Residual:** authorization is at `targetNfType` granularity; the resource server enforces audience + `cnf` but not per-service `scope` |
| F2 | **FIXED** | `crates/sbi-core/src/nnef.rs` + `nf/nf-nef/src/main.rs`. **Authentication:** with `RADIAN_NEF_AF_KEYS=af:key[,…]` (`with_af_keys`), a request must carry `Authorization: Bearer <key>` matching the key provisioned for its path `af_id` (constant-time `ct_eq`); missing/wrong key — or an AF reusing another's `af_id` — is `401` (uniform, no enumeration). **Authorization:** with `RADIAN_NEF_AF_SLA=af\|dnns\|dnais\|supis\|group` (`with_af_slas`/`parse_af_slas`, `AfSla`), `authorize_request` bounds each request to the AF's contracted DNN, DNAIs (all routes), SUPI scope (prefix), and group/any-UE permission — out-of-scope ⇒ `403`, deny-by-default (an AF with no SLA is refused). A subscription is owned by its creating `af_id`, so one AF cannot delete another's (`take_owned`). Both opt-in; unset ⇒ open (dev), warned. Tests `api_key_authenticates_the_af`, `sla_confines_an_af_to_its_contracted_scope`, `an_af_cannot_delete_another_afs_subscription`, `parse_af_slas_reads_the_env_grammar` |

All other findings are open.

## HIGH findings (detail)

### F1 — NAS integrity has no COUNT monotonicity → replay

- **Status:** ✅ **FIXED** (branch `audit`). `unprotect` now estimates the COUNT
  closest to the next-expected value (handling the 256-message SN-block wrap in both
  directions) and **rejects any COUNT at or below one already consumed** before
  advancing the receive window; a failed check no longer consumes a COUNT, so the
  retained-context re-verify path is preserved. Covered by `nas_security_rejects_replay`
  and `nas_security_count_wraps_past_the_sn_block_boundary`.

- **Class:** MAC/integrity — replay. **File:** `crates/nas/src/lib.rs:1765-1796` (`unprotect`).
- `unprotect` rebuilds the NAS COUNT from the attacker-visible 8-bit SN plus the
  locally stored high bytes (`c = (*count & !0xff) | sn`), verifies the MAC for
  that `c`, then does `*count = c + 1` with **no check that `c` exceeds the last
  accepted COUNT**. Replaying the last-accepted frame recomputes the identical
  COUNT, the MAC re-verifies, and the message is accepted again (the stored count
  doesn't even advance). TS 33.501 §6.4.4 requires COUNT-based replay rejection.
- **Exploit:** an on-path attacker / malicious gNB (N2 is unauthenticated, see F6)
  replays a captured integrity-protected uplink NAS PDU. Replaying
  `DeregistrationRequest` deregisters the victim (DoS); replaying `ServiceRequest`
  / `UL NAS Transport` drives spurious state changes. Both directions.
- **Fix:** track the highest accepted COUNT per direction with the standard 24-bit
  overflow/window estimation; reject COUNT ≤ last-accepted; advance only on a
  strictly-greater COUNT.

### F2 — NEF northbound is unauthenticated (external boundary)

- **Status:** ✅ **FIXED** (branch `audit`). The NEF now both **authenticates** the
  calling AF and **authorizes** what it may do.
  - *Authentication.* With `RADIAN_NEF_AF_KEYS=af:key[,…]` (`NefState::with_af_keys`),
    `create_subscription`/`delete_subscription` require `Authorization: Bearer <key>` whose
    key is the one provisioned for the request's path `af_id`, compared in constant time
    (`ct_eq`); a missing/wrong key — or an AF presenting another AF's `af_id` — is refused
    `401` with a uniform status so provisioned `af_id`s cannot be enumerated.
  - *Authorization (the F2 SLA).* With `RADIAN_NEF_AF_SLA` (`with_af_slas` / `parse_af_slas`,
    grammar `af_id|dnns|dnais|supis|group`), `authorize_request` bounds every request to the
    AF's contracted scope **before** translating it to the SMF/PCF/UDR: the target `dnn` must
    be granted, **every** `trafficRoutes[].dnai` must be granted (not just the first the
    handler applies), the target/group `supi`s must fall inside the AF's SUPI prefixes, and a
    group / any-UE influence is refused unless the SLA grants it — the exact verb the exploit
    used to reprogram routing network-wide. Each dimension is deny-by-default (`*` opens it),
    an AF absent from the SLA map is refused, and a violation returns `403`.
  - *Resource ownership.* A subscription records its creating `af_id`; a delete is honored
    only for the owner (`take_owned`), so one AF cannot withdraw — or probe for — another's
    influence.
  - Both controls are opt-in (unset ⇒ open dev default, logged as a warning; the default/BDD
    path is unchanged), consistent with the rest of the SBI security posture; configuring an
    SLA without keys is warned at startup, since the `af_id` selecting it is then unverified.
    Tests: `api_key_authenticates_the_af`, `sla_confines_an_af_to_its_contracted_scope`,
    `an_af_cannot_delete_another_afs_subscription`, `parse_af_slas_reads_the_env_grammar`.
    **Residual (deployment, not a code gap):** the SLA is operator-provisioned static config,
    and external-group membership (`externalGroupId` → `supis`) is still resolved by the
    caller rather than at the UDM/UDR.
- **Class:** Broken access control at the exposure boundary. **File:**
  `nf/nf-nef/src/main.rs:76-81` (serves `nnef::router` directly, never `protect`);
  handlers `crates/sbi-core/src/nnef.rs:266-323` (`create_subscription`), `404-441`.
- The NEF — documented as the northbound front door for AF traffic-influence —
  performs **zero** AF authentication and **zero** authorization of the target
  `supi`/`dnn`/`dnai`. `af_id` is an unverified path segment. mTLS cannot apply
  northbound (an external AF holds no core-CA cert).
- **Exploit:** anyone reaching `POST /3gpp-traffic-influence/v1/{af_id}/subscriptions`
  steers arbitrary subscribers' traffic to an attacker-chosen DNAI (edge
  breakout), or with `anyUeInd:true`/`externalGroupId` writes UDR
  application-influence data that every PCF applies to current and future
  sessions — reprogramming user-plane routing network-wide.
- **Fix:** require AF authentication at the NEF (OAuth2 with an AF/NEF audience,
  or API-key/mTLS northbound) and authorize each request against an AF SLA
  (allowed DNNs, DNAIs, UE scope) before translating to SMF/PCF/UDR.

### F3 — UDM serves auth vectors + subscriber data with no token check

- **Status:** ✅ **FIXED** (branch `audit`). `nf-udm` now wraps `nudm::router` in
  `oauth::protect(_, "UDM", verifier(&nrf_base))`, so with SBI security on every Nudm
  call must carry a valid `UDM`-audience access token (mirrors the UDR). Its clients
  attach one: `NudmClient` gained `with_tokens` + a `UDM` bearer, the AUSF
  (`AusfState::with_tokens`), the AMF (all Nudm calls via a token-aware `udm_client`
  helper keyed by its registered `AMF_INSTANCE_ID`), and the SMF (UECM/SDM calls via its
  own `udm_client`). Fully **opt-in** — with no OAuth configured, `verifier` is `None`,
  `protect` is a no-op, and no tokens are attached, so the default/BDD path is unchanged.
  Covered by `protected_udm_requires_a_valid_access_token`; BDD 45/501 green. *Note:* the
  strength of this (and all SBI `protect`) still depends on **F4** — the NRF binding the
  token to the authenticated caller and enforcing scope — which remains open.
- **Class:** OAuth2 (token not required) / broken access control. **File:**
  `nf/nf-udm/src/main.rs:55-59`; handlers `crates/sbi-core/src/nudm.rs:383-410`
  (`generate_auth_data`), `343-381` (SDM), `260-333` (UECM).
- Only UDR wraps its router in `oauth::protect` (`nf/nf-udr/src/main.rs:99`).
  The UDM validates nothing inbound; `generate_auth_data` returns a K_AUSF-bearing
  5G HE AV for any `supi`. The fronting AUSF holds no `TokenSource`
  (`nf/nf-ausf/src/main.rs`), confirming the UDM never expected to check tokens.
- **Exploit:** a caller reaching the UDM (plaintext default: anyone on the
  network; mTLS: any core-cert holder, e.g. a compromised edge NF) fetches
  authentication vectors for any subscriber, reads AM/SM data, or hijacks/erases
  the serving-AMF/SMF UECM registration — bypassing the AUSF.
- **Fix:** wrap `nudm::router` in `oauth::protect(_, "UDM", verifier)` with the
  correct audience; give the AUSF a `TokenSource` so it presents a UDM token.

### F4 — NRF token issuance not bound to caller; scope unenforced

- **Status:** ✅ **FIXED** (branch `audit`). Three layers now sit on token issuance.
  - *mTLS certificate binding (RFC 8705).* The mTLS serve path (`tls.rs`) surfaces the
    peer's certificate thumbprint (SHA-256 hex, `oauth::ClientCert`) to handlers. The NRF
    binds each NF registration to that thumbprint and, on `access_token`, refuses to issue a
    token for an `nfInstanceId` unless the presenting certificate matches the one that
    registered it — and refuses to re-register an instance under a different certificate. So
    a core NF can no longer obtain a token *as* another NF, nor hijack its registration.
  - *Per-consumer authorization (deferred item 1).* With `RADIAN_NRF_AUTHZ`
    (`NrfStore::with_authz_policy` / `parse_authz_policy`), `access_token` issues a token
    only if the requesting NF's **registered** type is contracted to call the requested
    `targetNfType` — deny-by-default (a consumer type absent from the policy, or a target not
    in its set, is refused; `"*"` grants any). The consumer type is read from the registry,
    never the attacker-controlled request body, so a compromised NF can no longer mint a
    token toward an arbitrary target under its own identity.
  - *Sender-constrained tokens (deferred item 2).* When issuance is over mTLS, the NRF
    stamps the caller's certificate thumbprint into the token as `cnf` (`x5t#S256`); every
    protected NF (`oauth::require_token`) then refuses a `cnf`-bearing token unless the
    presenting client certificate matches it — so a token captured off one NF cannot be
    replayed by a different one.
  - Opt-in and backward compatible: under cleartext SBI there is no certificate (no `cnf`,
    binding skipped) and, with no policy configured, any registered NF may request any
    target — the default/BDD path is unchanged. Tests
    `authz_policy_confines_a_consumer_to_its_targets`,
    `cnf_binds_a_token_to_the_presenting_certificate`, `parse_authz_policy_reads_the_grammar`,
    `nrf_binds_tokens_to_the_registering_client_certificate`.
  - **Residual (refinement, not the core finding):** authorization is at `targetNfType`
    granularity — the resource server enforces audience + `cnf` but not per-service `scope`
    (`iss` likewise unchecked). Enforcing `scope`/`iss` at each resource server would tighten
    a token to specific service operations on top of the identity/target binding here.
- **Class:** OAuth2 / authorization bypass (client-asserted identity). **File:**
  `crates/sbi-core/src/nnrf.rs:308-341` (`access_token`, sole check at `:330`
  `is_registered(&req.nf_instance_id)`); claims `oauth.rs:305-315`; resource check
  `oauth.rs:434-469` (`require_token` verifies **audience only** — never `scope`,
  `sub`, or `iss`).
- `nfInstanceId`, `targetNfType`, and `scope` are attacker-controlled body fields
  copied verbatim into the token. The NRF never binds the token `sub` to the
  authenticated caller (TLS client identity), and no resource server enforces
  scope. The token proves, at best, core membership — not authorization.
- **Exploit:** reach NRF → register a profile with any `nfInstanceId` →
  `POST /oauth2/token` with `targetNfType:"UDR"` and any scope → get a valid
  UDR-audience token → present to the one protected NF (UDR) → read/modify all
  subscriber data.
- **Fix:** bind `sub` to the authenticated caller (mTLS cert identity or client
  secret) and reject mismatches; authorize `(consumer, targetNfType, scope)`
  before issuing; enforce `scope`/`iss` at the resource server.

### F5 — User-plane anti-spoofing is family-conditional

- **Status:** ✅ **FIXED** (branch `audit`). `uplink` now fails closed: a session that
  assigned the UE an address (an anchor, or a chain's first hop — both are provisioned
  the full UE address via `session_establishment_request_via_peer`) accepts only its
  assigned families; a packet in a family the session was *not* assigned, or a non-IP
  packet, is dropped (`Uplink::UnassignedFamily`) instead of forwarded. A session with no
  assigned address at all (a pure forwarding tunnel, e.g. indirect handover forwarding) is
  left untouched, so N9/ULCL forwarding is preserved. Covered by
  `uplink_drops_the_unassigned_family_on_a_single_family_session` and
  `uplink_dual_stack_session_accepts_both_families`; full `cargo test -p bdd` green
  (45/501). *Residual:* F16 (no uplink **destination** egress filtering) is still open —
  this fix constrains the source, not the destination.
- **Class:** IP source spoofing / traffic escaping the tunnel. **File:**
  `crates/n6/src/lib.rs:98-109` (`uplink`).
- The L3 source check only fires for the family the session was *assigned*: the
  IPv4 branch guards on `ue_ip_for_teid(teid).is_some()`, the IPv6 branch on
  `ue_ipv6_for_teid(teid).is_some()`. For a single-family session, a packet of
  the **other** family short-circuits both guards and falls through to
  `admit_uplink → ToN6` with **no source validation**.
- **Exploit:** an IPv4-only subscriber sends an IPv6 packet with any forged
  source (the UPF's N6 TUN carries a default `2001:db8::/32` route,
  `nf-upf/src/main.rs:67`) → egresses spoofed; the symmetric IPv6-only + spoofed
  IPv4 case also passes. Enables reflection/amplification origination and ACL
  evasion, by any subscriber, with no privileged network position.
- **Fix:** fail closed — if a packet parses as a family with no assigned address
  for the session, drop it; drop packets that are neither valid IPv4 nor IPv6.

### F6 — AMF `UeContext` map unbounded; abandoned registrations never evicted

- **Status:** ✅ **FIXED** (branch `audit`). A registration guard timer is armed when
  a new registration is admitted and **re-armed from the last registration progress**
  (each transition to `Authenticating`/`SecurityMode` stamps `reg_progress_at`), so a
  slow-but-genuine registration is never cut off while a genuine stall is reclaimed one
  window (default 10 s, `RADIAN_AMF_REGISTRATION_GUARD_SECS`) after its last progress.
  Eviction drops the context — releasing its CBL admission slot via RAII — so an
  abandoned registration can neither leak memory nor hold the gate; the resident
  abandoned set is bounded by arrival-rate × window. Cleanup is deliberately minimal
  (directory entry + AM policy only, **no SDM/UECM DELETEs**) so a flood can't amplify
  into outbound requests. Covered by `registration_guard_evicts_stalled_registrations`.
  *Residual:* still no absolute per-association cap (a very high arrival rate × window
  is still large) — a maintained in-progress counter with a hard ceiling is the
  suggested follow-up.
- **Class:** Resource exhaustion / unbounded state. **File:**
  `nf/nf-amf/src/main.rs:758` (`ues: HashMap` per association), `3084` (insert per
  `InitialUEMessage`); decay path `cbl.rs:211-224`.
- N2 is plain unauthenticated SCTP (`nf-amf/src/main.rs:733-736`,
  `0.0.0.0:{N2_PORT}`, `listen(64)`). Every `InitialUEMessage` allocates a fresh
  never-reused id and inserts a `UeContext`; there is **no cap** and **no guard
  timer** evicting an in-progress registration. Contexts are removed only on
  terminal procedures. **CBL does not mitigate this** — its decay lease
  decrements the counter C(t) but never removes the context, so C(t) reads
  "healthy" while memory grows unbounded.
- **Exploit:** one malicious gNB streams `InitialUEMessage`s (distinct
  RAN-UE-NGAP-IDs, no auth) and never advances them; each leaks a `UeContext`
  → AMF OOM → control-plane crash for the whole RAN. Multiple associations
  compound it.
- **Fix:** cap concurrent in-progress registrations per association and globally;
  arm a registration guard timer that removes any context still pre-SMC after a
  few seconds; on CBL stale-decay, drive removal of the orphaned context.

### F7 — N3/N4 trust the network; predictable TEID/SEID

- **Status:** ◐ **PARTIAL** (branch `audit`). **Done:** the unbounded-session memory DoS
  ("Attack B") is closed — the UPF session table is now capped (`DEFAULT_MAX_SESSIONS`
  = 100k, tunable via `UpfState::set_max_sessions` / `RADIAN_UPF_MAX_SESSIONS`), and a
  full UPF answers further `SessionEstablishmentRequest`s with `NoResourcesAvailable`
  instead of allocating (test `session_table_is_capped_against_an_establishment_flood`).
  The cap also makes the `next_teid`/`next_seid` counter overflow unreachable.
  **Deferred, with rationale:** (1) *Unpredictable TEID/SEID (CSPRNG)* — the datapath
  contract is sound (SMF uses CHOOSE F-TEID and reads the allocated F-SEID from the
  response), but ~20 unit tests and the n6 helpers assert the allocations are `1,2,3…`
  and would fail *at runtime* (not compile time) under randomisation; doing it safely
  needs those tests refactored to read the allocated ids. (2) *N3/N4 peer-source
  validation* — `handle_n4` has 63 call sites, so binding a session to its establishing
  SMF source means threading the peer address through all of them (or moving the check
  into the `nf-upf` N4 loop, which already has `peer`); a focused follow-up. (3)
  *`valid_gnb_target` RAN-prefix allowlist* — cannot be made fail-closed by default
  without a deployment-supplied RAN CIDR, because the demo/BDD topology deliberately
  uses loopback (`127.0.0.x`) gNB addresses. All three are **bounded today** by the
  documented isolated-user-plane-segment / IPsec deployment assumption; the cap is the
  part that is safe and effective to fix unconditionally now.
- **Class:** Packet injection / session manipulation. **File:**
  `nf/nf-upf/src/main.rs:277-343` (`serve_n3` — `peer` never checked against the
  session's gNB), `crates/pfcp/src/lib.rs:838-847,690-698` (sequential TEID/SEID
  from 1), `1568-1805` (`handle_n4` — no association/source/F-SEID check).
- `serve_n3` forwards on TEID + inner packet alone; the GTP-U sender IP is used
  only for Echo/logs. TEIDs, SEIDs, and UE IPs (`10.45.0.2+`) are all sequential.
  `handle_n4` processes any N4 datagram addressed purely by the header UP-SEID.
- **Exploit:** anyone reaching N3 (`0.0.0.0:2152`) crafts a G-PDU with a guessed
  live TEID + inner source = guessed UE IP → forwarded **as the victim**, metering
  under the victim's URR and draining its AMBR. Anyone reaching N4
  (`0.0.0.0:8805`) sends a `SessionModificationRequest` for a guessed UP-SEID with
  an Update FAR → **hijacks or blackholes the victim's downlink**; unbounded
  `SessionEstablishmentRequest` → memory DoS. On the SMF side,
  `valid_gnb_target` (`smf/pdu_session.rs:2418`) accepts any unicast IP.
  Gated by N3/N4 reachability (the documented "isolated segment / IPsec"
  assumption), but the predictable IDs + missing peer validation mean no capture
  is needed once reachable.
- **Fix:** require a completed PFCP association from the datagram source; validate
  the N3 peer against the session's F-TEID and the CP F-SEID on modify/delete;
  cap the session table; CSPRNG for TEID/SEID/UE-IP; constrain `valid_gnb_target`
  to configured RAN prefixes.

## MEDIUM findings

- **F8 — SQN rollback via replayed AUTS.** `resync_sqn` (`subscriber-db/src/lib.rs:277,624`)
  sets the stored SQN to whatever the MAC-S-verified AUTS carries, with no
  `sqn_ms > current` check and no record of issued RANDs. Replaying a captured
  `Authentication Failure (synch)` `(rand, auts)` to `.../resync` rolls the SQN
  back → the network issues already-consumed SQNs → the real UE rejects them →
  auth loop DoS. **Fix:** adopt `sqn_ms` only if greater (mod window); bind resync
  to an unconsumed issued RAND.
- **F9 — Non-constant-time secret compare.** `res_star == ctx.xres_star`
  (`nausf.rs:180`), `hxres_star(..) != pending.hxres` (`amf/auth.rs:128`),
  `mac_s[..] == auts[6..]` (`aka/src/lib.rs:196`) use data-dependent `==`/`!=` on
  per-challenge secrets gating auth. **Fix:** `subtle::ConstantTimeEq`. (The 32-bit
  NAS-MAC `u32 !=` at `nas/src/lib.rs:1785` is single-word and not flagged.)
- **F10 — AV not single-use.** `confirm` (`nausf.rs:171-196`) removes the context
  only on success; a failed RES* leaves the AV/XRES* live for unlimited retries —
  the repeatability that turns F9 into a practical oracle. **Fix:** invalidate the
  context on first `confirm` regardless of outcome.
- **F11 — No SUPI concealment.** Only the null SUCI scheme works
  (`nas/src/lib.rs:1625` returns the IMSI only for scheme 0); the UDM treats
  `supiOrSuci` as the SUPI (`nudm.rs:388`). The MSIN travels in cleartext →
  IMSI-catcher / subscriber-tracking exposure. **Fix:** implement ECIES
  deconcealment at the UDM/SIDF; reject null-scheme outside config-gated emergency.
- **F12 — Insecure by default.** With no env config the SBI runs h2c (`http`),
  no OAuth, bound `0.0.0.0` (`sbi-core/src/lib.rs:109`, `tls.rs:41`, `oauth.rs:407`)
  — auth vectors/K_AUSF/subscriber data in plaintext to any reachable host.
  **Fix:** fail closed in non-dev builds (require `RADIAN_SBI_TLS_DIR`, default
  bind loopback, gate insecure mode behind an explicit flag).
- **F13 — SSRF in notify fan-out.** UDM SDM (`nudm.rs:229`) and both PCF notifiers
  (`npcf.rs:761`, `npcf_am.rs:265`) post to stored callbacks via the default
  redirect-following `sbi_client()`, unlike the hardened UDR path
  (`nudr.rs:255` scheme-check + `Policy::none()`). A stored `notificationUri` can
  302 to `http://169.254.169.254/...` at delivery. **Fix:** route every callback
  through `is_valid_callback_uri` + a no-redirect client; host allowlist.
- **F14 — Unprotected service routers + PCF token bug.** PCF/AUSF/CHF/NSSF/SMF
  serve `router(state)` with no `oauth::protect`. Separately `nf-pcf/src/main.rs:51`
  gates its UDR `TokenSource` on `sbi_secret().is_some()` instead of
  `client_tokens_enabled()`, so in ES256 mode PCF→UDR calls 401. **Fix:** apply
  `oauth::protect` per NF; use `client_tokens_enabled()`.
- **F15 — Predictable 5G-TMSI/GUTI.** `tmsi = amf_ue_id as u32`
  (`nf-amf/src/main.rs:3842`) from the monotonic `NEXT_AMF_UE_ID` (`:107`, starts
  at 1). Sequential, cleartext (RRC/Paging), and equal to the AMF-UE-NGAP-ID →
  passive linkability/tracking and trivial `RETAINED`/`GUTI_DIRECTORY`
  enumeration; TS 33.501 requires unpredictable allocation. (Resume is
  integrity-checked, so no direct hijack.) **Fix:** CSPRNG TMSI with
  collision-check, decoupled from the internal counter.
- **F16 — No uplink egress filtering.** `uplink` validates source only, never the
  inner destination; `tun.send(inner)` (`nf-upf/src/main.rs:298`) lets the kernel
  route by destination. If core/management/N4 addresses are routable from the UPF
  host, a UE can reach them. **Fix:** egress ACL / uplink-FAR destination policy;
  dedicated VRF with no route to core.
- **F17 — Sequential, never-released UE IPs.** `alloc_ue_ip`
  (`smf/pdu_session.rs:532`) is `fetch_add` from `10.45.0.2` with no free list;
  `release_sm_context` (`:1873`) never frees the IP. Predictable (compounds
  F5/F7), and after ~65k sessions silently walks past the `/16` pool into
  neighbouring space; an SMF restart resets to `.2` while the UPF holds old IPs →
  downlink misroute. **Fix:** track + free on release; bound to the pool and
  reject on exhaustion; randomize within the pool.
- **F18 — Auth-flood amplification.** One unauthenticated `InitialUEMessage` with
  a SUCI (`nf-amf/src/main.rs:1710` → `auth.rs:59`) triggers an NRF discovery plus
  a full `Nausf_UEAuthentication` across AUSF+UDM+UDR. Flooding distinct SUCIs
  forces sustained crypto/DB work. **Fix:** rate-limit/pace SUCI resolution before
  discovery; cache AUSF discovery.
- **F19 — CBL decay + fairness.** The 10 s decay lease (`cbl.rs:236`) reclaims a
  slot regardless of whether the registration is still live, so under genuine
  overload (raised AUSF/UDM latency) C(t) under-counts and the gate admits beyond
  M exactly when it should throttle. Admission is FCFS with no per-source fairness
  (`nf-amf/src/main.rs:1665`), so one malicious gNB fills all M slots and starves
  legitimate UEs. (The admit CAS itself is race-correct — no TOCTOU, exactly-once
  release.) **Fix:** extend the lease on registration progress rather than a fixed
  ceiling; per-association admission quotas.

## LOW findings

- **F20 — Null algorithms.** `NEA_PRIORITY = [2,1,3,0]` (`nf-amf/src/main.rs:87`)
  includes NEA0, so a UE offering only NEA0 gets no NAS confidentiality (a policy
  decision that should be explicit/logged); `protect`/`unprotect`
  (`nas/src/lib.rs:1745`) trust `nas_mac`, which returns `0` for NIA0, with no
  `nia != 0` assertion. Integrity selection is correct (`NIA_PRIORITY = [2,1,3]`
  never picks NIA0; AMF rejects a UE with no real integrity alg). **Fix:** gate
  NEA0 behind config; add a defensive `nia != 0` assert.
- **F21 — No key zeroization.** K/OPc/KEK/derived keys are plain arrays
  (`aka/src/lib.rs:20`, `subscriber-db/src/lib.rs`), dropped without wiping — no
  `zeroize` in the tree. Exposure via core dump / swap / heap reuse. **Fix:**
  `Zeroizing` / `#[derive(ZeroizeOnDrop)]`.
- **F22 — AMF state hygiene.** `GNB_LINKS` (`nf-amf/src/main.rs:342`) is pushed per
  association and pruned only lazily on paging/broadcast failure — the teardown
  (`:824`) doesn't remove it, so open/close association churn leaks entries.
  ~60 `Mutex::lock().unwrap()` sites mean any panic-under-lock poisons a global
  mutex and cascades (no concretely reachable trigger found). CBL fast-completions
  leave the decay task sleeping out its full 10 s. **Fix:** remove the `GnbLink`
  on teardown; `parking_lot` (no poisoning); `AbortHandle` in `CblSlot`.
- **F23 — OAuth edge cases.** ES256 verify falls back to `keys.first()` on unknown
  `kid` (`oauth.rs:257`) — benign with one JWK, a latent risk on key rotation;
  HS256 mode lets any secret-holder mint tokens and `iss` is never checked
  (`oauth.rs:108`). **Fix:** require exact `kid`; prefer ES256; validate `iss`.
- **F24 — No decode panic barrier.** Decode wrappers use `.ok()` (converts `Err`,
  not `panic!`), so panic-safety is inherited from `oxirush-ngap/-nas` and
  `rs_pfcp`, which were not fully audited. **Fix:** `catch_unwind` at the
  SCTP/UDP decode entry points + per-protocol `cargo fuzz` targets.

## Cross-cutting root causes

1. **Predictable sequential identifiers.** TEID (`pfcp:692`), SEID (`pfcp:693`),
   UE-IP (`smf:532`), TMSI (`amf:107`) are all monotonic counters. This turns
   cross-session injection and downlink hijack (F7) and UE tracking (F15) from
   *capture-required* into *guessable*. → **CSPRNG for all four.**
2. **Trusting unauthenticated segments with no per-source caps/rate-limits.** N2
   SCTP (`amf:733`), N3/N4 (`upf:88`), and the plaintext SBI default (F12) accept
   state-changing messages from any reachable host; combined with unbounded state
   (F6, F17) and no fairness (F19) one peer can exhaust or starve the system. →
   **per-source caps + rate limits + fail-closed transport + peer-bound PFCP/GTP-U.**
3. **Missing freshness/replay controls.** NAS COUNT (F1), AKA SQN (F8), and AV
   single-use (F10) all accept something that should be rejected as stale/reused.

## Positive controls (verified, no action)

- Parsers bounds-check every length field; generated PER decoders delegate to
  `asn1-codecs 0.7.2`, which returns `Err` (never panics) and caps allocations —
  no memory-safety/DoS surface. No `unsafe` in the tree.
- Integrity is mandatory: `NIA_PRIORITY` never selects NIA0; AMF rejects a UE with
  no real integrity algorithm; the SMC replays UE security capabilities
  (bidding-down defense).
- AKA resync verifies MAC-S before acting; Service-Request resume verifies NAS
  integrity before restoring context (a guessed TMSI alone can't hijack/reactivate).
- TLS construction is correct (real webpki verifiers, required client certs, CRL);
  no `alg:none`; no secrets logged; demo subscriber key env-gated, never
  auto-provisioned; UDR UECM callback has an SSRF guard + no-redirect client.

## Remediation priority

1. **F1 (NAS replay)** and **F6 (AMF context exhaustion)** — highest-impact,
   unauthenticated-N2-reachable control-plane breaks.
2. **F2–F4 (SBI authz)** — `oauth::protect` on every service router with the right
   audience, bind NRF tokens to the authenticated caller, authenticate the NEF.
3. **F5 (user-plane anti-spoofing)** — fail closed on the unassigned family;
   exploitable by any subscriber with no privileged position.
4. **F7 + root cause 1** — CSPRNG for TEID/SEID/UE-IP/TMSI and peer-source
   validation on N3/N4.
5. **F8–F11** (crypto freshness / constant-time / SUCI), then **F12–F19**, then
   the Lows.

## Method & caveats

Five parallel domain reviewers read the code and returned evidence-backed
findings; the top finding in each domain was re-verified by hand against the
cited lines (F1 NAS COUNT, F5 family-conditional guard, F6 N2 + `ues` map, F15
TMSI counter, and the "only UDR calls `oauth::protect`" premise). **Not covered:**
internals of `oxirush-ngap`/`oxirush-nas`/`rs_pfcp` beyond `asn1-codecs`; runtime
fuzzing; the BDD harness. Severities weigh both impact and reachability; several
user-plane/AMF findings are gated by the documented "isolated user-plane segment
/ IPsec per TS 33.501" deployment assumption and are called out as such — F5 is
not, as it is reachable by any ordinary subscriber.
