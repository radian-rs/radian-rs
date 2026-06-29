# Complete UE Registration — Security Mode + Registration Accept

> Built 2026-06-29 on branch `feat/registration-complete`. The first **complete** UE registration.

After 5G-AKA, the AMF now finishes registration: it derives K_AMF + NAS keys,
establishes a **NAS security context**, runs **Security Mode Command/Complete**, and
sends a protected **Registration Accept** (assigning a 5G-GUTI) — ending with the UE
**REGISTERED**. This closes the registration call flow that the previous six slices built up.

## The full flow now on `main`

```
NG Setup → InitialUEMessage(SUCI) → identify
  → [5G-AKA]  Authentication Request/Response → K_SEAF
  → derive K_AMF + NAS keys (NIA2/NEA2)
  → SecurityModeCommand (integrity, new context) ⇄ SecurityModeComplete
  → RegistrationAccept (integrity + ciphered, 5G-GUTI) ⇄ RegistrationComplete
  → REGISTERED
```

## What was built

- **`aka` crate** — `kamf` (K_AMF, TS 33.501 Annex A.7) and `nas_keys`
  (K_NASint/K_NASenc, Annex A.8).
- **`nas` crate** — a **NAS security context** (`NasSecurityContext::protect` /
  `unprotect`, the `[EPD|SHT|MAC(4)|SN|payload]` envelope, TS 24.501 §9.1.1) plus
  Security Mode Command/Complete and Registration Accept/Complete builders.
- **`nf-amf`** — the completion state machine: on auth success → `establish_security`
  (derive keys, send protected SMC); on Security Mode Complete → send protected
  Registration Accept; on Registration Complete → REGISTERED. Once a security context
  exists, uplink NAS is verified/deciphered before dispatch.

### Note: oxirush-nas `security` feature is broken

`oxirush-nas` 0.2.0 ships a `security` feature whose `security.rs` imports
`oxirush_security`, but the crate's manifest doesn't declare that dependency — so the
feature does not compile. We therefore implement the NAS security envelope ourselves
in `crates/nas`, directly on `oxirush-security`'s `nas_mac` / `nas_cipher` (NIA/NEA).

## Verification

- `cargo test` — green (18 tests workspace-wide). Highlights:
  - `nas::nas_security_protect_unprotect` — SMC (integrity, new context) and
    Registration Accept (integrity + ciphered) protect/unprotect between two contexts;
    a tampered MAC is rejected.
  - `nf-amf::full_registration_completes` — **the milestone**: spins NRF+UDM+AUSF,
    runs 5G-AKA, then completes registration with NAS security on both sides
    (SMC ⇄ Complete, Registration Accept ⇄ Complete), the UE decoding each protected
    message.
- The live SCTP path reuses the existing N2 send; uplink handlers are conn-free
  (return the downlink to send) so the orchestration is unit-tested without a gNB.

## Known limitations / next steps

- **SUCI not deconcealed** — `supiOrSuci` is still treated as the SUPI; SUCI→SUPI
  resolution (home-network key, UDM) is unimplemented, so the *live* N2 path needs a
  UE whose SUCI matches a provisioned SUPI.
- **Fixed algorithms/parameters** — NIA2/NEA2, ngKSI=0, ABBA=0x0000; no algorithm
  negotiation from the replayed UE security capabilities.
- **No NAS COUNT overflow / SQN resync** — counters are simple per-direction u32s;
  the AUTS (synchronisation-failure) path is unhandled.
- **In-memory, single AMF** — no persistence; no GUTI reallocation/registry.
- **SBI security still deferred** — the TS 33.501 hardening slice (TLS + OAuth2) for
  NRF/UDM/AUSF remains queued.
