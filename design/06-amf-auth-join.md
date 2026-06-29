# AMF Authentication — Joining N2 + SBI

> Built 2026-06-29 on branch `feat/amf-auth-join`. The first flow that spans both planes.

The AMF now drives UE registration into **5G-AKA**, acting as the **SEAF**: it
discovers the AUSF via the NRF, runs `Nausf_UEAuthentication`, sends a NAS
**Authentication Request** to the UE over N2, verifies the UE's RES*, and confirms
with the AUSF. This is the first slice where the **N2 (ASN.1/SCTP)** and **SBI
(JSON/HTTP-2)** planes work together for one flow.

## The flow

```
gNB ─InitialUEMessage[NAS: RegistrationRequest+SUCI]─▶ AMF
                       AMF ─NFDiscovery(AUSF)─▶ NRF
                       AMF ─Nausf authenticate {supi, snn}─▶ AUSF ─▶ UDM ─▶ AV
                       AMF ◀─ {rand, autn, hxres*, ctx} ──
AMF ─DownlinkNASTransport[NAS: Authentication Request {rand, autn, ngKSI}]─▶ gNB ─▶ UE
UE  ─UplinkNASTransport[NAS: Authentication Response {res*}]─▶ AMF
                       AMF: SEAF check HRES*(rand,res*) == hxres*
                       AMF ─Nausf 5g-aka-confirmation {res*}─▶ AUSF
                       AMF ◀─ {AUTHENTICATION_SUCCESS, kseaf} ──
AMF holds K_SEAF → (Security Mode Command / Registration Accept — TODO)
```

## What was built

- **`nas` crate** — NAS Authentication Request/Response builders + parsers:
  `authentication_request`, `authentication_response`, `parse_authentication_request`,
  `res_star_from_authentication_response` (TS 24.501 §8.2.1/8.2.2).
- **`nf-amf::auth`** — the SEAF orchestration: `AmfAuth::begin` (discover AUSF via
  NRF, call `Nausf` authenticate, build the NAS challenge) and `AmfAuth::finish`
  (SEAF HRES* verify, then AUSF confirm → K_SEAF).
- **AMF handler** — `InitialUEMessage` (identified) → `start_authentication`;
  `UplinkNASTransport` carrying an Authentication Response → `complete_authentication`.
  Per-UE state gains `Authenticating`/`Authenticated` and stores K_SEAF.

The AUSF is found via real NFDiscovery: its NRF profile advertises an
`nfServices[].ipEndPoints[]` endpoint, which the AMF reads to build the AUSF URL.

## Verification

- `cargo test` — green (16 tests workspace-wide). Highlights:
  - `nas`: Authentication Request/Response roundtrips.
  - `nf-amf::authenticated_registration_over_sbi` — **the payoff**: spins NRF + UDM +
    AUSF, registers the AUSF, the AMF discovers it and runs 5G-AKA; the UE computes
    RES*; the AMF SEAF-verifies and confirms → `AUTHENTICATION_SUCCESS` + K_SEAF.
  - `on_initial_ue` identify/need-identity decisions; uplink correlation.

The SCTP transport reuses the existing N2 send path; the integration test exercises
the orchestration (`begin`/`finish`) directly with real SBI servers, playing the UE
side with the `aka` crate (so no live gNB/UE is required in CI).

## Known limitations / next steps

- **Registration not yet completed** — on success the AMF holds K_SEAF but does not
  yet derive K_AMF, run **Security Mode Command** (NAS security context), or send
  **Registration Accept**. That is the next slice and completes registration.
- **Fixed ngKSI/ABBA** — ngKSI=0, ABBA=0x0000; no key-set negotiation.
- **No SQN resync** — the UE's synchronisation-failure (AUTS) path isn't handled.
- **AMF doesn't self-register** with the NRF (it is a discovery consumer here).
- **SBI still unauthenticated** — the deferred TS 33.501 hardening slice (TLS +
  OAuth2) still applies to all of NRF/UDM/AUSF.
