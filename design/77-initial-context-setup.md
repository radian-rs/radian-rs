# Full Initial Context Setup Procedure

> Built 2026-07-04 on branch `feat/initial-context-setup`. Until now the AMF
> established the gNB's UE context **implicitly**: the Registration Accept rode a
> plain `DownlinkNASTransport`, with the AM-policy outputs delivered piecemeal
> (RFSP in a trailing UE Context Modification, design/70; the Mobility Restriction
> List on the transport, design/71) — and the RAN never received an AS security
> key at all. This implements the real procedure (TS 38.413 §8.3.1): after
> Security Mode Complete the AMF sends **one Initial Context Setup Request**
> carrying GUAMI, the allowed NSSAI, the UE's security capabilities, **K_gNB**,
> the UE-AMBR / RFSP / mobility restriction, and the protected Registration Accept
> as its NAS-PDU; the gNB establishes the context and answers with an Initial
> Context Setup Response.

## What was built

### `aka` — K_gNB

`kgnb(kamf, ul_nas_count)` (TS 33.501 Annex A.9, FC=0x6E, 3GPP access), wrapping
`oxirush_security::derive_kgnb`. The COUNT is the uplink NAS COUNT of the trigger
message — the Security Mode Complete at initial registration.

### `ngap`

- `InitialContext` struct + `initial_context_setup_request(amf, ran, mcc, mnc,
  &ic)` — procedure code 14, hand-built for the conditional IEs: AMF/RAN-UE-NGAP-ID
  and GUAMI (region/set/pointer 1/1/0, matching the served GUAMI + assigned GUTIs),
  Allowed NSSAI, UE Security Capabilities (`helpers::ue_security_capabilities`),
  Security Key (K_gNB as a 256-bit BIT STRING) — all REJECT; UE-AMBR when present;
  Mobility Restriction List / Index to RFSP / NAS-PDU as IGNORE optionals.
- `initial_context_setup_params` — parses the whole thing back (RAN side / tests).
- `initial_context_setup_response` builder + `initial_context_setup_response_ids`.
- The MRL construction is factored into `mobility_restriction_list(..)`, shared
  with the design/71 `DownlinkNASTransport` carrier.

### `nf-amf`

- `UeContext.kamf` — `establish_security` now also returns K_AMF, retained
  alongside the NAS security context to derive K_gNB.
- `on_security_mode_complete` now emits **one**
  `InitialContextSetupRequest (RegistrationAccept)` instead of the
  DownlinkNASTransport(+MRL) + trailing UEContextModificationRequest pair:
  K_gNB = `kgnb(kamf, sec.ul_count - 1)` (the SM Complete's COUNT — `unprotect`
  has already advanced past it), the replayed UE security capabilities, the AM
  policy outputs, and the protected accept. A missing K_AMF (unreachable in
  practice) degrades to the plain NAS transport rather than handing the RAN a
  bogus key.
- `handle_ngap` gained the `InitialContextSetupResponse` arm.
- Fail-open fix surfaced by testing: an unreachable subscription/PCF no longer
  clobbers an already-known UE-AMBR (`effective_ambr.or(ctx.ue_ambr)`).

## Boundaries / notes

- **The mid-connection paths keep their design/69–73 vehicles** (UE Context
  Modification for RFSP/AMBR changes, DL-NAS+MRL for service-area changes, plain
  DL-NAS accepts for mobility updates / Service Requests) — ICS is for initial
  context establishment; re-establishing it on every idle-resume is a follow-up.
- **PDU Session Resource Setup List Cxt Req is not used** (no PDU sessions exist
  at registration time in this core; sessions are set up by the separate
  procedure as before).
- K_gNB is derived per spec but the sim does no AS security, so the key's
  *cryptographic* use isn't exercised live (no test vector available; the
  derivation is deterministic-tested and the wire carriage live-proven).
- The registration-reject path keeps the plain transport + UE Context Release.

## Verification

- `cargo test --workspace --exclude bdd` — green (**163** tests). New:
  - aka `kgnb_is_deterministic_and_count_bound`.
  - ngap `initial_context_setup_roundtrips` — the full `InitialContext` (NSSAI,
    capabilities, 256-bit key, AMBR, RFSP, MRL, NAS) survives APER encode→decode;
    optional IEs genuinely optional; the response round-trips.
  - nf-amf `security_mode_complete_triggers_initial_context_setup` — a UE
    completes security mode; the AMF emits exactly one ICS whose Security Key
    equals `kgnb(kamf, 0)`, capabilities/AMBR/RFSP/MRL flow through, and the UE
    verifies the NAS-PDU as its Registration Accept with the registration area.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` registration
  now runs the ICS procedure end to end and still pings.
- **Live loopback (real core + free-ran-ue)** — the flagship proof, and the first
  live *acknowledged* UE-context procedure: AMF *"sent InitialContextSetupRequest
  (RegistrationAccept)"* (allowed NSSAI, RFSP 5, UE-AMBR 600/300 Mbps from the UDR
  policy) → **"recv SuccessfulOutcome InitialContextSetup (code=14)"** → *"gNB
  established the UE context (InitialContextSetupResponse) for UE 1"* → the UE
  logs *"UE Registration finished"*. The free5gc-based gNB decoded the complete
  ICS (GUAMI + NSSAI + capabilities + Security Key + AMBR + RFSP + MRL + NAS) —
  full APER wire-compat, unlike the ignored UECtxMod of design/70.

## Known limitations / next steps

- **ICS on idle-resume** — re-establish the AS context (fresh K_gNB from the
  Service Request's UL NAS COUNT) instead of the bare Service Accept transport.
- **NH / NCC handling** (TS 33.501 Annex A.10) for handover key chains.
- **PDU sessions inline in ICS** (Cxt Req list) when sessions already exist.
- Failure handling: Initial Context Setup Failure → release / retry.
