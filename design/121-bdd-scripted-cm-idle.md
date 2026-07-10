# BDD Scripted CM-IDLE Resume (116d)

> Built 2026-07-09 on branch `feat/bdd-scripted-idle`. Fourth slice of the design/116 plan
> (after 116a/117 registration, 116b/118-119 outcomes, 116c/120 PDU session): the scripted
> tier now drives the **CM-IDLE cycle** — AN release → CM-IDLE → Service Request resume — end
> to end against the live core. This is the marquee "not sim-drivable" unlock (free-ran-ue
> can't be driven CM-IDLE), and it was pure test code: no crate changes.

## What was built

Everything the flow needs already existed in `ngap`/`nas` (the AMF's own idle handlers,
designs 63–78, are driven from the gNB/UE side with the existing builders/parsers). The
slice is entirely in `bdd`:

- **`ScriptedUe::service_request(tmsi)`** — build a NAS-protected Service Request
  (signalling, ngKSI 0) identifying the UE by its 5G-TMSI, and record the **resume K_gNB**
  derived from the NAS COUNT the message goes out under (TS 33.501 §6.9.2.1.1) so the test
  can cross-check the AMF's Initial Context Setup.
- Scenario **116d** in `scripted_registration.feature`: a registered UE with a PDU session
  (the 116c prelude) is released by the gNB (`UEContextReleaseRequest`, radio cause 20
  user-inactivity), the AMF answers a `UEContextReleaseCommand` and retains the context
  CM-IDLE; the UE then resumes with a Service Request in an `InitialUEMessage` carrying its
  5G-S-TMSI, and the AMF re-establishes the AS context with an **InitialContextSetupRequest**
  that:
  - carries a **fresh K_gNB** equal to the UE's own resume derivation (key freshness on
    resume, design/78),
  - brings the PDU session back **inline** with the UPF's retained uplink F-TEID (the SMF/UPF
    reactivated the user plane), and
  - carries the **ServiceAccept** as its NAS-PDU (read + verified UE-side).

  The gNB confirms with an `InitialContextSetupResponse` reporting its DL F-TEID.

## Verification

- **`cargo test -p bdd` — 2 features / 10 scenarios / 88 steps GREEN** (deterministic across
  reruns): the new scenario drives register → PDU session → AN release → Service Request
  resume against the live NRF/UDR/UDM/AUSF/PCF/SMF/UPF/AMF; the rest of the scripted
  registration suite and the N6 datapath feature are unaffected.
- `cargo clippy -p bdd --tests` — no net-new warnings (1 site before == after).
- No workspace crate changed (only `bdd/src/ran.rs` + `bdd/tests/cucumber.rs` + the feature),
  so `cargo test --workspace --exclude bdd` is unaffected.

## Boundaries / next

- Control plane only (as with 116c): reactivation is proven by the inline session's UPF
  F-TEID and the resume K_gNB, not a GTP-U echo. The AN release does not send a
  `UEContextReleaseComplete` — the AMF retains the context on issuing the release command and
  does not await it, and no builder exists (adding one is a trivial follow-up if a scenario
  needs to assert it).
- Next in the idle arc: **paging + DL buffering** (design/65 — a downlink packet to a
  CM-IDLE UE pages it; needs the datapath/namespace wiring) and **T3513** paging
  retransmission (design/74), plus mobility/periodic registration updates (designs 76/85) on
  the scripted tier. And the **datapath echo** (scripted-tier `datapath_e2e`) remains the
  other open front. Remaining registration scenarios: D3/D4 (GUTI/Identity), D9 (area ∪),
  D10 (DNN reject #27).
