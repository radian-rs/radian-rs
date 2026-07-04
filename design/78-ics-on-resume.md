# Initial Context Setup on Idle-Resume — Fresh K_gNB

> Built 2026-07-04 on branch `feat/ics-on-resume`. Design
> [77](77-initial-context-setup.md) established the UE context explicitly at
> initial registration, but a CM-IDLE UE coming back (Service Request resume,
> design [64](64-service-request-resume.md); mobility registration update, design
> [76](76-mobility-registration-update.md)) still got a bare accept in a
> `DownlinkNASTransport` — even though the AN release had torn the gNB's AS
> context down and the RAN had no key. This closes design/77's first follow-up:
> **every CM-IDLE return re-establishes the AS context with an Initial Context
> Setup Request carrying a fresh K_gNB** derived from the trigger message's uplink
> NAS COUNT (TS 33.501 §6.9.2.1.1) — the accept rides as its NAS-PDU.

## What was built (`nf-amf` only)

The CM-IDLE-return handler (`on_service_request`) now builds the same
`ngap::InitialContext` the registration path uses:

- **fresh K_gNB** = `aka::kgnb(kamf, sec.ul_count - 1)` — the COUNT of the
  *Service Request* or *mobility Registration Request* that triggered the return
  (`unprotect` has already advanced past it); `kamf` persists in the retained
  context (design/77).
- The retained **allowed NSSAI**, **UE security capabilities**, **UE-AMBR**,
  **RFSP**, and **service area restriction** (Mobility Restriction List) all ride
  along — the new gNB gets the full context, not just a NAS blob.
- NAS-PDU = the protected **Service Accept** (resume) or **Registration Accept**
  with the re-assigned 5GS TAI list (mobility update).
- Labels: `InitialContextSetupRequest (ServiceAccept)` /
  `…(RegistrationAccept — mobility update)`.
- The Service-Request branch still follows with the per-session
  `PDUSessionResourceSetupRequest (resume)` messages (inline Cxt-Req sessions
  remain the design/77 follow-up); a mobility update still reactivates nothing.
- A retained context without K_AMF (pre-K_gNB era) degrades to the plain
  `DownlinkNASTransport` with a warning rather than handing the RAN a bogus key.

A pending AM-policy change (design/73) still applies *after* the ICS via the
existing UpdateAmPolicy signalling — the ICS establishes the context with the
retained policy and the change lands one message later, exactly as if the notify
had arrived just after the resume.

## Boundaries / notes

- **Key freshness, not key isolation**: each return derives K_gNB from the same
  K_AMF with a new COUNT — NH/NCC chaining (TS 33.501 Annex A.10) and horizontal
  K_AMF derivation remain deferred.
- The gNB's Initial Context Setup Response is logged (design/77 arm); an Initial
  Context Setup Failure is still unhandled.
- PDU sessions are not inline in the resume ICS (Cxt Req list — deferred).

## Verification

- `cargo test --workspace --exclude bdd` — green (**163** tests). All three
  resume-path tests upgraded to assert the ICS:
  - `service_request_resumes_a_cm_idle_ue` — `[InitialContextSetupRequest
    (ServiceAccept), PDUSessionResourceSetupRequest (resume)]`, the Security Key
    equals `kgnb(kamf, 0)` (the SR's COUNT), and the UE verifies the Service
    Accept from the ICS NAS-PDU.
  - `mobility_registration_update_reassigns_the_area` — the mobility accept (new
    TAI list, kept NSSAI) rides the ICS; the RAN also gets the retained NSSAI;
    fresh count-bound key; still zero UP activations.
  - `am_policy_update_for_a_cm_idle_ue_pages_and_applies_on_resume` — the held
    policy applies after the ICS: `[ICS(ServiceAccept), UECtxMod, CUC]`.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live registration ICS
  path (design/77) is unaffected.
- The resume itself is not live-drivable — free-ran-ue cannot go CM-IDLE
  (design/64/65 precedent); integration-tested end to end including the UE-side
  verify of the ICS NAS-PDU.

## Known limitations / next steps

- **NH/NCC key chains** (TS 33.501 Annex A.10; `derive_nh` already available).
- **PDU sessions inline in the resume ICS** (Cxt Req list) — one procedure
  instead of ICS + N PDU Session Resource Setups.
- **Initial Context Setup Failure** handling (release / retry).
