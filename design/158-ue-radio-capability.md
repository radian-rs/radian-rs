# UE Radio Capability: store and replay (design/138 G39)

> Built 2026-08-11 on branch `ue-radio-capability`. Implements **G39**
> ([138](138-open5gs-gap-survey.md) §7): the AMF stores the UE's radio capability
> reported by the NG-RAN and replays it in a later InitialContextSetup, so a gNB
> needn't re-run a UE Capability Enquiry. open5gs is the working oracle here
> (`ngap-build.c:892`); free5gc's handler is a stub.

## The gap

When a gNB has learned a UE's radio capabilities (via RRC UE Capability Enquiry),
it reports them to the AMF in a `UERadioCapabilityInfoIndication` (TS 38.413
§8.5.2) — an opaque octet string. A capable AMF **retains** it and, on a later
context setup toward the RAN (a Service Request resume, a handover), **replays**
it as the `UERadioCapability` IE. That lets the target node configure the UE's
radio bearers immediately instead of issuing another capability enquiry over the
air. radian did neither: it had no handler for the indication (the NGAP dispatch
had no arm) and never emitted the IE — every resume forced a fresh enquiry.

## What this slice does

Three small pieces, following radian's existing NGAP patterns:

- **`ngap`** — a parser `ue_radio_capability_from_indication(pdu) -> Option<(u64,
  Vec<u8>)>` (the `(amf_ue_id, capability)`), its inverse builder
  `ue_radio_capability_info_indication(amf_ue_id, ran_ue_id, cap)`, and a new
  `Option<Vec<u8>>` field on `InitialContext` that
  `initial_context_setup_request` emits as the `UERadioCapability` IE
  (criticality IGNORE) when present. The parse-back path recovers it too.
- **`nf-amf`** — `UeContext` gains `ue_radio_capability: Option<Vec<u8>>`; a new
  NGAP dispatch arm routes `Id_UERadioCapabilityInfoIndication` to
  `on_ue_radio_capability_indication`, which stores the octet string against the
  UE (a class-2 procedure — no response). Both InitialContextSetup build sites (the
  initial-registration path and the Service-Request-resume path) now carry
  `ctx.ue_radio_capability`. The resume path reads it into a local **before** the
  context is moved back into the table.
- The capability is normally learned *after* the registration ICS, so it rides
  the **next** context setup (resume/handover) — exactly where a target node
  benefits.

## Decisions

- **D1 — store on the `UeContext`, replay from it.** The capability is per-UE and
  long-lived; the context is where it belongs, and every ICS build site already
  reads context. No new side table.
- **D2 — criticality IGNORE on the emitted IE.** TS 38.413 marks `UERadioCapability`
  IGNORE in InitialContextSetup; a gNB that doesn't want the hint can skip it
  without failing the procedure.
- **D3 — the parser returns `(amf_ue_id, cap)`, not just `cap`.** The AMF always
  needs both (which UE, what capability) and the indication carries the
  AMF-UE-NGAP-ID as a mandatory IE — so one parser gives the handler everything and
  keeps the oxirush entry-value type out of `nf-amf`.
- **D4 — a symmetric builder in `ngap`.** `ue_radio_capability_info_indication`
  mirrors the parser; it makes the round-trip test real (encode → decode → parse)
  and gives a driving gNB / future BDD tier a way to send the message.
- **D5 — HandoverRequest replay deferred.** ICS is the primary, well-exercised
  replay point and closes the resume case. Adding the IE to the HandoverRequest
  build is a mechanical follow-up once radian's handover path carries it (§Follow-ups).

## Tests

- `ngap` `ue_radio_capability_replays_through_ics_and_parses_from_indication`:
  an ICS built with a capability survives APER encode/decode and
  `initial_context_setup_params` recovers it; a built indication round-trips and
  the parser returns `(amf_ue_id, cap)`; a non-indication PDU yields `None`.
- `nf-amf` `ue_radio_capability_indication_stores_for_replay`: an indication for a
  known UE stores the capability on its context; one for an unknown UE is ignored
  (no panic, no phantom context).
- `cargo test --workspace --exclude bdd` green; clippy clean on `ngap` + `nf-amf`;
  **BDD 48/48** unchanged — the scripted gNB sends no indication, so the ICS on the
  registration path carries no capability (field `None`), exactly as before.

## Follow-ups

- **Replay in HandoverRequest** (D5) — add the `UERadioCapability` IE to the
  HandoverRequest builder and thread the stored blob through the handover path.
- **`UERadioCapabilityForPaging`** — derive/store the paging-optimised subset
  (the indication can carry it) to shrink paging messages.
- **A BDD tier** where the scripted gNB sends the indication and a subsequent
  resume ICS is asserted to carry it — needs scripted-gNB support for the message
  (the builder from this slice is the piece it would use).
