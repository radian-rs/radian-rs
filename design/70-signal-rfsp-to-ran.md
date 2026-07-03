# Signal RFSP to the RAN — UE Context Modification

> Built 2026-07-03 on branch `feat/signal-rfsp-to-ran`. Designs
> [67](67-npcf-am-policy.md)–[69](69-npcf-am-policy-update-notify.md) sourced the AM
> policy (RFSP index + UE-AMBR) from the PCF/UDR and applied the **UE-AMBR** at the
> gNB, but the **RFSP** (RAT/Frequency Selection Priority, TS 23.501 §5.3.4.3) was
> only logged — it never reached the RAN. This closes that gap: the AMF now signals
> the RFSP (and UE-AMBR) to the NG-RAN in a **UE Context Modification Request**
> (TS 38.413 §9.2.2.7), both at registration and on a mid-connection AM policy change.

## Why UE Context Modification

RFSP is delivered to the NG-RAN in the *Index to RAT/Frequency Selection Priority*
IE, which lives in the Initial Context Setup Request and the UE Context Modification
Request. radian establishes the UE context implicitly (no Initial Context Setup), and
a *proper* ICS would have to carry the security context (GUAMI, Security Key, UE
Security Capabilities) — a much larger slice. Per TS 38.413 §9.2.2.7 the UE Context
Modification Request has only the two UE-NGAP-IDs mandatory, with `IndexToRFSP` and
`UEAggregateMaximumBitRate` as first-class optional IEs — so a
`{AMF-ID, RAN-ID, RFSP, UE-AMBR}` message is fully 3GPP-complete, and it *is* the
canonical vehicle for updating RFSP mid-connection. That also makes it compose
cleanly with the design/69 UpdateNotify path.

## What was built

### `ngap` crate

- `ue_context_modification_request(amf_ue_id, ran_ue_id, rfsp: Option<u16>, ue_ambr:
  Option<(u64,u64)>)` — builds the request (procedure code 40), pushing the optional
  `IndexToRFSP` (IE 31, criticality *ignore*) and `UEAggregateMaximumBitRate` only
  when supplied.
- `ue_context_modification_params` — extracts `(amf_ue_id, ran_ue_id, rfsp, ambr)`
  (RAN side / tests).
- `ue_context_modification_response(...)` + `ue_context_modification_response_ids`
  — the NG-RAN's acknowledgement, for the round-trip test and a gNB simulator.

### `nf-amf`

- `UeContext` gained `rfsp: Option<u16>`, set from the AM policy decision in
  `on_security_mode_complete` (previously the RFSP was only logged).
- **At registration**: after the Registration Accept, when the policy carries an RFSP
  or UE-AMBR, the AMF sends a `UEContextModificationRequest` carrying both — the
  gNB's first sight of the UE's RAT/frequency-selection priority.
- **On the design/69 UpdateNotify path** (`on_am_policy_update`): the `UpdateAmPolicy`
  command now carries the new `rfsp`; the handler stores it and signals the RAN with
  a `UEContextModificationRequest` (RFSP + UE-AMBR) *in addition to* the UE's
  Configuration Update Command. `am_policy_notify` extracts `policy.rfsp` from the
  pushed policy.
- `handle_ngap` gained a `UEContextModificationResponse` arm — logs the gNB's
  acknowledgement (a real gNB replies; the sim doesn't — see below).

## Boundaries / notes

- **Only RFSP + UE-AMBR are signalled.** Service-area restrictions (Service Area List)
  and other AM-policy outputs remain deferred (design/67).
- **UE-AMBR is now signalled at the UE-context level too**, where it 3GPP-belongs, in
  addition to the PDU Session Resource Setup carrying it (unchanged, backward compat).
  Slight redundancy, deliberate — the setup path predates this.
- **free-ran-ue does not implement UE Context Modification** (it warns
  *"Unknown NGAP PDU … Procedure Code: 40"* and ignores it). So there is no live ACK —
  matching the design/50/69 precedent for N2-toward-RAN control the sim can't drive.
  The message is verified wire-valid by an APER round-trip and confirmed transmitted
  live (below).

## Verification

- `cargo test --workspace --exclude bdd` — green (**150** tests). New:
  - ngap `ue_context_modification_roundtrips` — RFSP 7 + UE-AMBR 300/600 Mbps
    survive APER encode→decode; the optional IEs are genuinely optional; the response
    round-trips; a request isn't misread as a response.
  - nf-amf `am_policy_update_notify_applies_the_new_ue_ambr` (updated) — the
    UpdateNotify handler now emits `[UEContextModificationRequest, ConfigurationUpdate
    Command]` and the first carries the new RFSP + UE-AMBR to the RAN.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` registration
  (real free-ran-ue) now emits the UE Context Modification and still registers + pings.
- **Live loopback (real NRF+UDR+UDM+AUSF+PCF+AMF + free-ran-ue)** — the UE reaches
  **REGISTERED**; the AMF logs *"signalling AM policy to the RAN — RFSP Some(5),
  UE-AMBR Some((600000000, 300000000)) bps"* and *"sent UEContextModificationRequest
  (RFSP)"* right after the Registration Accept; the sim receives it
  (*"Unknown NGAP PDU … Procedure Code: 40"*). RFSP 5 / UE-AMBR 600/300 Mbps are the
  UDR demo subscriber's am-policy-data (design/68).

## Known limitations / next steps

- **Signal the Service Area List** (per-TA/per-slice restrictions) to the RAN, and
  wire the remaining AM-policy outputs from design/67.
- **A full Initial Context Setup procedure** (security context + UE-AMBR + RFSP at the
  UE-context level) would let the AMF establish the RAN context explicitly instead of
  implicitly, and carry the Registration Accept as its NAS-PDU.
