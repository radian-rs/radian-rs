# NGAP UE Context Release after Registration Reject — Implementation Notes

> Built 2026-07-03 on branch `feat/ue-context-release`. Closes the first "next
> step" of [34](34-registration-reject-62.md): after the #62 Registration Reject
> the AMF dropped *its* UE context but never told the gNB — the RAN-side context
> lingered until the gNB timed it out.

## What was built

- **`ngap::ue_context_release_command(amf_ue_id, ran_ue_id, nas_cause)`**
  (TS 38.413 §9.2.2.4) — the UE-NGAP-IDs *pair* choice plus a NAS `Cause`
  (`CauseNas::NORMAL_RELEASE`), built via `build_ngap!` like the other AMF
  builders; `parse_ue_context_release_command` for the gNB side / tests.
- **AMF reject flow sends two PDUs** — the NAS-protected Registration Reject
  (DownlinkNASTransport) followed by the **UEContextReleaseCommand**, so the gNB
  releases its side too. The gNB's **UEContextReleaseComplete**
  (SuccessfulOutcome) is now recognized and logged instead of "unhandled PDU".
- **Handler refactor** — `on_uplink_nas` now returns
  `Vec<(NGAP_PDU, &'static str)>` (the SCTP loop sends each in order); the
  Security Mode Complete arm produces the multi-PDU answer, and the remaining
  single-answer arms moved unchanged into `dispatch_uplink_nas`
  (`Option`-returning, keeping their `?` flow).

## Verification

- `cargo test --workspace --exclude bdd` — green. New/updated:
  - `ngap::ue_context_release_command_roundtrips` — APER encode/decode of the
    command; the parser yields the ID pair + NAS cause.
  - `nf-amf::unsubscribed_slices_reject_registration_with_cause_62` now asserts
    the downlink *sequence* — reject then release command — and that the release
    command addresses the same (AMF, RAN) UE pair with cause normal-release.
- **BDD, 5 scenarios / 25 steps green** — the happy registration path is
  behaviourally unchanged by the Vec refactor (one accept, as before).

## Known limitations / next steps

- **Release only on the #62 reject** — other context-drop points (e.g. a future
  deregistration procedure, gNB association loss) don't run the release
  procedure yet; there is also no release on PDU-session teardown (sessions
  outlive nothing today — no deregistration exists).
- **No T3346 back-off on the reject** (carried from design/34); per-slice NSSAI
  rejection causes, UE-AMBR from am-data, and AMF-side SMF selection remain
  open.
