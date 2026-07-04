# Handover Failure Paths

> Built 2026-07-04 on branch `feat/handover-failure-paths`. Designs
> [79](79-nh-ncc-path-switch.md)–[82](82-handover-data-forwarding.md) built the
> happy paths; every failure was a silent `return` and an abandoned handover
> **leaked its in-flight entry forever**. This adds the failure machinery:
> **Handover Preparation Failure** toward the source, **Handover Failure** from
> the target, **Handover Cancel / Acknowledge**, **Path Switch Request Failure**,
> and the two relocation timers (**TNGRELOCprep** / **TNGRELOCoverall**) that
> expire abandoned handovers.

## What was built

### `ngap`

- `handover_preparation_failure(amf, ran, radio_cause)` + params — the
  UnsuccessfulOutcome of HandoverPreparation, AMF → source.
- `handover_failure(amf, radio_cause)` + params — the UnsuccessfulOutcome of
  HandoverResourceAllocation, target → AMF (no RAN-UE-ID: the target never
  assigned one).
- `handover_cancel(amf, ran, radio_cause)` / `handover_cancel_acknowledge` +
  params — the source aborts; the AMF confirms.
- `path_switch_request_failure(amf, ran, psis, radio_cause)` + params — per
  TS 38.413 the cause rides in each released session's
  `PathSwitchRequestUnsuccessfulTransfer` (no message-level Cause IE).

### `nf-amf`

- **`on_handover_required` now answers failures** instead of going silent:
  unknown UE → `unknown-local-UE-NGAP-ID`; unseeded NH chain → `unspecified`;
  no association for the target gNB → `unknown-targetID` — each a
  `HandoverPreparationFailure` on the source association.
- **`on_handover_failure`** (new UnsuccessfulOutcome arm): the target rejected —
  drop the in-flight entry and forward a preparation failure (the target's
  cause) to the source.
- **`on_handover_cancel`** (new arm, source association): drop the entry,
  release the target's prepared context when it had acknowledged
  (`UEContextReleaseCommand`, cause *handover-cancelled*, via the target's
  channel), and answer `HandoverCancelAcknowledge` (also for an unknown
  handover — idempotent).
- **Timers**: `PendingHandover` gained `target_tx` / `target_ran_ue_id` /
  `commanded`. `TNGRELOCprep` (10 s, `RADIAN_AMF_TNGRELOCPREP_SECS`) is armed at
  Handover Required — expiry of an un-acknowledged handover drops it and fails
  the source (cause *tngrelocprep-expiry*); it no-ops once commanded.
  `TNGRELOCoverall` (20 s, `RADIAN_AMF_TNGRELOCOVERALL_SECS`) is armed at the
  acknowledge — expiry of a commanded handover whose UE never arrived drops it
  and releases the target (cause *tngrelocoverall-expiry*). Handover Notify
  consuming the entry stops both (they find nothing).
- **`on_path_switch` fails loudly**: unknown UE / unseeded chain now answer a
  `PathSwitchRequestFailure` reporting the requested sessions released, instead
  of ignoring the request.

## Boundaries / notes

- A UE whose handover fails or cancels simply stays on the source gNB — no
  context was moved, nothing to roll back (the burned NH-chain rotation is the
  spec-intended cost of an attempt).
- The transparent failure containers (`TargettoSource_Failure_…`) are not
  relayed.
- The source's own recovery after a preparation failure (retry, reselection) is
  RAN behaviour, out of scope.

## Verification

- `cargo test --workspace --exclude bdd` — green (**171** tests). New:
  - ngap `handover_failure_messages_roundtrip` — all five failure messages
    survive APER encode→decode (causes included; cross-parses fail cleanly).
  - nf-amf `n2_handover_failure_paths_clean_up` — five scenarios end to end:
    unknown target → immediate preparation failure (*unknown-targetID*); target
    rejection → the source receives the forwarded failure with the target's
    cause and the entry drops; a post-acknowledge cancel → Cancel Acknowledge to
    the source + `UEContextReleaseCommand (handover cancelled)` to the target;
    TNGRELOCprep expiry → failure (*tngrelocprep-expiry*) + drop; TNGRELOCoverall
    expiry → target release (*tngrelocoverall-expiry*) + drop, with the prep
    expiry proven a no-op once commanded.
  - The design/79 path-switch test now asserts the failure responses (released
    PSI list) for unknown/unseeded cases.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green.**
- Not sim-drivable (two gNBs; design/64/65 precedent).

## Known limitations / next steps

- **Indirect data forwarding** (design/82 backlog).
- Relaying the failure transparent containers.
- Inter-AMF handover (N14) remains out of scope for a single-AMF core.
