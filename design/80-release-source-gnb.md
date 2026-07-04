# Source-gNB Release + Cross-Association Takeover on Path Switch

> Built 2026-07-04 on branch `feat/release-source-gnb`. Design
> [79](79-nh-ncc-path-switch.md)'s path switch had two gaps. The noted one: the
> **source gNB was never released** — its stale UE context lingered after the
> handover. The latent one its test hid: each gNB association task owns its own
> `ues` map, and the `PathSwitchRequest` arrives on the **target** association —
> in a real two-gNB deployment the design/79 lookup would miss, because the
> context lives with the **source** association. This slice fixes both with one
> mechanism: a **cross-association context takeover** in which the source side
> hands the context out and releases its gNB.

## What was built

### `ngap`

- `ue_context_release_command_radio(amf, ran, radio_cause)` — the release command
  with a **radio-network cause** (the existing builder only spoke NAS causes);
  used with `CauseRadioNetwork::SUCCESSFUL_HANDOVER` (the cause free5gc uses for
  the same message).
- `release_command_radio_cause` — the gNB-side/test parser.

### `nf-amf`

- **`UeCmd::TakeUe { amf_ue_id, reply: oneshot::Sender<Option<Box<UeContext>>> }`**
  — the takeover request, delivered over the same per-association command channel
  the paging/callback surface uses (the unused `Clone` derive on `UeCmd` was
  dropped to admit the oneshot).
- **`on_take_ue`** (source side, a new select-loop arm): removes the context,
  replies on the oneshot, and — when it really owned the UE — emits a
  `UEContextReleaseCommand (successful handover)` on **its own** N2 association,
  releasing the source gNB's stale context (the Xn handover completion,
  TS 23.502 §4.9.1.2).
- **`on_path_switch`** (target side): when the UE isn't in the local map, it asks
  **every other association concurrently** (`JoinSet`, per-ask 500 ms bound — a
  live select loop answers immediately: the owner with the context, everyone else
  with `None`), inserts the taken context, and proceeds with the design/79 flow.
  It also now **re-points `UE_DIRECTORY`** to the target association's command
  channel — SBI callbacks (UpdateNotify, network deregistration, SMF modify)
  reach the UE through the new gNB, which would otherwise silently break after
  a handover.

## Boundaries / notes

- 3GPP-wise the source gNB releases after the target's Xn-U *Release Resources*;
  the AMF-issued release command matches the common implementation practice
  (free5gc) and our AMF's role as the only entity that spans both associations.
- A takeover race (two path switches for the same UE) resolves by whoever removes
  the context first; the loser's path switch is ignored (no Failure message —
  design/79 boundary unchanged).
- The 500 ms ask bound only matters when an association is wedged; live loops
  answer immediately.

## Verification

- `cargo test --workspace --exclude bdd` — green (**167** tests). New:
  - ngap: the release-command test now covers the radio-cause variant
    (successful-handover round-trips; ids still parse; NAS-cause reads `None`).
  - nf-amf `path_switch_takes_over_the_ue_and_releases_the_source` — a simulated
    **source association task** owns the context and services `TakeUe`; the path
    switch lands on the **target** association with an empty map: the context
    moves (RAN-UE-ID, NH chain rotated to `{NH₁, NCC 1}`), the acknowledge is
    correct, the source emitted exactly one
    `UEContextReleaseCommand (successful handover)` **addressed by the old
    RAN-UE-NGAP-ID**, and `UE_DIRECTORY` re-points to the target's channel
    (verified via `same_channel`).
  - The design/79 same-association test still passes (a local context skips the
    takeover).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green.**
- An Xn handover needs two gNBs — not sim-drivable (design/64/65 precedent);
  the cross-association mechanics are integration-tested with a real spawned
  owner task.

## Known limitations / next steps

- **PathSwitchRequestFailure** + `PDUSessionResourceReleasedListPSAck` error
  paths.
- **N2 handover** (Handover Required / Request / Command) — where {NH, NCC} rides
  the Handover Request and the AMF orchestrates both sides explicitly.
- UE Context Release **Complete** from the source is logged by the existing
  release arm but not correlated to the handover.
