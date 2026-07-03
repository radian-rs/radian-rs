# RAN/UE QoS-flow Release Signalling — Implementation Notes

> Built 2026-07-02 on branch `feat/qos-flow-release`. Finishes the release path
> that [52](52-upf-per-flow-modify.md) left open: a mid-session **removed** GBR
> flow was dropped at the UPF but never signalled to the gNB/UE. Now the SMF tells
> the AMF which QFIs were released, and the AMF adds an **N2 `QosFlowToReleaseList`**
> + an **N1 delete-flow-description** to the mid-session modify.

## What was built

### NGAP (`ngap`)

- **`pdu_session_resource_modify_request(.., released_qfis: &[u8], nas)`** — the
  `ModifyRequestTransfer` now includes a **`QosFlowToReleaseList`** (each released
  QFI with cause `RELEASE_DUE_TO_5GC_GENERATED_REASON`) when non-empty. The
  add-or-modify list is now emitted **only when there are flows** (its APER
  `sz_lb=1` forbids an empty list) — a pure-release or session-AMBR-only modify is
  now valid.

### NAS (`nas`)

- **`pdu_session_modification_command(.., released: &[u8])`** — the Authorized QoS
  flow descriptions IE (0x79) now appends a **delete** operation (operation code 2,
  no parameters: `[qfi, 0x40, 0x00]`) for each released QFI, alongside the
  create/modify entries for the still-authorized flows.

### AMF (`nf-amf`)

- `ModifyPolicy` carries `released_qfis`; the `namf-comm/…/modify` callback parses
  `releasedQfis` from the SMF's body. `on_network_modification` threads them into
  both the N1 command and the N2 modify (and drops the old empty-flows→default-flow
  fallback, so a release-only modify sends no spurious add-or-modify flow).

### SMF (`nf-smf`)

- `refresh-policy` computes the **released** set — old GBR QFIs **fully gone** from
  the new decision (distinct from the N4 `remove`, which also covers
  filter-changed/re-provisioned QFIs) — and includes it in the AMF notification
  (`releasedQfis`).

## Model / boundaries

- **Released = fully gone.** A QFI whose classifier changed is re-provisioned
  (add-or-modify), not released; only a QFI absent from the new policy is released
  toward the RAN/UE.
- **N1 deletes the flow description**, not a per-flow QoS *rule* — the UE was only
  ever given the single match-all QoS rule (→ default QFI), so there is no per-flow
  rule to delete; the flow-description delete is the meaningful N1 action for this
  model.
- Not live-verified (free-ran-ue drives no modification); wire shapes are
  unit/integration-pinned, same posture as [50](50-n2n1-pdu-modify.md).

## Verification

- `cargo test --workspace --exclude bdd` — green (109 tests). New/changed:
  - `ngap::modify_request_roundtrips` (extended) — the AMBR + add-or-modify +
    **release** lists survive the APER round trip.
  - `nas::pdu_session_modification_command_layout` (extended) — the released QFI
    carries a delete op (`[3, 0x40, 0x00]`).
  - `nf-amf::network_modification_signals_ran_and_ue` (extended) — the UE-decodable
    N1 now contains the delete for the released QFI 3.
  - `nf-smf::refresh_policy_applies_a_mid_session_udr_change` (extended) — a second
    refresh **removes** the GBR flow: the UPF drops its per-flow QER **and** the AMF
    is notified with `releasedQfis == [2]`.
- **BDD, 5 scenarios / 25 steps green**, incl. the live **`@sim`** e2e — the release
  path fires only on `refresh-policy`, so the datapath is unaffected.

## Known limitations / next steps

- **GFBR admission control** + **URR usage reporting**; **buffering / QER gate**.
- **Combine** the SMF's session-AMBR + per-flow N4 modifications into one Session
  Modification (today a refresh may send two).
- Live interop for the modification/release procedures (a UE/gNB that drives them).
