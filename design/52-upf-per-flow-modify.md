# Mid-session Per-flow QoS Changes — Implementation Notes

> Built 2026-07-02 on branch `feat/upf-per-flow-modify`. Completes the QoS-change
> arc: [49](49-upf-ambr-qer.md) re-rated the session AMBR mid-session and
> [50](50-n2n1-pdu-modify.md) pushed the change to the RAN/UE, but [51](51-upf-per-flow-gbr.md)'s
> per-flow QERs were **establishment-time only**. This slice makes a mid-session
> policy change **add, re-rate, and remove per-flow (GBR) QERs** at the UPF too.

## What was built

### PFCP — per-flow session modification (`pfcp`)

- **`session_flow_modification_request(up_seid, seq, create: &[FlowQer], update:
  &[FlowQer], remove_qfis: &[u8])`** — one Session Modification carrying, per flow:
  **Create QER + classifier PDR** (new flows), **Update QER** (MFBR re-rate), and
  **Remove QER + Remove PDR** (dropped flows). The Create QER/PDR builders are now
  shared with establishment (`flow_create_ies`), and the per-flow QER/PDR ids are
  **stable per QFI** (`PER_FLOW_QER_BASE + qfi` / `PER_FLOW_PDR_BASE + qfi`) so a
  later modification can target them.
- **`handle_n4`** modification arm applies them **in order `remove → create →
  update`** (so a re-provisioned QFI ends up as its new flow): `remove_flow`,
  `add_flow` (via the shared `parse_created_flows`), and `update_flow_rate` /
  `set_ambr` — one Update-QER loop now dispatches on `qer_id` (session AMBR id 1 vs.
  a per-flow QER).
- `UpfState` gains `add_flow` / `update_flow_rate` / `remove_flow` (private, driven
  by `handle_n4`); `flow_qfis` already exposed the installed flows.

### SMF — diff + drive (`nf-smf`)

- `refresh-policy` now, after the session-AMBR re-rate, **diffs the old vs new
  per-flow QERs** (`diff_flows`, by QFI) into `(create, update, remove)` and — when
  non-empty — sends `session_flow_modification_request`. A new/filter-changed QFI is
  created (and, on a filter change, the stale one removed), an MFBR-only change is
  an update, and a dropped QFI is removed.

The RAN/UE already learns the new flow list via design/50's N2/N1 modify (the AMF
notification carries the full decision), so no AMF change was needed here.

## Boundaries / notes

- **UPF-side scope.** This slice adds mid-session per-flow QoS at the **UPF**. The
  RAN/UE side conveys **add-or-modify** flows (design/50) but does **not** yet
  signal a **QoS-flow release** (the N2 `QosFlowToReleaseList` + N1 rule delete) —
  a removed flow is dropped at the UPF but not explicitly released toward the gNB/UE.
- **Filter change = re-provision.** A changed classifier for the same QFI is a
  remove + create (not an in-place SDF update); an MFBR-only change is a cheap
  Update QER.
- Same simplifications as [51](51-upf-per-flow-gbr.md): MFBR ceiling only (no GFBR
  admission, URR, or buffering); a compact proto+port SDF filter.

## Verification

- `cargo test --workspace --exclude bdd` — green (109 tests). New/changed:
  - `pfcp::mid_session_per_flow_create_update_remove` — establish one GBR flow;
    a modification **adds** QFI 3 and **re-rates** QFI 2 (a 50-packet burst then
    passes at t=1s — impossible under the old rate); a second modification
    **removes** QFI 3 (its traffic falls back to the session AMBR). `flow_qfis`
    tracks each step.
  - `nf-smf::refresh_policy_applies_a_mid_session_udr_change` (extended) — the v1
    (non-GBR) policy installs no per-flow QER; after `refresh-policy` picks up the
    v2 policy (a GBR flow with a classifier), the **UPF now polices QFI 2**
    (`flow_qfis(1) == [2]`) — the mid-session **add** reached the user plane.
  - Establishment/per-flow tests from [51](51-upf-per-flow-gbr.md) carried through
    the shared `flow_create_ies` / `parse_created_flows` refactor.
- **BDD, 5 scenarios / 25 steps green**, incl. the live **`@sim`** e2e — the flow
  modification fires only on `refresh-policy` (not exercised by the sim), so the
  datapath is unaffected.

## Known limitations / next steps

- **RAN/UE QoS-flow release** — signal a removed flow to the gNB (N2
  `QosFlowToReleaseList`) + UE (N1 delete-rule), completing the release path.
- **GFBR admission control** + **URR usage reporting**; **buffering / QER gate**.
- Combine the session-AMBR and per-flow N4 modifications into **one** Session
  Modification (today refresh may send two).
