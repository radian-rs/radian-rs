# PCC Charging Decisions as a Keyed Partial Map

> Built 2026-07-04 on branch `feat/pcc-charging-descs`. The last partial-update thread
> (designs 107/108): extend the SM policy to real PCC-style **charging decisions**
> (`chgDecs`, TS 29.512) — a keyed map of `ChargingData` that flows reference by id —
> conveyed in an Update as a partial map (present = install/modify, `null` = remove,
> absent = keep), and decoupling the CHF **rating group** from the QFI.

## The gap it closes

Charging wasn't modelled in the policy at all. The SMF derived a flow's rating group
as `urr_id − PER_FLOW_URR_BASE` (i.e. **rating group = QFI**) — a hack that can't
express two flows sharing a rating group, or a rating group that isn't a QFI. Real
PCC rules reference a `ChargingData` (`refChgData`) that carries the rating group,
decoupling charging identity from the QoS flow.

## What was built

### `sbi-core` (`npcf`)

- **`ChargingData`** (TS 29.512 §5.6.2.11, trimmed) — `rating_group` + metering
  method / online / offline (informational).
- **`QosFlowPolicy.ref_chg_data: Option<String>`** — a flow's charging-data reference
  (`refChgData`). `None` ⇒ the legacy rating-group-equals-QFI fallback.
- **`SmPolicyDecision.charging_descs: HashMap<String, ChargingData>`** (`chgDecs`) —
  the charging decisions the flows are metered under. `SmPolicyDecision` now derives
  `Default` (so decision literals spread cleanly).
- **`SmPolicyDecision::rating_group_for(qfi)`** — resolves a flow's rating group via its
  `ref_chg_data` → `charging_descs`. `None` when unreferenced (caller keeps its fallback).
- **`SmPolicyUpdate.charging_descs: HashMap<String, Option<ChargingData>>`** — the keyed
  partial map (present = install/modify, `null` = remove, absent = keep).
- `diff`/`apply` extended to the charging map (same add/modify/remove semantics as the
  QoS-flow map, keyed by id instead of QFI).
- `PolicyConfig::demo()` charges the GBR flow under a `"chg-voice"` decision (rating
  group 100).

### `nf-smf`

- `container_for` now takes the session's `SmPolicyDecision` and resolves a per-flow
  URR's rating group via `rating_group_for` (falling back to the QFI when the flow has
  no charging decision). The session-level URR stays rating group 0. Both charging call
  sites (mid-session threshold report + final release report) capture and pass the
  policy — so the CHF now bills under the **operator-configured** rating group.

## Boundaries / notes

- This delivers the **`chgDecs`** dimension of TS 29.512's partial `SmPolicyDecision`.
  Full `pccRules` (flows as keyed rules referencing `qosDecs`/`chgDecs` by id) and
  `sessRules` (session AMBR / default rule as a keyed map) remain a larger restructure —
  the current model keeps the flat `qos_flows` Vec and top-level `session_ambr`.
- `metering_method` / `online` / `offline` are carried but not yet acted on (the UPF
  URR is unconditional volume metering).
- The rating-group fallback (= QFI) preserves the pre-existing behaviour for any flow
  without a charging decision, so unprovisioned policies are unaffected.

## Verification

- `cargo test --workspace --exclude bdd` — green (**204** tests, +2). New:
  - sbi-core `charging_descs_partial_map_and_rating_group` — `rating_group_for`
    resolution (referenced / unreferenced / unknown QFI); `diff` installs a re-rated
    decision, removes one (`null` on the wire under `chgDecs`), adds one; `apply` merges.
  - nf-smf `container_charges_under_the_flows_rating_group` — a per-flow URR bills under
    the charging decision's rating group (100), an unreferenced flow falls back to the
    QFI, the session URR is group 0.
- `cargo clippy --workspace --exclude bdd` — no new warnings (parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). The
  demo GBR flow now carries a charging reference; `@sim` (skipped, `FREE_RAN_UE_BIN`
  unset) exercises no per-flow charging report.

## Known limitations / next steps

- **Full `pccRules` / `sessRules` keyed maps** — flows and session rules as first-class
  keyed entities referencing `qosDecs`/`chgDecs` by id (the remaining TS 29.512 shape).
- **Act on metering method / online-offline** — gate metering by the charging decision.
