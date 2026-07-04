# SM-side Partial Update (Npcf_SMPolicyControl)

> Built 2026-07-04 on branch `feat/sm-partial-update-notify`. The symmetric
> counterpart to design/107: the **session-management** policy Update
> (`Npcf_SMPolicyControl`) now returns a **partial** delta instead of a full
> `SmPolicyDecision`. The SMF merges it onto its stored policy, keeping any attribute
> the PCF omitted (TS 29.512 §5.6.2.5).

## The shape difference from the AM side

The AM side (design/107) is a **push**: the PCF POSTs an UpdateNotify to the AMF's
callback. The SM side is a **pull**: the SMF POSTs `…/update` and the PCF returns the
decision in the response. So "partial" here lands on the Update **response** — the PCF
returns only what changed; the SMF merges it onto the decision it already holds.

The SMF *already* diffs internally (design/49–54: `diff_flows`, session-AMBR compare)
to drive the user plane — so making the wire partial mostly moves the delta
computation to where it belongs (the PCF) and adds one merge step at the SMF.

## What was built

### shared `policy` module

- `FieldUpdate<T>` (the three-way Keep/Clear/Set attribute delta, its serde helpers,
  and a `diff(prev, next)` constructor) moved out of `npcf_am` into a new
  `sbi_core::policy` module — it's now shared by both policy services.
  `npcf_am` re-exports it (`pub use`), so `sbi_core::npcf_am::FieldUpdate` (the
  design/107 path used by `nf-amf`) still resolves unchanged.

### `sbi-core` (`npcf`)

- **`SmPolicyUpdate`** — the partial Update body: `session_ambr: FieldUpdate<…>` (the
  scalar, three-way) and `qos_flows: HashMap<u8, Option<QosFlowPolicy>>` keyed by QFI,
  where a present flow is installed/modified, a `null` one removed, and an absent QFI
  kept. (The collection needs per-QFI granularity — a single Keep/Clear/Set can't
  express "change one flow, keep the others".)
- **`SmPolicyDecision::diff(&self, next) -> Option<SmPolicyUpdate>`** — the session AMBR
  as a `FieldUpdate`; each QoS flow new/changed → `Some`, removed → `None`, unchanged →
  omitted. `None` when nothing changed.
- **`SmPolicyDecision::apply(&mut self, &SmPolicyUpdate)`** — merge: resolve the AMBR,
  install/replace (`Some`) or remove (`None`) each QFI in the delta, keep the rest;
  flows stay QFI-ordered.
- The **`update` handler** returns `prev.diff(&fresh)` (partial), storing the fresh
  full decision; **`PcfClient::update_sm_policy`** returns the `SmPolicyUpdate`.

### `nf-smf`

- `refresh_sm_policy` merges: `let mut decision = old_policy.clone(); decision.apply(&update);`
  then runs its existing diff-and-signal logic against the merged full decision. Its
  own refresh-policy HTTP response stays the full `SmPolicyDecision` (unchanged).

## Boundaries / notes

- The PCF sends a **minimal** diff, so a change to one flow (or the AMBR) no longer
  restates the rest — and a removed flow is an explicit `null`, not "absent from a
  full list".
- Correctness rests on the SMF's `old_policy` matching the PCF's stored `prev` (both
  are the last decision — kept in step by create + each update). `Create` still returns
  the full `SmPolicyDecision`; only the Update became partial.
- PCC rules beyond the trimmed session-AMBR + QoS-flow model (charging, gating,
  usage-monitoring deltas) aren't modelled here.

## Verification

- `cargo test --workspace --exclude bdd` — green (**201** tests, +1). New/updated:
  - `npcf::sm_policy_partial_diff_and_apply` — `diff` emits a changed flow (value), a
    removed flow (`null` on the wire), an added flow, an unchanged flow omitted, the
    unchanged AMBR omitted; `apply` reconstructs the next decision; a no-op → `None`;
    clearing the AMBR → `Clear`.
  - `npcf::pcf_sources_policy_from_udr_and_update_reflects_changes` — the Update
    response is now a partial delta (only the added QFI 2, unchanged QFI 1 omitted);
    merging it recovers the full v2 policy.
- `cargo clippy --workspace --exclude bdd` — no new warnings (parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). The
  SM policy *create* path (which `@sim` drives) is unchanged; the partial *update* is
  the mid-session refresh, not `@sim`-driven. `@sim` skipped this session
  (`FREE_RAN_UE_BIN` unset).

## Known limitations / next steps

- **Real PCC-rule deltas** — sessRules / pccRules / chargingDescs as their own keyed
  partial maps (TS 29.512), beyond session-AMBR + QoS flows.
- **Configuration Update Complete retransmission** (from design/106) — still open.
