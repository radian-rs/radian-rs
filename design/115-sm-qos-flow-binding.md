# SMF QoS-flow Binding

> Built 2026-07-04 on branch `feat/sm-qos-flow-binding`. Builds on design/114: instead of
> each PCC rule carrying its own QFI (one-rule-per-flow), the SMF now **binds** PCC rules
> to QoS flows by their referenced QoS decision (TS 23.501 §5.7.1.7) — so rules sharing a
> QoS decision share **one** QoS flow (one QFI).

## What was built

### `sbi-core` (`npcf`)

- **The QFI moves to `QosData`** — a QoS decision now defines one QoS flow (its QFI + QoS
  parameters). `PccRule` no longer carries a QFI; the flow it binds to is a property of
  the QoS decision it references (`refQosData`).
- **`qos_flows()` is now the binding function**: each referenced QoS decision becomes one
  flow, carrying its QFI + QoS and the classifier + charging of the **highest-precedence**
  rule bound to it. Rules sharing a `refQosData` collapse to one flow; a QoS decision no
  rule binds to yields no flow; a rule referencing an unknown decision binds nothing.
- `set_flows()` (the sm-data / demo bridge) puts the QFI on the QoS decision it creates;
  `rating_group_for()` resolves via a rule bound to the QoS decision with the given QFI.
- `SmPolicyUpdate` / `diff` / `apply` are unchanged (still four keyed partial maps).

### `nf-smf`

- No code change — the datapath still consumes `qos_flows()`'s `Vec<QosFlowPolicy>` (one
  SDF filter per flow). Only the UDR SM policy-data test docs move the `qfi` from
  `pccRules` to `qosDecs`.

## Boundaries / notes

- **Binding key = the QoS decision reference** (`refQosData`), not the raw QoS parameters
  — radian binds by the operator's QoS-decision grouping rather than re-deriving the TS
  23.501 binding parameters (5QI + ARP) from scratch.
- **One SDF filter per bound flow** — when multiple rules bind to one flow, the flat
  `QosFlowPolicy` view carries the highest-precedence rule's filter (and charging). Full
  **multi-SDF-filter per flow** (the union of all bound rules' filters → multiple UPF
  classifier PDRs on one QER) is a follow-up — it needs a per-flow / per-filter PDR-id
  scheme at the UPF.
- Wire: `pccRules` entries lose `qfi`; `qosDecs` entries gain it.

## Verification

- `cargo test --workspace --exclude bdd` — green (**206** tests). New/updated:
  - sbi-core `pcc_rules_bind_to_qos_flows` (replaces `pcc_rule_resolves_…`) — two PCC
    rules sharing a `refQosData` bind to **one** QoS flow (QFI from the QoS decision);
    the flow takes the highest-precedence rule's filter + charging; a QoS decision no
    rule binds to, and a dangling rule, produce no flow.
  - sbi-core `sm_policy_partial_diff_and_apply`, `pcf_sources_…` and nf-smf
    `refresh_/charging_` tests moved the `qfi` to `qosDecs` (rules bind via `refQosData`).
- `cargo clippy --workspace --exclude bdd` — no new warnings (parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). BDD
  establishes a session with no per-flow flows, so binding isn't exercised there.

## Known limitations / next steps

- **Multi-SDF-filter per QoS flow** — carry the union of bound rules' filters into the
  datapath (one QER/URR per flow, one classifier PDR per filter). Needs a UPF PDR-id
  scheme change.
- **Binding by QoS parameters** — group rules whose QoS decisions have identical 5QI+ARP
  (+GBR) into one flow, rather than binding strictly by the `refQosData` id.
- `PccRule` traffic-control / usage-monitoring references; `SessionRule.authDefQos`;
  acting on `chgDecs` metering method / online-offline.
