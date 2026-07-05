# PCC Rules + QoS Decisions as Keyed Maps (pccRules / qosDecs)

> Built 2026-07-04 on branch `feat/sm-pcc-rules`. The capstone of the SM-policy keyed-map
> restructure (designs 112 `chgDecs`, 113 `sessRules`): the flat `qos_flows` Vec becomes
> **PCC rules** (`pccRules`, TS 29.512 §5.6.2.6) — first-class keyed entities that
> reference a keyed **QoS decision** map (`qosDecs`, §5.6.2.8) and a charging decision
> (`chgDecs`) by id. The SM policy is now fully the TS 29.512 keyed-map shape, and every
> map is conveyed in an Update as a partial map.

## What was built

### `sbi-core` (`npcf`)

- **`QosData`** (`qosDecs`) — 5QI, ARP (priority + pre-emption), optional GBR/MBR.
- **`PccRule`** (`pccRules`) — the bound QFI, precedence, packet filter (`flowInfos`),
  and `refQosData` / `refChgData` references.
- **`SmPolicyDecision`** replaces the `qos_flows` field with `pcc_rules` + `qos_descs`
  (joining `session_rules` from 113 and `charging_descs` from 112 — four keyed maps).
  - **`qos_flows()`** — a derived accessor that resolves each PCC rule against its QoS
    decision into the flat `QosFlowPolicy` view the SMF/UPF/AMF act on, ordered by
    `(precedence, qfi)`. An unresolved `refQosData` yields default QoS (no panic).
  - **`set_flows()`** — the sm-data / demo bridge: builds `pcc-{qfi}` rules + `qos-{qfi}`
    decisions from a flat flow list.
  - **`rating_group_for()`** now resolves via the PCC rule's `refChgData`.
- **`SmPolicyUpdate`** is now four keyed partial maps (session rules, PCC rules, QoS
  decisions, charging decisions); `diff`/`apply` are each four `diff_keyed`/`apply_keyed`
  calls (the per-QFI flow logic is gone).
- `PolicyConfig::demo()` builds its flows via `set_flows`.

### `nf-smf`

- All `SmPolicyDecision.qos_flows` field reads become `.qos_flows()` calls
  (`flow_qers`, `decision_gfbr`, `ambr_bps`'s neighbours, the CreateSmContext response,
  the AMF modify body, `refresh_sm_policy`). The datapath is otherwise unchanged — it
  still consumes a `Vec<QosFlowPolicy>`. The sm-data fallback uses `set_flows`.

## Boundaries / notes

- **Wire reshape**: the UDR SM policy-data doc and the PCF↔SMF decision now use
  `pccRules` + `qosDecs` (+ `sessRules` + `chgDecs`) instead of a flat `qosFlows` array.
  This does **not** touch the SMF's Nudm sm-data DNN config (still a `qosFlows` array) nor
  the SMF→AMF modify body / CreateSmContext response (still `qosFlows` — `nf-amf` reads
  those unchanged via `parse_qos_flows`).
- radian binds **one PCC rule per QoS flow** (the rule carries its QFI) — it doesn't model
  multiple rules binding to one flow, nor SMF-side QoS-flow binding of same-QoS rules.
- `QosData` is trimmed (no separate MBR beyond the GBR set, no QNC/notification control);
  `PccRule.flowInfos` is one SDF filter.

## Verification

- `cargo test --workspace --exclude bdd` — green (**206** tests, +1). New/updated:
  - sbi-core `pcc_rule_resolves_referenced_qos_and_charging` — a PCC rule resolves its
    `refQosData` (5QI/ARP/GBR) + filter + `refChgData` (rating group) into the derived
    flow; flows order by precedence; an unresolved QoS reference → default 5QI.
  - sbi-core `sm_policy_partial_diff_and_apply` — rewritten to the PCC/QoS keyed maps
    (install/re-rate/remove rules and QoS decisions; `null` removals on the wire; the
    derived `qos_flows()` reflects the merge).
  - sbi-core `pcf_sources_…`, `per_dnn_…`, `charging_…` and nf-smf `refresh_/charging_`
    tests moved to the `pccRules`/`qosDecs` wire + the `qos_flows()` accessor.
- `cargo clippy --workspace --exclude bdd` — no new warnings (parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). BDD
  provisions no policy docs, so the wire reshape doesn't touch it.

## Known limitations / next steps

- **QoS-flow binding** — group same-QoS PCC rules into one QoS flow (SMF binding),
  instead of one-rule-per-QFI.
- `PccRule` extras (traffic control / usage-monitoring references), `QosData` MBR/QNC,
  acting on `chgDecs` metering method / online-offline, `SessionRule.authDefQos`.
