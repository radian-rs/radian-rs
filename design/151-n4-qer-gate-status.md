# 151 — N4 QER Gate Status: policy-driven flow blocking (G18, first slice)

**Status:** implemented
**Gap item:** [137](137-free5gc-422-gap-survey.md) §3.3 / §8 **G18** (N4 generic rule engine — first slice)
**Builds on:** [134](134-ulcl-multi-upf.md) (UPF datapath + per-flow QERs), the PCF SM-policy model in `crates/sbi-core/src/npcf.rs`

## Problem

G18 is the "N4 generic rule engine" gap: the UPF parses PDR/FAR/QER/URR IEs into
specialised fields but does not honour several of them. One was that a **QER's Gate
Status was unenforced** — the UPF had no representation of a closed gate at all, so a
policy decision to **block a service data flow** could not take effect. TS 29.512 models
this as a PCC rule's `flowStatus` (ENABLED / ENABLED-UPLINK / ENABLED-DOWNLINK /
DISABLED / REMOVED); TS 29.244 carries it to the UPF as the QER **Gate Status** IE
(§8.2.7). radian modelled neither end: `PccRule` had no `flowStatus`, the SMF never set a
gate on the QERs it built, and `Session::admit` only checked token buckets.

This slice makes that one field real, end-to-end: **a PCF policy can block a GBR flow**.

## Scope

Per-flow (GBR) gates only — where `flowStatus` naturally lives (one PCC rule → one QoS
flow). The session-AMBR QER stays ungated (a session-wide block is not a normal policy
primitive; the SMF would release the session instead), and gate-only classifiers for
**non-GBR** flows (which today produce no QER) are a follow-up. Explicitly **not** in this
slice: PDR precedence evaluation, IPFilterRule SDF parsing, OHR, BAR, URR
packet-counts/StartTime — the rest of G18.

## Design

The gate rides the existing PCF → SMF → UPF path; every touch-point is additive and an
absent gate is the open default, so existing policy and the env-driven BDD suite are
unchanged.

1. **PCF (`npcf.rs`).** New `FlowStatus` enum (TS 29.512 wire strings, hyphenated) with
   `flow_status: Option<FlowStatus>` on `PccRule` and a resolved `flow_status: FlowStatus`
   on the flattened `QosFlowPolicy`. `SmPolicyDecision::qos_flows()` surfaces the
   representative (highest-precedence) rule's status onto the flow; `set_flows()` carries
   it back. `FlowStatus::gate()` maps each value to an `(uplink_open, downlink_open)` pair
   (DISABLED/REMOVED ⇒ both closed).

2. **SMF (`pfcp` + `nf-smf`).** A `Gate { uplink, downlink }` (open bits) on `pfcp::FlowQer`.
   `flow_qers()` fills it from `QosFlowPolicy::flow_status.gate()`. The per-flow **Create
   QER** carries a Gate Status IE only when the gate is restricted (an open flow's QER is
   byte-identical to before); a mid-session **Update QER** always states the gate, so
   re-opening a closed flow reaches the UPF. `diff_flows` now treats a gate flip as a
   mid-session update.

3. **UPF (`pfcp`).** `FlowEnforcer` gains a `gate`; `parse_created_flows` reads it off the
   Create QER and the Update-QER handler applies it via `set_flow_gate`. `Session::admit`
   drops a matched flow whose gate is closed for that direction **before** policing and
   **without** counting bytes — a URR measures only forwarded traffic. Unmatched traffic
   has no per-flow gate and is unaffected.

## Wire note

`GateStatus::new` takes `(downlink, uplink)`; `Gate::to_gate_status`/`from_gate_status`
keep the two directions straight, pinned by `gate_round_trips_through_gate_status_ie` and
the directional `ENABLED-UPLINK` assertions in the PCF and SMF tests.

## Tests

- `npcf::flow_status_gates_the_bound_flow` — `flowStatus` → `qos_flows()` → gate mapping +
  the hyphenated wire strings + absent-⇒-ENABLED default.
- `pdu_session::flow_status_becomes_the_qer_gate` — the SMF bridge maps a directional
  status to the right `FlowQer` gate (no transposition).
- `pfcp::gate_round_trips_through_gate_status_ie` — `Gate` ↔ IE round-trip.
- `pfcp::per_flow_gate_status_blocks_and_reopens_the_flow` — a closed gate drops matched
  traffic at establishment; a mid-session Update QER reopens it; a per-direction close
  drops uplink while downlink stays open; unmatched traffic is never gated.

Whole workspace builds; `pfcp` / `sbi-core` / `n6` / `nf-smf` tests + clippy clean.

## Follow-ups (rest of G18)

- Gate-only classifiers for **non-GBR** flows (emit a classifier PDR + gated QER with no
  MFBR so a DISABLED non-GBR SDF is dropped).
- PDR **precedence** evaluation (today branch order = PDR id), **IPFilterRule** SDF
  parsing, **OHR**, **BAR**, and URR packet-counts / StartTime-EndTime / real URSEQN.
- An end-to-end **BDD** gating scenario (QoS enforcement is unit-tested only today; a
  scenario needs a policy-config path to set `flowStatus` + new datapath steps).
