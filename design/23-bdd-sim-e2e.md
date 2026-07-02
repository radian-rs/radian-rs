# Simulator-driven end-to-end BDD feature

> Built 2026-06-30 on branch `feat/bdd-sim-e2e`. A second `bdd/` feature that drives the
> **whole stack** — the radian core plus the free-ran-ue gNB/UE — from registration through
> a forwarded packet, automatically.

Design/22 added a self-contained UPF-datapath BDD test. This slice adds the other half: an
`@sim` feature that runs the **real simulator** against the **real core**, reproducing the
manual end-to-end ping (design/21 follow-up) as a repeatable test.

## The feature (`datapath_e2e`, `@sim`)

```
 ┌───────────────────────┐  veth  ┌──────────────────────┐  veth  ┌──────────────┐
 │ host: radian core     │10.0.1.1│ ns <tag>_ran: gNB    │10.0.2.1│ ns <tag>_ue  │
 │ NRF UDM AUSF SMF AMF    ├────────┤ 10.0.1.2             ├────────┤ UE 10.0.2.2  │
 │ UPF + N6 TUN 10.45.0.1  │        │                      │        │ ueTun0       │
 └───────────────────────┘        └──────────────────────┘        └──────────────┘
```

The scenario, in order: clean → set up the RAN + UE namespaces (two veth pairs, routes) →
start the six core NFs in the host (UPF under sudo for its TUN) → start the free-ran-ue **gNB**
in the RAN namespace → start the **UE** in the UE namespace → **the UE pings the N6 gateway**.
Each stage polls a readiness signal (SBI/SCTP ports, `n6upf0`, the gNB's control-plane port,
and — the PDU-session-complete signal — the UE's `ueTun0` appearing). A `Teardown topology`
scenario stops everything and asserts the environment is clean.

The UE (credentials matching the radian UDM demo subscriber) registers via 5G-AKA, gets an
IP on `ueTun0`, and the ping traverses UE → gNB → N3 → UPF → N6 → the host kernel and back —
the full control **and** user plane, conformance-checked by an independent implementation.

## Supporting changes

- **`nf-ausf` self-registers with the NRF** (mirrors the SMF) — the AMF can now discover the
  AUSF without the manual registration the old runbook needed. `RADIAN_AUSF_NRF` overrides
  the NRF base.
- **`bdd/src/netns.rs`** grew helpers: a namespace↔namespace veth, route add, host-process
  spawn (sudo or not), interface/port readiness polls, ns-scoped ping, and pattern kills.
- **`bdd/tests/fixtures/{gnb,ue}.yaml`** — the simulator configs (namespace topology + demo
  credentials).
- The runner **gates `@sim`** on `FREE_RAN_UE_BIN`: absent ⇒ the feature is filtered out
  (not skipped/failed), so `cargo test -p bdd` still runs the self-contained datapath feature.

## Verification

- `FREE_RAN_UE_BIN=… cargo test -p bdd` — **2 features, 4 scenarios, 21 steps pass**, both
  ending "Test environment is clean" (no leftover namespaces, veths, TUN, or processes).
- `cargo test -p bdd` (no sim binary) — the `@sim` feature is skipped; the self-contained
  datapath feature passes (2 scenarios / 10 steps).
- `cargo test --workspace --exclude bdd` — 49 pass; `cargo clippy` clean.

## Known limitations / next steps

- **Needs the external simulator** — `FREE_RAN_UE_BIN` must point at a built free-ran-ue
  (Go); the feature is otherwise skipped. Privileged (sudo) + Linux-only, like all of `bdd/`.
- **Fixed single UE / addresses**, one DNN/slice — fine under `@serial`.
- The `@sim` feature depends on the same deferred items as the manual flow (SQN 0, null-scheme
  SUCI, single algorithms) baked into the UE fixture.
