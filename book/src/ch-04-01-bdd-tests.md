# BDD Tests

The unit tests in each crate prove the codecs and state machines in isolation.
The **`bdd`** crate proves the thing that matters most and is hardest to fake: a
real packet moving through a real UPF, over real GTP-U, out a real TUN. These are
netns-based integration tests written with **cucumber**.

They are **privileged (sudo) and Linux-only**, so they are excluded from the
quick sweep and run on their own:

```
cargo test --workspace --exclude bdd     # quick unit sweep
cargo test -p bdd                         # the netns integration suite
```

The suite follows a house convention: each feature is tagged `@serial`, starts
with `Given a clean test environment`, and ends with a `Scenario: Teardown
topology` that asserts `the test environment should be clean` — so a run never
leaks namespaces, veths, TUN devices, or processes into the next.

## Feature 1: the datapath (self-contained)

`n6_datapath.feature` needs **no external simulator**. The test process itself
plays the SMF and the gNB, using radian-rs's own `pfcp` and `gtpu` crates:

```
 ┌──────────────────────────┐   veth   ┌───────────────────────────────┐
 │ test process (host)      │ 10.0.1.1 │ namespace <tag>_upf            │
 │  SMF: PFCP  → N4          ├──────────┤ 10.0.1.2  nf-upf (real binary) │
 │  gNB: GTP-U ↔ N3          │          │  N4 :8805  N3 :2152  n6upf0    │
 └──────────────────────────┘          └───────────────────────────────┘
```

It starts the real `nf-upf` in a namespace, plays the SMF to establish and modify
a session, then GTP-U-encapsulates a **hand-crafted ICMP echo** (with correct
IPv4/ICMP checksums) toward the UPF. The UPF decaps it to `n6upf0`, the
namespace's kernel answers the ping, and the UPF routes the reply back — which
the test receives as a downlink G-PDU. Getting the echo reply back proves the
full **N3 → N6 → N3** round trip. This is a good regression guard because it runs
anywhere with root.

## Feature 2: end-to-end with the simulator (`@sim`)

`datapath_e2e.feature` drives the **whole stack** — the radian core plus the
free-ran-ue gNB and UE — reproducing the
[interop walkthrough](ch-04-00-free-ran-ue-interop.md) automatically. It sets up
the RAN and UE namespaces, starts the six core NFs, runs the simulator's gNB and
UE, waits for the UE's `ueTun0` to appear (the signal that the PDU session
completed), then **pings the N6 gateway** from the UE namespace.

Because it needs the external binary, this feature is **gated on
`FREE_RAN_UE_BIN`**. If that variable is not set, the feature is filtered out —
not failed — so `cargo test -p bdd` still runs the self-contained datapath
feature everywhere:

```
FREE_RAN_UE_BIN=/path/to/free-ran-ue cargo test -p bdd
```

## What a run looks like

```
Feature: N6 user-plane datapath forwards a real packet
  Scenario: A UE packet round-trips through the N3/N6 datapath   ✔
  Scenario: Teardown topology                                     ✔
Feature: End-to-end datapath with the free-ran-ue simulator
  Scenario: A UE registers, establishes a PDU session, and pings ✔
  Scenario: Teardown topology                                     ✔

2 features · 4 scenarios (4 passed) · 21 steps (21 passed)
```

## How it is built

- `bdd/src/netns.rs` — thin wrappers over `ip netns` / veth: create and delete
  namespaces, wire veths, spawn processes (in a namespace or the host), poll for
  readiness (ports, interfaces), ping, and sweep by prefix.
- `bdd/src/datapath.rs` — the SMF + gNB roles and the ICMP crafting, with unit
  tests for the checksums.
- `bdd/tests/cucumber.rs` — the cucumber World, step definitions, and the runner
  that scopes resources per feature and gates `@sim`.
- `bdd/tests/features/*.feature` and `bdd/tests/fixtures/{gnb,ue}.yaml`.

Two layers of guard, then: one that runs on any Linux host with `sudo`, and one
that runs the full simulator interop where the binary is available.
