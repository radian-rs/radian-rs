# PFCP Network Instance (DNN) on the Forwarding Rules

> Built 2026-07-04 on branch `feat/pfcp-network-instance`. An interop audit
> (`gap.txt`) from a downstream MUP/SRv6 mobile-backhaul controller found radian-rs
> emitted **zero** Network Instance IEs, so the controller (which maps a session to
> a VRF by its Network Instance = DNN) originated no routes for any radian-rs
> session. This carries the session's DNN as the PFCP **Network Instance** (TS
> 29.244 §8.2.4) on every forwarding rule, mirroring free5GC.

## What was built

### `crates/pfcp`

- `session_establishment_request` gained a `dnn: &str` parameter. Both FARs now use
  `forward_to_network(Interface::…, NetworkInstance::new(dnn))` (was
  `forward_to(Interface::…)`) — so the uplink (Core) and downlink (Access) FAR each
  carry Network Instance = DNN.
- `session_modification_request` gained a `dnn: &str` parameter. Its
  `UpdateForwardingParameters` now re-sends the **destination interface** (Access)
  and the **Network Instance** (DNN) alongside the gNB Outer Header Creation — the
  Update FAR is fully specified (matching free5GC), keeping the DNN→VRF binding
  visible on every downlink re-point (activation, handover, path switch).

### `nf-smf`

- `SmContext` gained a `dnn: String` field (set from the create request). The
  establishment passes `&req.dnn`; the modification (`update_sm_context`) reads
  `c.dnn` and passes it — so activations, Service-Request resumes, and handover
  downlink re-points all carry the DNN.

The radian UPF ignores the IE (it allocates the N3 F-TEID regardless); the datapath
is unchanged. The IE is for a downstream controller reading the PFCP stream.

## Boundaries / notes

- The Network Instance is set on the **FAR forwarding parameters** (where free5GC
  sets it and the controller reads it), not on the PDI.
- The **indirect-forwarding** session (design/84) is a transient RAN→UPF→RAN tunnel
  with no DNN→VRF meaning, so it is left without a Network Instance.
- This addresses audit Gap 1 (and folds in its note #3 — the missing destination
  interface on the modification). Gaps 2 (N3 F-TEID CHOOSE bit) and 3's End Marker
  remain open.

## Verification

- `cargo test --workspace --exclude bdd` — green (**186** tests). New:
  - pfcp `network_instance_carries_the_dnn` — the establishment's uplink + downlink
    Create FARs both carry Network Instance = `"internet"`; the modification's
    Update FAR carries the Network Instance, the destination interface, and the OHC.
  - All existing callers updated to the new signatures (nf-smf, nf-upf, n6, bdd,
    pfcp tests).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD N6 datapath feature — 2/2 scenarios green.** This is the real end-to-end
  check: it drives a live PFCP **session establishment + modification** (now
  carrying the Network Instance) through radian's UPF in a namespace, and the
  packet round-trips — confirming the IE doesn't disturb the datapath.
- The `@sim` e2e scenario remained blocked locally by an unrelated `zebra-rs`
  process holding the host UPF's N4 port (`127.0.0.8:8805`); CI verifies it.

## Known limitations / next steps

- **Gap 2** — set the CHOOSE (CH) bit on the uplink PDI F-TEID (standards-compliant
  UPF-allocation signal) instead of the CH=0 placeholder + Created-PDR readback.
- **Gap 3 (End Marker)** — send a GTP-U End Marker on a downlink path switch to
  flush the old path in order.
- Per-DNN Network Instance **naming policy** (currently the DNN string verbatim).
