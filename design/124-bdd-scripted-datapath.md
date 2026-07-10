# BDD Scripted Datapath Echo (user plane, no simulator)

> Built 2026-07-09 on branch `feat/bdd-scripted-datapath`. Seventh BDD slice of the design/116
> plan and the milestone the scripted tier was building toward: a **registered UE moves a real
> packet end-to-end** through the fully-signalled stack — register → PDU session → GTP-U echo —
> with **no free-ran-ue and no namespaces**. Pure test code; no crate behaviour changed.

## The topology trick

The scripted gNB (the test process) and the UPF both want GTP-U port **:2152** on the host.
`datapath_e2e` (@sim) solves this by putting the RAN in namespaces; this slice does it far more
cheaply — the UPF binds a **distinct loopback alias**:

- The whole core runs on the host. The UPF is spawned with `RADIAN_UPF_BIND=127.0.0.2` and
  `RADIAN_UPF_N3_ADDR=127.0.0.2`, so it binds and advertises its N3/N4 on `127.0.0.2`; the SMF
  reaches it at `127.0.0.2:8805`. (The UPF source already documents this exact escape hatch:
  "N3 collides with another GTP-U … bind it to a different alias".)
- The scripted gNB plays real GTP-U on `127.0.0.1:2152`. `127.0.0.1:2152` and `127.0.0.2:2152`
  are distinct sockets — no collision, no `CAP_NET_ADMIN` beyond the UPF's own N6 TUN.

The N6 side is unchanged from `datapath_e2e`: the UPF's `n6upf0` TUN (`10.45.0.1/16`) lives on
the host, and the host kernel auto-answers the ping to the gateway.

## What was built (all in `bdd`)

- `start_core` now binds the UPF to `127.0.0.2` (N3/N4) and points the SMF's N4 there. This is
  transparent to the control-plane scenarios (they never dial N3), so `scripted_registration`
  is unaffected.
- The PDU-session step now reports the gNB's DL F-TEID at its **real** N3 address
  (`127.0.0.1`) and records the UPF's uplink F-TEID + address; the IP step records the UE's
  assigned address. The AMF's existing `on_pdu_session_setup_response` → `UpdateSMContext`
  installs the downlink at the UPF, so the tunnel is fully programmed by signalling.
- New step **"the UE can reach the data network gateway `…` over the datapath"** — reuses
  `bdd::datapath::ping_through_datapath` to GTP-U-encap an ICMP echo (UE → gateway) on the
  UPF's uplink F-TEID and confirm the reply returns on the gNB's DL F-TEID (the full
  N3 → N6 → N3 round trip).
- New feature **`scripted_datapath.feature`**: register → PDU session → assigned IP → **the
  datapath echo**, with the mandated teardown.

## Verification

- **`cargo test -p bdd` — 3 features / 16 scenarios / 155 steps GREEN** (deterministic across
  reruns): the new scenario moves a real packet through the signalled stack; the
  `scripted_registration` (14) and `n6_datapath` (2) features are unaffected by the
  UPF-bind change.
- `cargo clippy -p bdd --tests` — no net-new warnings (1 site before == after).
- No workspace crate changed.

## Significance

This closes the loop on the scripted tier: it now proves **both** the full control plane
(register / auth / policy / session / idle) **and** the user plane (a real packet through a
signalled PDU session) — end to end, against the live core, CI-runnable, with no external
simulator. `@sim` (free-ran-ue) keeps its wire-compat role; the scripted tier now matches its
end-to-end reach on the parts free-ran-ue can drive, and exceeds it on the parts it can't
(CM-IDLE, GUTI re-registration, …).

## Next

The remaining design/116 fronts are the rest of the **idle arc** (paging + DL buffering,
design/65 — now datapath-testable with this loopback topology; T3513, design/74) and the
**handover / lifecycle** features. Per-flow QoS / GBR traffic policing (designs 49/51) is also
now drivable over this datapath.
