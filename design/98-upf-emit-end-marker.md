# UPF Emits the GTP-U End Marker

> Built 2026-07-04 on branch `feat/upf-emit-end-marker`. Design
> [97](97-pfcp-end-marker.md) made the SMF *signal* a GTP-U End Marker
> (PFCPSMReq-Flags SNDEM) on a downlink path switch, but radian's own UPF ignored
> the flag — the emission was left for a downstream UPF. This makes radian's UPF
> **act** on SNDEM: it sends a GTP-U End Marker (TS 29.281 §7.3.4) on the old
> downlink tunnel when the path switches.

## What was built

### `gtpu`

- `MSG_END_MARKER` (message type 254), the `N3Message::EndMarker { teid }` parse
  variant, and `end_marker(teid)` — a payload-less GTP-U End Marker for a tunnel.

### `crates/pfcp`

- `UpfState.pending_end_markers: Vec<(u32, Ipv4Addr)>` + `take_end_markers()` —
  mirroring the buffered-downlink `pending_flush`/`take_flush` mechanism.
- `set_downlink` gained a `send_end_marker` flag: on a switch (SNDEM set **and** the
  downlink actually moves to a *different* gNB tunnel), the **old** `(gNB TEID, IP)`
  is queued before the OHC is overwritten.
- `handle_n4` parses PFCPSMReq-Flags SNDEM from the Session Modification and passes
  it to `set_downlink`.

### `nf-upf`

- The N4 loop drains `take_end_markers()` (alongside the existing buffered-downlink
  flush) and sends `gtpu::end_marker(old_teid)` to the old gNB's N3 address
  (`:2152`) — so the source gNB learns the old downlink stream has ended and can
  deliver forwarded then direct-path packets in order.

## Boundaries / notes

- **One End Marker** per switch (the spec allows a small burst / retransmission —
  not modelled).
- Emitted only on a genuine **re-point** (SNDEM + a different gNB); a first
  activation, a Service-Request resume, or a same-gNB refresh emits none.
- The End Marker carries the **old gNB's DL TEID** and goes to the old gNB address —
  it is the UPF telling the source gNB "no more downlink on this tunnel."

## Verification

- `cargo test --workspace --exclude bdd` — green (**190** tests). New:
  - gtpu `end_marker_roundtrips` — message type 254, zero length, parses back to
    `EndMarker { teid }`, and is not a G-PDU.
  - pfcp `upf_emits_end_marker_only_on_a_path_switch` — a first install (even with
    SNDEM) and an SNDEM-less re-point queue nothing; a genuine path switch (SNDEM +
    a different gNB) queues exactly one End Marker for the **old** tunnel, consumed
    once.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD N6 datapath feature 2/2 green** — the live establishment + modification +
  packet round-trip is unaffected by the new UPF path (the datapath's modify is a
  first activation → no End Marker). The `@sim` e2e scenario remained blocked
  locally by an unrelated `zebra-rs` process on the host UPF's N4 port; CI verifies
  it. The End Marker itself needs a 2-gNB handover (not sim-drivable) —
  unit/integration-tested at the UPF.

## Known limitations / next steps

- **End Marker burst / retransmission** (TS 29.281 allows more than one).
- End-to-end verification on a real 2-gNB handover once a two-gNB test rig exists.
