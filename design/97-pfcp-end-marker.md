# GTP-U End Marker on a Downlink Path Switch

> Built 2026-07-04 on branch `feat/pfcp-end-marker`. The interop audit (`gap.txt`)
> Gap 3 was largely a misread — radian already re-programs the downlink FAR OHC on a
> handover/path switch (designs 79–84) — but it flagged one real sub-gap: radian
> never asked the UPF to send a GTP-U **End Marker** on the old path. free5GC does
> (`SendEndMarker`), so the target gNB can deliver downlink in order across the move.
> This adds the End Marker request on a genuine re-point.

## What was built

### `crates/pfcp`

- `session_modification_request` gained a `send_end_marker: bool` param. When set,
  it adds the **PFCPSMReq-Flags** IE with the **SNDEM** bit (Send End Marker Packets,
  TS 29.244 §8.2.79) to the Session Modification Request — telling the UPF to emit a
  GTP-U End Marker on the old downlink tunnel before switching to the new OHC.

### `nf-smf`

- `update_sm_context` reads the session's current gNB target and sets
  `send_end_marker = old_gnb.is_some_and(|g| g != (new_teid, new_addr))` — true only
  when the downlink is re-pointed from an **existing, different** gNB tunnel (a
  handover / Xn path switch). A first activation or a Service-Request re-activation
  (no prior gNB, or the same one) sends no End Marker.

Since path switch (design/79) and N2 handover (design/81) both drive
`update_sm_context` with the new gNB F-TEID, the End Marker is now requested on
every real downlink move automatically.

## Boundaries / notes

- **SMF-side signalling only.** radian's own UPF does not yet *act* on SNDEM (emit
  the GTP-U End Marker packet) — the flag is for a downstream UPF (e.g. the MUP-C).
  Making radian's UPF emit the End Marker on the old N3 tunnel is a follow-up (and
  only observable on a real 2-gNB handover, which isn't sim-drivable).
- The condition is per-session (one downlink FAR); the End Marker rides the same
  Session Modification that re-points the OHC.
- This closes the only real part of audit Gap 3.

## Verification

- `cargo test --workspace --exclude bdd` — green (**188** tests). New/updated:
  - pfcp `end_marker_requested_only_on_a_repoint` — a plain downlink install carries
    no PFCPSMReq-Flags; a re-point carries the IE with SNDEM set.
  - nf-smf integration test extended — after installing the downlink at one gNB, a
    second UpdateSMContext to a **different** gNB (the re-point, which now carries the
    End Marker request) is accepted by the real UPF and the downlink follows to the
    new tunnel — proving the SNDEM-carrying modification doesn't disturb the UPF.
  - All `session_modification_request` callers updated (default `false`).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD N6 datapath feature 2/2 green** — a live PFCP establishment + modification
  through the real UPF; the datapath is unaffected. The `@sim` e2e scenario remained
  blocked locally by an unrelated `zebra-rs` process on the host UPF's N4 port
  (`127.0.0.8:8805`); CI verifies it. The End Marker itself needs a 2-gNB handover
  (not sim-drivable) — integration-tested via the nf-smf re-point.

## Known limitations / next steps

- **UPF emits the End Marker** — honour SNDEM by sending a GTP-U End Marker (message
  type 254) to the old gNB N3 tunnel before switching.
- The End Marker count / retransmission (spec allows a small burst) is not modelled.
