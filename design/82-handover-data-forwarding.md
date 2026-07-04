# Data Forwarding During N2 Handover — Direct Forwarding

> Built 2026-07-04 on branch `feat/handover-data-forwarding`. Design
> [81](81-n2-handover.md)'s N2 handover moved the UE but **dropped every downlink
> packet in flight** — nothing carried the forwarding tunnels. This closes that
> gap for **direct forwarding** (TS 23.502 §4.9.1.3.2): the source signals
> forwarding availability, the target offers a **DL forwarding F-TEID** in its
> acknowledge, and the AMF relays it to the source in the **Handover Command** —
> the source then forwards in-flight downlink packets straight to the target over
> Xn-U while the UE moves.

## What was built

### `ngap` — the forwarding IEs on all three legs

- `handover_required` gained `direct_forwarding: bool` → each
  `HandoverRequiredTransfer` carries *Direct Forwarding Path Availability*
  (`direct-path-available`); the parser folds it back out (any session marked ⇒
  `true`).
- `handover_request_acknowledge`'s admitted sessions became
  `(psi, dl_teid, dl_addr, Option<(fwd_teid, fwd_addr)>)` — the optional
  **`dL-Forwarding-UP-TNL-Information`** in the
  `HandoverRequestAcknowledgeTransfer`; parsed back symmetrically.
- `handover_command` gained `forwarding: &[(psi, teid, addr)]` → a
  **`PDUSessionResourceHandoverList`** whose `HandoverCommandTransfer` carries
  the target's DL forwarding F-TEID per session (IE omitted when no session
  forwards); `handover_command_params` returns the list.

### `nf-amf`

- `on_handover_required` parses and logs the source's forwarding availability.
- `on_handover_request_ack` splits the target's answer: the **DL F-TEIDs**
  (stored in the pending handover — the UPF re-points to them at Notify,
  unchanged) and the **forwarding F-TEIDs**, which are relayed to the source in
  the Handover Command. The AMF's role in direct forwarding is exactly this
  relay — the forwarding traffic itself is RAN-to-RAN (Xn-U) and never touches
  the core.

## Boundaries / notes

- **Direct forwarding only.** Indirect forwarding (no Xn-U between the gNBs —
  the UPF relays via SMF-established N4 forwarding tunnels) is not modelled; a
  source that reports no direct path simply gets no forwarding tunnels and
  in-flight packets still drop in that case.
- Per-QoS-flow forwarding granularity (`qosFlowToBeForwardedList`) is not
  modelled — forwarding is per session.
- The source's availability flag is informational to the AMF (logged); the
  decision to offer a tunnel is the target's (its acknowledge), per spec.

## Verification

- `cargo test --workspace --exclude bdd` — green (**169** tests). Extended:
  - ngap `n2_handover_messages_roundtrip` — the availability flag round-trips
    (true and false), the acknowledge carries the forwarding F-TEID
    (`0xBB / 10.0.9.6`) alongside the DL F-TEID, the Handover Command carries
    the forwarding list (and omits the IE when empty).
  - nf-amf `n2_handover_orchestrates_source_to_target` — the target's
    acknowledge now offers a forwarding tunnel and the source's Handover
    Command is asserted to carry exactly `[(5, 0xBB, 10.0.9.6)]` + the
    container; the UPF re-point at Notify still targets the *real* DL F-TEID
    (`0xAA`), not the transient forwarding tunnel.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green.**
- Not sim-drivable (two gNBs; design/64/65 precedent) — wire encodings APER
  round-trip-tested, orchestration integration-tested.

## Known limitations / next steps

- **Indirect data forwarding** — SMF/UPF N4 forwarding tunnels when Xn-U is
  absent.
- **Handover failure paths** (Preparation Failure / Cancel, stale in-flight
  expiry) — the design/81 backlog.
- End-of-forwarding marker handling (GTP-U end marker) is a UPF concern, not
  modelled.
