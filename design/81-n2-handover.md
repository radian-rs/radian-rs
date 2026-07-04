# N2 Handover

> Built 2026-07-04 on branch `feat/n2-handover`. Design
> [79](79-nh-ncc-path-switch.md)/[80](80-release-source-gnb.md) covered the **Xn**
> handover (RAN-coordinated; the AMF only switches the path afterwards). This adds
> the **N2 handover** (TS 23.502 §4.9.1.3, TS 38.413 §8.4.1–8.4.3) — the handover
> the AMF orchestrates itself when Xn isn't available, across both gNB
> associations: **Handover Required** (source) → **Handover Request** to the
> target, carrying the rotated `{NH, NCC}` → **Handover Request Acknowledge** →
> **Handover Command** back to the source → **Handover Notify** → downlink
> switch + context takeover + source release.

## What was built

### `ngap` — the five-message set

- `handover_required` / `handover_required_params` — source→AMF: target gNB id
  (Global RAN Node ID inside Target ID), the PDU sessions to move, the RRC
  source→target transparent container.
- `handover_request` / `handover_request_params` — AMF→target: HandoverType
  intra5GS, cause, UE-AMBR, UE security capabilities, **Security Context
  `{NCC, NH}`** (TS 33.501 §6.9.2.3.2 — the target derives its K_gNB from it),
  allowed NSSAI, GUAMI, per-session `PDUSessionResourceSetupItemHOReq` (reusing
  the setup transfer: the **UPF's UL N3 F-TEID** + QoS flows), the container.
- `handover_request_acknowledge` / `handover_request_ack_params` — target→AMF:
  admitted sessions, each with the **target's DL N3 F-TEID**
  (`HandoverRequestAcknowledgeTransfer`), and the target→source container.
- `handover_command` / `handover_command_params` — AMF→source: relays the
  target's container (the source sends it to the UE via RRC).
- `handover_notify` / `handover_notify_params` — target→AMF: the UE arrived
  (with its ULI).
- `gnb_id_from_ng_setup` — the gNB id from the NG Setup's Global RAN Node ID;
  `ng_setup_request` gained a `gnb_id` parameter.

### `nf-amf` — the orchestration

- `GnbLink.gnb_id` — captured from each gNB's NG Setup; **N2-handover target
  resolution** is keyed on it.
- `UeCmd::Forward { pdu, label }` — cross-association signalling: the owning
  select loop sends a pre-built PDU on its own N2 connection.
- `HANDOVERS: Mutex<HashMap<amf_ue_id, PendingHandover>>` — the in-flight state
  (source channel + RAN-UE-ID, the rotated `{NH, NCC}`, the admitted sessions),
  created at Required, filled at Acknowledge, consumed at Notify.
- `on_handover_required` (source association): resolves the target association
  by gNB id, **rotates the NH chain** (burned even if the handover fails), fetches
  each session's UL N3 F-TEID + QoS from its SMF (the same retained-state fetch
  the Service Request resume uses), and Forwards the Handover Request to the
  target.
- `on_handover_request_ack` (target association): records the admitted DL
  F-TEIDs and Forwards the Handover Command to the source.
- `on_handover_notify` (target association): takes the context over from the
  source (`TakeUe` — the source releases its gNB with cause
  *successful-handover*, design/80), applies the rotated NH chain / target
  RAN-UE-ID / new TAC, re-points each admitted session's UPF downlink
  (`UpdateSMContext` → N4 modify), and re-points `UE_DIRECTORY` at the target
  association.

## Boundaries / notes

- **No data forwarding** (direct or indirect) — packets in flight during the
  handover are lost; the Handover Required/Ack transfers carry no forwarding
  tunnels.
- **No Handover Preparation Failure / Cancel**, no expiry of stale `HANDOVERS`
  entries (an unanswered handover leaks its entry until the UE hands over again).
- Sessions the SMF fetch fails for are omitted from the Handover Request;
  admission is whatever the target acknowledges.
- The UL F-TEID fetch reuses `activate_up_connection` (idempotent for an active
  session — it just returns the stored N3 info).

## Verification

- `cargo test --workspace --exclude bdd` — green (**169** tests). New:
  - ngap `n2_handover_messages_roundtrip` — all five messages survive APER
    encode→decode (target gNB id, `{NCC, NH}`, UL/DL F-TEIDs, containers);
    `gnb_id_from_ng_setup` parses back what `ng_setup_request` encodes.
  - nf-amf `n2_handover_orchestrates_source_to_target` — the full flow across
    two simulated associations: Handover Required on the source → the target
    link receives the Handover Request (NCC 1, NH₁ = KDF(K_AMF, K_gNB), the
    UPF's UL F-TEID from the mock SMF, the source's container) → the target's
    acknowledge → the source association receives the Handover Command
    (old RAN-UE-ID, the target's container) → Handover Notify → the context
    moves (target RAN-UE-ID, new TAC, NH chain applied), the mock SMF sees the
    downlink re-point to the target's DL F-TEID (`000000aa`/`10.0.9.5`), the
    source emits the successful-handover release, `UE_DIRECTORY` re-points, and
    the `HANDOVERS` entry is consumed.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green.**
- **Live**: the gNB-id capture is wire-proven — the AMF logs *"gNB Some(788)
  serves TACs Some([[00, 00, 01]])"* against the real free-ran-ue NG Setup
  (788 = 0x314, its configured `gnbId: "000314"`). The handover itself needs two
  gNBs — not sim-drivable (design/64/65 precedent).

## Known limitations / next steps

- **Data forwarding** (direct/indirect tunnels) during the handover.
- **Handover Preparation Failure / Cancel** + expiry of stale in-flight entries.
- **Inter-AMF N2 handover** (the N14 context transfer) — far out of scope for a
  single-AMF core.
