# Network-Initiated PDU Session Release

> Built 2026-07-03 on branch `feat/network-pdu-session-release`. Design
> [90](90-pdu-session-status-reconcile.md) reconciled session state at a CM-IDLE
> return but left its boundary open: a **connected** UE was never told mid-session
> when the network dropped a PDU session. This builds the network-initiated PDU
> session release procedure (TS 23.502 §4.3.4) — the SMF asks the AMF to release a
> session, the AMF tears down the RAN resources (N2) and tells the UE (N1), the
> gNB confirms, and the AMF finalises at the SMF. The N2/N1 counterpart to the
> design/50 modification.

## What was built

### `nas`

- `pdu_session_release_command(psi, pti, cause)` — the 5GSM **PDU Session Release
  Command** (message type 0xD3 + mandatory 5GSM cause; network-initiated ⇒ PTI 0).
- `pdu_session_release_complete(psi, pti)` (0xD4, UE side) and
  `is_pdu_session_release_complete(container)` — the detector the AMF uses to
  recognise the UE's final N1 ack. `sm_cause::REGULAR_DEACTIVATION` (#36).

### `ngap`

- `pdu_session_resource_release_command(amf, ran, psi, nas)` — the N2 **PDU Session
  Resource Release Command** (TS 38.413 §9.2.1.6): the N1 rides as the NAS-PDU, the
  per-session transfer carries a NAS *normal-release* cause. `nas_pdu_from_release_
  command` (gNB side) extracts `(psi, N1)`.
- `pdu_session_resource_release_response(amf, ran, psi)` (test/sim) +
  `release_response_result` — the gNB's confirmation and its parser.

### `nf-amf`

- SBI callback `POST /namf-comm/v1/ue-contexts/{supi}/release` (`{pduSessionId,
  cause?}`) → resolves the UE via `UE_DIRECTORY`, sends `UeCmd::ReleaseSession` to
  the owning association task (`202` reachable / `404` not). Mirrors `modify_policy`.
- `on_network_release` builds the N1 Release Command (protected DL NAS) + the N2
  Release Command. The session stays tracked until the gNB confirms.
- `on_release_response` (new `PDUSessionResourceReleaseResponse` handle_ngap arm):
  on the gNB's confirmation, `release_sm_context` at the SMF (N4 delete / IP
  release) and drop the session from `ctx.sm_refs`.
- The UE's **PDU Session Release Complete** (0xD4 over UL NAS) is now recognised in
  `dispatch_uplink_nas` and acknowledged — it no longer falls through to the
  establishment (CreateSMContext) path.

## Boundaries / notes

- The session is finalised at the SMF on the **N2 Release Response** (not the UE's
  N1 Release Complete) — a simplification; the release complete is a pure ack. In
  strict TS 23.502 order the SMF's N4 delete follows the release complete.
- **CM-IDLE** targets aren't handled here (this releases a *connected* UE); a
  session dropped while idle is reconciled at the UE's next return (design/90).
- Single session per command (no multi-session release list); the N2 transfer
  cause is fixed *normal-release*.

## Verification

- `cargo test --workspace --exclude bdd` — green (**182** tests). New:
  - nas `pdu_session_release_command_and_complete_layout` — the 0xD3/0xD4 octet
    layouts, the detector, and a UL-NAS-carried release complete round-trip.
  - ngap `pdu_session_resource_release_roundtrips` — the command carries the N1 +
    psi, the response reports the released session back.
  - nf-amf `network_release_tears_down_session_ran_and_ue` — the N2 Release Command
    carries a UE-decodable N1 Release Command (0xD3 / cause #36); on the gNB's
    Release Response the mock SMF sees the release, the session drops from
    `sm_refs`; a release for an absent session is a no-op.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` datapath is
  unaffected (no release is triggered).
- Not sim-drivable (free-ran-ue exposes no network-release trigger) —
  integration-tested end to end.

## Known limitations / next steps

- **Finalise on the N1 Release Complete** (strict §4.3.4 ordering) + a release
  timer / retransmission.
- **Multi-session release** in one command.
- **CM-IDLE release** (release a retained session and inform the UE on return).
