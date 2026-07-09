# AMF Authentication Reject on a Failed RES* (116b follow-up / D6)

> Built 2026-07-09 on branch `feat/amf-auth-reject`. Closes the gap the scripted tier
> surfaced in design/118: a rejected RES* left the AMF silent. Now the AMF signals an
> **Authentication Reject** and releases the UE (TS 24.501 §5.4.1.3.7), and the previously
> deferred scripted scenario **D6** asserts it.

## The gap (found by design/118)

Driving a scripted UE with a corrupted RES* showed `complete_authentication` returned
`None` on an AUSF confirmation failure — the AMF sent **nothing**: no Authentication
Reject, no UE Context Release. The UE was left waiting; the gNB kept the RAN context. Per
TS 24.501 §5.4.1.3.7 the AMF must send an Authentication Reject (the UE then deletes its
native 5G security context and enters 5GMM-DEREGISTERED) and should release the connection.

## What was built

### `nas`

- **`authentication_reject() -> Vec<u8>`** — the 5GMM Authentication Reject (TS 24.501
  §8.2.5, no IEs), sent unprotected since no NAS security context exists yet.

### `nf-amf`

- **`complete_authentication` now returns `Vec<(NGAP_PDU, &'static str)>`** (was a single
  `Option`) and takes the whole `Nas5gsMessage` (extracting RES* itself). Authentication is
  *not accepted* when the AUSF confirm errors, returns `success = false`, **or** the response
  carries no RES* → the AMF emits `[AuthenticationReject (DL NAS), UEContextReleaseCommand]`,
  removes the UE from `UE_DIRECTORY`, and drops the AMF context. The success path is
  unchanged (returns the Security Mode Command). A post-success internal error (missing
  K_SEAF/SUPI, or no common integrity algorithm) is **not** treated as "authentication not
  accepted" — it stays a silent drop, so a spec-inappropriate reject isn't sent for an AMF
  bug.
- The `AuthenticationResponse` handling moved into the multi-downlink special-case in
  `on_uplink_nas` (alongside Security Mode Complete / Deregistration, which also answer with
  more than one downlink); its old single-downlink arm in `dispatch_uplink_nas` is removed.

### `bdd` — scenario D6

`scripted_registration.feature`: the UE registers, is challenged, answers with a **wrong
RES\*** (`ScriptedUe::wrong_challenge_response` — the real RES* with a corrupted byte), and
the AMF answers an **Authentication Reject** (read UE-side, unprotected) followed by a
**UEContextReleaseCommand**.

## Verification

- `cargo test -p nas -p nf-amf` — green (nas 33, nf-amf 51; the return-type change broke no
  existing AMF test).
- **`cargo test -p bdd` — 2 features / 8 scenarios / 58 steps GREEN**: D6 drives the new
  reject path against the live core; the rest of the scripted registration suite and the N6
  datapath feature are unaffected.
- `cargo test --workspace --exclude bdd` — green (30 test binaries).
- `cargo clippy -p nas -p nf-amf -p bdd --tests` — no net-new warnings (28 sites before ==
  after).

## Boundaries / next

- The Authentication Reject carries no EAP message (5G-AKA, not EAP-AKA'); the release cause
  is `NORMAL_RELEASE`.
- The `scripted_registration` D-series now has D1/D5/D6/D7/D8; still ahead: **D3/D4** (GUTI
  re-registration + Identity Request fallback), **D9** (registration area = gNB TA ∪ UE TAI),
  **D10** (unsubscribed DNN → 5GSM reject #27 + T3396 — needs UE-side PDU-session signalling).
  Then the idle / handover / lifecycle features (design/116 phases 116c–e).
