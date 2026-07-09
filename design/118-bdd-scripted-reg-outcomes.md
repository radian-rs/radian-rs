# BDD Scripted Registration Outcomes (116b)

> Built 2026-07-09 on branch `feat/bdd-scripted-reg-outcomes`. Second slice of the
> design/116 plan (after 116a / design/117): three more `@scripted` registration
> scenarios exercising authentication and slice **outcomes** end-to-end against the live
> core — D5 (AUTS resync), D7 (slice reject #62), D8 (requested-NSSAI intersection).

## What was built

### Shared-crate helpers (each unit-tested)

- **`aka::ue_recover_sqn(sub, rand, autn) -> Option<[u8; 6]>`** — the USIM recovers the
  network's SQN from AUTN (`SQN = AUTN[0..6] ⊕ AK`, verifying MAC-A). A UE compares this
  against its stored SQN to tell a fresh challenge from a synchronisation failure.
- **`nas::registration_request_suci_with_nssai(mcc, mnc, msin, ue_sec_cap, requested)`** —
  a SUCI Registration Request carrying a **Requested NSSAI** (IEI 0x2F); the existing
  `registration_request_suci` now delegates with an empty list.

### `bdd/src/ran.rs` — `ScriptedUe` grows a USIM SQN model

- `sqn_ms: Option<[u8; 6]>` + `set_sqn_ms` — when set, `authenticate` checks the challenge
  is strictly ahead of it.
- `authenticate` now returns **`ChallengeReply`** — `Response(RES*)` when the challenge is
  accepted, or `SynchFailure(AUTS)` (built via `aka::compute_auts`) when the SQN is stale.
  On acceptance it adopts the network's fresher SQN.
- `registration_request_requesting(slices)` — a SUCI registration asking for specific
  slices.

### Feature scenarios (`scripted_registration.feature`)

- **D8 — requested NSSAI ∩ subscription**: the UE requests `[sst1/010203, sst2]`; the
  accept (read UE-side) allows `sst1/010203` (subscribed) and rejects `sst2`.
- **D7 — unsubscribed slice rejected**: the UE requests only `sst2`; after security is
  established the AMF answers a **Registration Reject 5GMM cause #62** carrying the rejected
  NSSAI and a T3346 back-off timer, then a **UEContextReleaseCommand**.
- **D5 — stale SQN → AUTS resync (the marquee scripted-only one)**: the UE's USIM is set
  ahead of the network, so it rejects the first challenge with an AUTS; the AMF resynchronises
  through the **real** AUSF → UDM → UDR (design/61), re-challenges with a fresh SQN, and the
  UE accepts → the AMF proceeds to the Security Mode Command. This is the first time the SQN
  resync path is driven by a full scripted registration, not just an SBI-level unit test.

All three reuse the 116a auth/security steps; the scenarios share the one core the first
scenario starts (the free processes persist across scenarios — the `datapath_e2e` pattern),
and each opens its own gNB association + UE.

## Found gap (deferred, not a regression)

**D6 (wrong RES\* → abort) is intentionally NOT included.** Driving a scripted UE with a
corrupted RES\* revealed that the AMF's `complete_authentication` returns `None` on an AUSF
confirmation failure — it sends **nothing**: no Authentication Reject, no UE Context Release.
Per TS 24.501 §5.4.1.3.7 the AMF should send an Authentication Reject and release the
connection. This is a real compliance gap the scripted tier surfaced; it wants its own
fix-slice (AMF behaviour change + the D6 assertion), so it is recorded here rather than
asserted as correct.

## Verification

- `cargo test -p aka -p nas` — green (aka 8, nas 32; the 3 new helper tests pass).
- `cargo test --workspace --exclude bdd` — green (30 test binaries).
- **`cargo test -p bdd` — 2 features / 7 scenarios / 52 steps GREEN**, clean teardown: the
  three new scenarios run against the live NRF/UDR/UDM/AUSF/PCF/SMF/AMF over real SCTP + SBI
  (D5 exercises the real resync round-trip); the N6 datapath feature is unaffected.
- `cargo clippy -p aka -p nas -p bdd --tests` — no net-new warnings (6 pre-existing before
  and after; my insertions only shifted their line numbers).

## Boundaries / next

- D5 asserts up to the post-resync Security Mode Command (the resync-specific proof); the
  post-SMC path is already covered by D1.
- Still ahead in `scripted_registration`: **D6** (needs the AMF Authentication-Reject fix
  above), **D3/D4** (GUTI re-registration + Identity Request fallback — need a two-registration
  UE flow), **D9** (registration area = gNB TA ∪ UE TAI, needs a UE arriving from a different
  TAC), **D10** (unsubscribed DNN → 5GSM reject #27 + T3396 — needs UE-side PDU-session
  signalling). Then the idle / handover / lifecycle features (design/116 phases 116c–e).
