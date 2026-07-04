# Finalise a PDU Session Release on the UE's N1 Complete

> Built 2026-07-03 on branch `feat/release-finalize-on-complete`. Design
> [91](91-network-pdu-session-release.md) finalised a network-initiated release at
> the SMF on the **N2 Release Response** and treated the UE's N1 PDU Session
> Release Complete as a bare ack — a simplification it flagged. This corrects the
> ordering to TS 23.502 §4.3.4 (the SMF's N4 delete follows the UE's **Release
> Complete**) and adds a guard timer so a silent UE can't strand the session.

## What was built (`nf-amf`)

- `UeContext.releasing: HashSet<u8>` — PDU sessions with a release outstanding
  (command sent, awaiting the UE's N1 complete).
- `on_network_release` now marks the session `releasing` and **arms a guard timer**
  (`arm_release_guard`, mirroring `arm_t3522`) when it sends the Release Command.
- `on_release_response` (the N2 Release Response) no longer finalises — it logs
  that the gNB freed the RAN resources and leaves the session tracked, awaiting the
  complete. (Now synchronous; no SMF call.)
- `finalize_release(ues, amf_smf, amf_ue_id, psi)` — the shared, **idempotent**
  finaliser: `release_sm_context` at the SMF (N4 delete / IP release) and drop the
  session from `sm_refs` + `releasing`. A no-op if the session isn't releasing (so
  a late guard firing after the complete, or a stray complete, does nothing).
- The `dispatch_uplink_nas` release-complete branch (0xD4) now calls
  `finalize_release` — the strict-ordering finalisation point.
- `UeCmd::ReleaseGuardExpiry { amf_ue_id, psi }` + its select-loop arm:
  `finalize_release` if the session is still `releasing` (the UE never answered).
  Guard interval `RELEASE_GUARD_SECS` = 6 (env `RADIAN_AMF_RELEASE_GUARD_SECS`).

Flow: Release Command (mark releasing + arm guard) → N2 Release Response (RAN freed,
still pending) → UE N1 Release Complete → `finalize_release`. If the complete never
arrives, the guard fires `finalize_release` instead.

## Boundaries / notes

- The guard **finalises** on expiry rather than **retransmitting** the Release
  Command first — a simpler backstop (one attempt, then finalise anyway to avoid a
  stranded UPF datapath).
- The guard timer is per `(UE, psi)` and one-shot; a second release for the same
  session while one is pending re-arms it (last wins) but the finaliser's
  idempotency keeps the SMF release single.
- Still single-session per command and CM-CONNECTED only (design/91 boundaries).

## Verification

- `cargo test --workspace --exclude bdd` — green (**183** tests). Updated/new:
  - nf-amf `network_release_finalises_on_ue_complete` — the N2 Release Response
    frees the RAN side but does **not** finalise (the mock SMF sees no release, the
    session stays tracked); the UE's N1 Release Complete over UL NAS
    (`dispatch_uplink_nas`) finalises it (SMF release, `sm_refs`/`releasing`
    cleared); a late guard firing is idempotent (no double release).
  - nf-amf `network_release_guard_finalises_a_silent_ue` — with no complete, the
    guard's `finalize_release` releases the session at the SMF anyway.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` datapath is
  unaffected (no release triggered).
- Not sim-drivable (free-ran-ue exposes no network-release trigger) —
  integration-tested.

## Known limitations / next steps

- **Retransmit** the Release Command on the guard (with a bounded count) before
  finalising, rather than finalising on the first expiry.
- **Multi-session release** in one command (list of PSIs, per-session pending).
- **CM-IDLE release** — release a retained session and inform the UE on return.
