# Multi-Session PDU Release in One Request

> Built 2026-07-04 on branch `feat/multi-session-release`. Designs
> [91](91-network-pdu-session-release.md)–[93](93-cm-idle-pdu-release.md) released
> a **single** PDU session per request. This lets one SMF request name several
> sessions; the AMF releases each — one N2 Release Command per session (the N2
> command carries a single N1), each finalising independently (design/92).

## What was built (`nf-amf`)

- The `release_session` callback now parses a **list**: `pduSessionIds` (array) or
  the single `pduSessionId` (unchanged for existing callers). Empty ⇒ `400`.
- `UeCmd::ReleaseSession` carries `psis: Vec<u8>` (was a single `psi`).
- `on_network_release(ues, amf_ue_id, psis: &[u8], cause, tx)` loops: one N2
  PDU Session Resource Release Command (+ its N1) **per** requested session,
  marking each `releasing` and arming its own guard; unknown sessions are skipped.
  Returns one downlink per released session.
- **CM-IDLE** path: releases each requested session found in the retained context
  at the SMF and drops them from `sm_refs` (design/93), so the design/90 PDU
  Session Status reconciliation omits them on return. `404` only when the UE holds
  **none** of the requested sessions.

Each session still finalises independently — on its own N1 Release Complete or its
own guard expiry (design/92) — so a multi-session release is just N concurrent
single-session procedures sharing one trigger.

## Boundaries / notes

- **One N2 command per session** (not one command listing all PSIs): the N2
  PDUSessionResourceReleaseCommand carries a single NAS-PDU (one N1), so N sessions
  need N commands. The wire-level `PDUSessionResourceToReleaseListRelCmd` stays
  single-item.
- **Partial success** — CM-CONNECTED returns `202` as soon as the command is
  queued (unknown PSIs are skipped in the association task, logged); CM-IDLE
  returns `202` if **any** named session was released, `404` if none.
- Cause is shared across the batch (one `cause` for all listed sessions).

## Verification

- `cargo test --workspace --exclude bdd` — green (**185** tests). New/updated:
  - nf-amf `multi_session_release_fans_out_per_session` — one call for `[5, 6]`
    emits **two** N2 Release Commands (each with its own N1 for a distinct PSI),
    both marked `releasing`; each finalises on its own N1 complete (the mock SMF
    releases both, `sm_refs` empties).
  - nf-amf `cm_idle_pdu_session_release` (extended) — a `pduSessionIds: [6, 9]`
    request releases the held session 6 (skipping the unheld 9) → `202`, both
    idle sessions gone.
  - The design/91/92 single-session tests updated to the slice signature.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD:** the N6 datapath feature passes (2 scenarios). The `@sim` e2e scenario
  could not run locally this session — an **unrelated** process (`zebra-rs`) was
  holding `127.0.0.8:8805`, which collides with the host UPF's `0.0.0.0:8805` N4
  bind, so the datapath UPF wouldn't start (nothing to do with the release path,
  which `@sim` doesn't exercise). CI verifies the full `@sim` run. Not otherwise
  sim-drivable (free-ran-ue exposes no release trigger).

## Known limitations / next steps

- **Reactivate-race** hardening for CM-IDLE release (design/93 backlog).
- **Retransmit** the Release Command on the guard before finalising (design/92).
- **Per-session cause** in one request (currently one cause for the batch).
