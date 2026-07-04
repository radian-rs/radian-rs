# Network-Initiated PDU Session Release for a CM-IDLE UE

> Built 2026-07-03 on branch `feat/cm-idle-pdu-release`. Designs
> [91](91-network-pdu-session-release.md)/[92](92-release-finalize-on-complete.md)
> built network-initiated PDU session release for a **CM-CONNECTED** UE (N2 Release
> Command + N1). A release request for a **CM-IDLE** UE fell through to `404` — the
> retained session was never torn down. This handles it: with no N2 to signal, the
> AMF releases the retained session at the SMF now and lets the design/90 PDU
> Session Status reconciliation inform the UE on its next return.

## What was built (`nf-amf`)

The `release_session` callback (`POST /namf-comm/v1/ue-contexts/{supi}/release`)
now has two arms:

- **CM-CONNECTED** (`UE_DIRECTORY` hit) — unchanged: `UeCmd::ReleaseSession` to the
  owning association, which runs the full N2/N1 procedure (designs 91/92).
- **CM-IDLE** (directory miss, or the association closed mid-call) — find the
  session in the retained context (by SUPI), `release_sm_context` at the SMF (tear
  down the UPF datapath now), and drop the PSI from the retained `sm_refs`. `202`.
  When the UE next returns (Service Request / registration update), the accept's
  **PDU Session Status** IE (design/90) no longer lists the session, so the UE
  releases it locally.

`404` only when the UE holds no such session (neither connected nor retained with
that PSI). The SMF release reuses `release_sm_context` (as `evict_stale_retained`
already does for retained sessions), constructing an `AmfSmf` from `NRF_BASE`.

## Boundaries / notes

- **No paging** — the session is being torn down, so there's no value bringing the
  UE up just to tell it; the natural next return reconciles it (TS 23.502 §4.3.4
  permits release-without-paging for a CM-IDLE UE).
- **Release racing a resume** — if the UE resumes between the retained lookup and
  the PSI removal, it may reactivate the session (design/88) just as the SMF tears
  it down; the removal then no-ops (the context left `RETAINED`). A small,
  accepted window; the common idle-stays-idle case is clean.
- The retained context isn't otherwise disturbed (registration, other sessions,
  security all intact) — only the released PSI is dropped.

## Verification

- `cargo test --workspace --exclude bdd` — green (**184** tests). New:
  - nf-amf `cm_idle_pdu_session_release` — a retained CM-IDLE UE with sessions
    {5, 6}; a release POST for PSI 5 returns `202`, the mock SMF sees PSI 5's SM
    context released, the retained `sm_refs` drops 5 and keeps 6; a release for a
    PSI the UE doesn't hold returns `404`.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` datapath is
  unaffected (no release triggered).
- Not sim-drivable (free-ran-ue can't go CM-IDLE and exposes no release trigger) —
  integration-tested.

## Known limitations / next steps

- **Reactivate-race** hardening (mark the retained session release-pending so a
  concurrent resume skips reactivating it).
- **Multi-session release** in one request (list of PSIs).
- **Retransmit** the Release Command on the guard (design/92 backlog) before
  finalising a CM-CONNECTED release.
