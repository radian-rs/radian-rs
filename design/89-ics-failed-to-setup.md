# Failed-to-Setup Handling on the Initial Context Setup Response

> Built 2026-07-03 on branch `feat/ics-failed-to-setup`. Design
> [88](88-ics-inline-pdu-sessions.md) carried the reactivated PDU sessions inline
> in the ICS and installed the gNB's downlink from the ICS Response's **admitted**
> list — but a session the gNB **rejected** (`PDUSessionResourceFailedToSetupList
> CxtRes`, TS 38.413 §9.2.2.2) was silently ignored, leaving the SMF/UPF with a
> session the RAN never established (and the AMF would try to reactivate it on the
> next resume). This handles the failed list: the AMF releases each rejected
> session at the SMF and drops it from the UE context.

## What was built

### `ngap`

- `initial_context_setup_response_with_results(amf, ran, admitted, failed)` — the
  general ICS Response builder. `admitted` = `(psi, gnb_dl_teid, addr)` →
  `PDUSessionResourceSetupListCxtRes`; `failed` = `(psi, radio-network cause)` →
  `PDUSessionResourceFailedToSetupListCxtRes` (each cause in a
  `PDUSessionResourceSetupUnsuccessfulTransfer`). Either list is omitted when
  empty. `initial_context_setup_response_with_sessions` is now a thin wrapper (no
  failures).
- `initial_context_setup_failed_session_ids(pdu) -> Vec<(u8, u8)>` — the AMF-side
  parser for the failed list: `(psi, cause)` per rejected session. Empty when
  every inline session was admitted (or the ICS carried none).
- `cause_value(&Cause)` — a small helper reading the numeric out of any `Cause`
  group (for logging without threading each group's constants).

### `nf-amf` — `on_initial_context_setup_response`

After installing the admitted sessions' downlinks (design/88), the handler now
iterates the failed list: for each rejected PSI it looks up the tracked SM
context, calls `release_sm_context` (tearing down the SMF/UPF datapath), and
removes the session from `ctx.sm_refs` — so a later resume won't try to reactivate
a session the RAN refused.

## Boundaries / notes

- The **cause** is logged only (the AMF's action — release — is the same whatever
  the reason); the group (radio-network / transport / …) is dropped, so a
  radio-network `28` and a NAS `28` log identically.
- **No retry** — a rejected session is released, not re-attempted on another
  resource. (Real behaviour is operator/cause-dependent.)
- The **UE is not told** its session was released here (no N1 PDU Session Release
  Command / Allowed PDU Session Status in the accept) — the UE learns on its next
  interaction. Reconciling the UE's view is the design/87 PDU-Session-Status
  follow-up.

## Verification

- `cargo test --workspace --exclude bdd` — green (**177** tests). New/updated:
  - ngap `initial_context_setup_roundtrips` (extended) — a response admitting one
    session (5) and rejecting another (6) round-trips both lists, and the rejected
    session's cause (`MULTIPLE_PDU_SESSION_ID_INSTANCES`) reads back via
    `initial_context_setup_failed_session_ids`; an all-admitted response has an
    empty failed list.
  - nf-amf `ics_response_installs_inline_session_downlinks` (extended) — the gNB
    admits PSI 5 (installs its DL F-TEID) and rejects PSI 6: the mock SMF sees one
    `release` for PSI 6's SM context, PSI 6 is dropped from `sm_refs`, PSI 5 is
    kept; a session-less response releases nothing.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` registration
  ICS carries no inline sessions/failures, so the happy path is untouched.
- The failed-list path isn't sim-drivable (free-ran-ue admits the sessions it is
  asked to set up) — integration-tested.

## Known limitations / next steps

- **Per-session S-NSSAI** on the inline setup (still fixed sst 1, design/88).
- **UE-side reconciliation** — Allowed PDU Session Status in the accept / an N1
  release so the UE drops a session the RAN rejected (ties into the design/87 PDU
  Session Status follow-up).
- **Retry** a rejected session on alternative resources rather than releasing.
