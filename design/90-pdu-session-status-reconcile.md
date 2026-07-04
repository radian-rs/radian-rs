# PDU Session Status Reconciliation on a CM-IDLE Return

> Built 2026-07-03 on branch `feat/pdu-session-status-reconcile`. Designs
> [87](87-uplink-data-status.md) and [89](89-ics-failed-to-setup.md) left the UE
> and AMF session views un-reconciled: the AMF never acted on the UE's **PDU
> Session Status** IE (a session the UE locally dropped stayed tracked), and never
> told the UE which sessions the network kept (so a session the network released —
> e.g. a gNB-rejected one, design/89 — lingered on the UE). This wires the **PDU
> Session Status** IE (TS 24.501 §9.11.3.44) both ways on a CM-IDLE return.

## What was built

### `nas`

- The two-octet PSI bitmap is now shared (`psi_bitmap_value` /
  `psis_from_psi_bitmap`) between the Uplink Data Status (design/87) and PDU
  Session Status IEs — the same layout (octet 3 = PSI 0–7, octet 4 = PSI 8–15).
- `pdu_session_status_from_request` — the AMF-side parser: the sessions the UE
  reports active in a **Service Request** or **Registration Request**. `None` when
  the IE is absent (the UE reported nothing — keep everything); `Some(psis)`
  (possibly empty) is the authoritative UE view.
- `service_accept(active_pdu_sessions: Option<&[u8]>)` and `registration_accept(…,
  active_pdu_sessions)` gained the network's **PDU Session Status** IE (included
  when `Some`). `service_request_with_pdu_status` builds the UE-side request;
  `pdu_session_status_from_accept` is the UE-side parser.

### `nf-amf` — `on_service_request`

Before snapshotting `sm_refs` on a CM-IDLE return (Service Request or registration
update):

1. **UE → network.** If the trigger carried a PDU Session Status IE, release each
   session the AMF tracks that the UE did **not** list (`release_sm_context`,
   tearing down the SMF/UPF datapath) and drop it from `ctx.sm_refs`. An absent IE
   reconciles nothing.
2. **Network → UE.** The accept (Service Accept / Registration Accept) carries the
   reconciled active set in its PDU Session Status IE, so the UE releases anything
   it still holds that the network dropped.

The reactivation set (design/87/88) is computed *after* reconciliation, so a
dropped session is neither reactivated nor advertised.

## Boundaries / notes

- **Initial registration** passes `None` (no sessions yet) — its Registration
  Accept is unchanged, so the live `@sim` registration is byte-for-byte as before.
- The design/89 case (a gNB rejects a session in the ICS *Response*, after the
  accept was sent) is still resolved by releasing at the SMF; the UE learns at its
  **next** CM-IDLE return via that return's PDU Session Status. No mid-connection
  N1 PDU Session Release Command is sent to proactively tell a connected UE.
- **Allowed PDU Session Status** IE (§9.11.3.13, the UE's per-access
  re-establishment allowance) is not modelled — only PDU Session Status.

## Verification

- `cargo test --workspace --exclude bdd` — green (**179** tests). New:
  - nas `pdu_session_status_reconciliation_ies` — a Service Request /Accept and a
    Registration Accept round-trip the IE; a plain Service Request and a minimal
    accept omit it (`None`).
  - nf-amf `service_request_reconciles_dropped_pdu_session` — a retained UE with
    sessions {5, 6} resumes with a Service Request listing only 5: session 6 is
    released at the mock SMF, only 5 is reactivated (inline in the ICS), `sm_refs`
    ends `{5}`, and the Service Accept advertises PDU Session Status `[5]` (the UE
    decodes it).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` registration
  Accept passes `None`, so it is unchanged.
- The reconciliation path isn't sim-drivable (free-ran-ue can't go CM-IDLE and
  doesn't drop sessions, design/64/65 precedent) — integration-tested.

## Known limitations / next steps

- **Mid-connection N1 release** so a *connected* UE is told immediately when the
  network drops a session (rather than at its next CM-IDLE return).
- **Allowed PDU Session Status** on the Service Request (per-access
  re-establishment control).
- **Per-session S-NSSAI** on the inline ICS setup (still fixed sst 1, design/88).
