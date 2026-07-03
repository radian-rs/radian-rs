# UE-Initiated Deregistration — Implementation Notes

> Built 2026-07-03 on branch `feat/deregistration`. Closes the "no deregistration
> procedure" gap from [35](35-ue-context-release.md): a departing UE now tears
> down everything it owned — the N4 session at the UPF, the SM context at the
> SMF, and both sides' UE contexts — instead of leaking all of it.

TS 24.501 §5.5.2.2 flow: Deregistration Request (UE originating) → the network
releases the PDU session, answers with a **Deregistration Accept** (unless the
de-registration type says **switch-off**, which expects silence), and releases
the RAN-side context (reusing the design/35 machinery, cause *deregister*).

## What was built

- **`pfcp` — Session Deletion** (TS 29.244 §7.5.6): `session_deletion_request
  (up_seid, seq)` (SMF side); `handle_n4` gains the deletion arm —
  `UpfState::remove` drops the session (its TEID and UE-IP routes with it),
  answering *accepted*, or *session context not found* for an unknown SEID.
- **SMF — `Nsmf_PDUSession_ReleaseSMContext`** (TS 29.502 §5.2.2.4):
  `POST /nsmf-pdusession/v1/sm-contexts/{ref}/release` → N4 Session Deletion →
  drop the SM context → `204`. Unknown ref → `404`; UPF unreachable → `502`
  and the context is kept (the AMF may retry); a non-accepted N4 answer (UPF
  already lost it) still drops our side.
- **`nas`** — `deregistration_is_switch_off` (bit 4 of the §9.11.3.20
  de-registration type), `deregistration_accept()` (§8.2.13, header-only), and
  a UE-side request builder for tests.
- **AMF — `on_deregistration`** (multi-PDU, via the design/35 Vec path): release
  the SM context at the SMF if one is active (best effort — the UE is leaving
  either way), NAS-protect the Deregistration Accept unless switch-off, send the
  **UEContextReleaseCommand** (cause `deregister` this time), drop the AMF
  context.

## Verification

- `cargo test --workspace --exclude bdd` — green. New:
  - `pfcp::session_deletion_removes_the_session` — establish → delete →
    `session_count` 0, TEID unroutable, N6 route gone; unknown SEID answers
    non-accepted.
  - `nf-smf` main test gains the release leg — `204` + UPF session gone; second
    release → `404`.
  - `nas::deregistration_roundtrips` — switch-off bit both ways; header-only
    accept.
  - `nf-amf::deregistration_releases_session_and_contexts` — mock SMF counts
    `/release`: normal dereg → [Accept, ReleaseCommand(cause deregister)] +
    SMF hit + context dropped + UE-side accept verifies; switch-off → release
    command only.
- **Live with free-ran-ue** (its `Stop()` sends a real, NAS-protected
  Deregistration Request on SIGTERM, switch-off **clear** — it expects the
  accept): full loopback session then SIGTERM — UE logs **"UE deregistration
  complete"**; AMF logs the SM release → Accept → UEContextReleaseCommand;
  SMF logs "released SM context; N4 session deleted".
- **BDD, 5 scenarios / 25 steps green** (regression; BDD kills the UE hard, so
  the graceful path stays a manual/integration concern).

## Known limitations / next steps

- **Network-initiated deregistration** (§5.5.2.3, e.g. on subscription
  withdrawal) is not implemented.
- **Only the tracked session is released** — one `sm_ref` per UE context (the
  single-PDU-session-per-UE constraint from design/16 still holds).
- **The BDD e2e doesn't exercise graceful stop** — `kill_netns_procs` is
  SIGKILL; switching the UE stop to SIGTERM would add live dereg coverage but
  couples teardown to simulator behaviour. Left manual for now.
- UE-AMBR from am-data, AMF-side SMF selection, and back-off enforcement remain
  open.
