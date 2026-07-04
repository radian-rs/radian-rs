# Inline PDU Sessions in the Initial Context Setup

> Built 2026-07-03 on branch `feat/ics-inline-pdu-sessions`. Design
> [78](78-ics-on-resume.md) re-established the AS context on a CM-IDLE resume with
> an Initial Context Setup, but the reactivated PDU sessions **trailed** as
> separate `PDUSessionResourceSetupRequest` messages. TS 38.413 §9.2.2.1 lets the
> ICS carry the sessions inline (**PDU Session Resource Setup List Cxt Req**) — one
> procedure. This does that: the ICS on a Service Request resume carries the
> reactivated sessions, and the gNB's ICS Response carries their per-session
> results.

## What was built

### `ngap`

- `InitialContext.pdu_sessions: Vec<IcsPduSession>` (`IcsPduSession { psi, flows,
  upf_teid, upf_addr }`); the ICS builder maps each to a
  `PDUSessionResourceSetupItemCxtReq` reusing the existing setup-request transfer
  (UPF UL N3 F-TEID + QoS flows), no per-session N1 (the accept is the ICS
  NAS-PDU). `QosFlow`/`Gbr` gained `PartialEq`.
- `initial_context_setup_request_session_ids` — the RAN/test parser for the
  request's inline sessions `(psi, upf_teid, addr)`.
- `initial_context_setup_response_with_sessions` (+ `initial_context_setup_session_
  ids`) — the gNB's ICS Response carrying / parsed for each session's DL N3 F-TEID
  (`PDUSessionResourceSetupListCxtRes`).

### `nf-amf`

- On a resume, `on_service_request` gathers the reactivated sessions **before**
  building the ICS (fetching each session's UPF N3 F-TEID via Nsmf `ACTIVATING`,
  as before) and puts them in `InitialContext.pdu_sessions` — so a resume emits a
  **single** `InitialContextSetupRequest` instead of the ICS + N trailing setups.
- New `on_initial_context_setup_response` (the ICS Response `handle_ngap` arm):
  parses the inline session results and drives `UpdateSMContext` with each gNB DL
  F-TEID — the same downlink-install the standalone
  `PDUSessionResourceSetupResponse` path does.
- The no-K_AMF fallback (unreachable in practice) still degrades to a plain
  DownlinkNASTransport + trailing PDU setups.

The registration-time ICS (design/77) is unchanged — no PDU sessions exist yet, so
its `pdu_sessions` is empty.

## Boundaries / notes

- **Single S-NSSAI** (sst 1) on each inline item, matching the standalone setup's
  simplification.
- **No per-session failure list** handling on the ICS Response
  (`PDUSessionResourceFailedToSetupListCxtRes`) — the AMF acts on the admitted
  list only.
- The mobility/periodic registration-update path with Uplink Data Status
  (design/87) now also rides its reactivated sessions inline in the ICS.

## Verification

- `cargo test --workspace --exclude bdd` — green (**177** tests). New/updated:
  - ngap `initial_context_setup_roundtrips` (extended) — an inline session in the
    request round-trips (`initial_context_setup_request_session_ids`), and the gNB
    response's DL F-TEID parses (`initial_context_setup_session_ids`); an ICS with
    no sessions parses to an empty list.
  - nf-amf `service_request_resumes_a_cm_idle_ue` (updated) — a resume now emits a
    **single** ICS carrying PSI 5 inline with the UPF's UL F-TEID (no trailing
    setup).
  - nf-amf `registration_update_reactivates_uplink_data_status_sessions` (updated)
    — the Uplink Data Status session rides the ICS.
  - nf-amf `ics_response_installs_inline_session_downlinks` — the gNB's ICS
    Response (DL F-TEID `0xAB / 10.0.1.2` for PSI 5) drives one UpdateSMContext;
    a session-less response installs nothing.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` registration
  ICS (no inline sessions) and the standalone PDU session establishment are
  unaffected; the inline-session encoding reuses the same setup transfer free5gc
  decodes there.
- The resume-with-inline-sessions path isn't sim-drivable (free-ran-ue can't go
  CM-IDLE, design/64/65 precedent) — integration-tested end to end.

## Known limitations / next steps

- **Failed-to-setup list** handling on the ICS Response (release/retry a session
  the gNB rejected).
- **Per-session S-NSSAI** rather than the fixed sst 1.
