# AN Release — gNB-initiated UE Context Release + CM-IDLE

> Built 2026-07-03 on branch `feat/cm-idle-release`. Registration-lifecycle audit
> slice 4, and the **first slice of the idle-mode arc**. Until now the UE was
> permanently CM-CONNECTED: the only UE-context release was AMF-initiated
> (deregistration), and a gNB `UEContextReleaseRequest` (RAN user inactivity) was
> unhandled. This adds the **AN release** procedure (TS 23.502 §4.2.6): the gNB
> asks to release the UE, the AMF deactivates the user plane and transitions the
> UE to **CM-IDLE**, keeping its registration and PDU sessions for a later resume.

## What was built

### N4 user-plane deactivation (`pfcp` / UPF)

- **`session_deactivate_request(up_seid, seq, far_id)`** — a Session Modification
  with an Update FAR that **DROPs** downlink and clears its Outer Header Creation.
- `handle_n4`'s modification arm now distinguishes the two downlink Update FARs:
  an OHC → install the gNB tunnel (activate); no OHC + `ApplyAction::DROP` →
  **`UpfState::clear_downlink`** (deactivate). With the target cleared,
  `route_downlink` returns `None`, so downlink to that UE IP is dropped. The
  session and its uplink TEID persist — a later activation re-installs the route.

### SMF (`nf-smf`)

- `SmContextUpdateData` gained an optional **`upCnxState`** (and the gNB F-TEID
  fields are now optional). `upCnxState == "DEACTIVATED"` routes to a new
  `deactivate_up` that runs the N4 deactivation and clears the stored gNB target;
  the activation path (gNB F-TEID present) is unchanged.

### AMF (`ngap` / `nf-amf`)

- `ngap`: `ue_context_release_request` builder (gNB-side / tests) +
  `parse_ue_context_release_request` → `(AMF-UE-NGAP-ID, RAN-UE-NGAP-ID)`.
- A `CmState { Connected, Idle }` on the UE context.
- `on_ue_context_release_request`: for each of the UE's PDU sessions, call
  `AmfSmf::deactivate_up` (Nsmf UpdateSMContext, `upCnxState=DEACTIVATED`) — the
  UPF drops downlink toward the released gNB tunnel — then mark the context
  **CM-IDLE** (registration + PDU sessions retained) and answer with a
  `UEContextReleaseCommand`.

## Boundaries / notes

- **No resume yet** — the CM-IDLE context is retained but the UE can't come back
  until **Service Request** (slice 2). The gNB’s `UEContextReleaseComplete` is
  already logged.
- **Drop, not buffer** — deactivation DROPs downlink. **Buffering + Downlink Data
  Notification + paging** is slice 3; a real UPF would BUFF (with a BAR) to trigger
  paging.
- **Retained in the association map** — the CM-IDLE context stays in the owning
  SCTP association's table (keyed by its old AMF-UE-NGAP-ID). A cross-association
  resume (the UE returns on a different gNB) needs an AMF-wide context store —
  deferred with Service Request.
- **Not driven by free-ran-ue** — the sim implements neither gNB inactivity release
  nor Service Request, so the procedure is unit/integration-tested plus a
  real-binary SMF↔UPF smoke (as design/50's modify path was).

## Verification

- `cargo test --workspace --exclude bdd` — green (**136** tests). New:
  - pfcp `session_modification_installs_downlink` extended — a deactivate DROPs
    downlink and clears the route; the session survives; a re-activation
    re-installs it.
  - ngap `ue_context_release_request_roundtrips`.
  - nf-amf `an_release_deactivates_up_and_goes_cm_idle` — a mock SMF records
    `upCnxState=DEACTIVATED` for both of the UE's sessions, the context goes
    CM-IDLE (retained, not dropped), and a `UEContextReleaseCommand` is returned;
    an unknown UE yields nothing.
- **BDD 2 features / 5 scenarios / 25 steps green** — unaffected (the sim never
  goes idle).
- **Live (real binaries)** — NRF/UDR/UDM/PCF/UPF/SMF up; driving the SMF's
  UpdateSMContext by curl through **create → activate (install gNB downlink) →
  deactivate (`upCnxState=DEACTIVATED`) → re-activate**, the SMF logs
  `N4 downlink installed` → `deactivated UP connection (AN release); downlink
  dropped` → `N4 downlink installed` again, and the UPF handles all five N4
  messages — proving the SMF↔UPF deactivation/reactivation path end to end.

## Known limitations / next steps

- **Service Request (resume)** — slice 2: a returning UE (5G-S-TMSI) re-activates
  its PDU sessions (Nsmf UpdateSMContext `ACTIVATING` → N2 PDU Session Resource
  Setup) and moves back to CM-CONNECTED. Needs the AMF-wide retained-context store.
- **Paging + DL buffering + Downlink Data Notification** — slice 3: BUFF at the
  UPF, a PFCP Session Report (DL data) → SMF → AMF → NGAP Paging.
- **Periodic registration / mobile-reachable timer** (T3512) for implicit
  deregistration of a UE that never comes back.
