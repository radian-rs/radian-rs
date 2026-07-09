# BDD Scripted PDU Session Establishment (116c)

> Built 2026-07-09 on branch `feat/bdd-scripted-pdu-session`. Third slice of the design/116
> plan (after 116a/117 registration and 116b/118-119 outcomes): the scripted gNB/UE now
> take a **registered UE through a full PDU session establishment** against the live core —
> the foundation the CM-IDLE / handover / traffic arcs all build on.

## Why this first

The idle arc (AN release → Service Request → paging) and everything session-related
presuppose an established PDU session. The scripted tier could register a UE but not open a
session, so this is the gating capability. It is done **control-plane only** — the scripted
gNB parses the N2 setup and answers with its DL F-TEID, proving the whole
UE → AMF → SMF → UPF (PFCP) → N2 → gNB → N1 accept chain — but it does not yet move GTP-U
user traffic. A datapath echo needs N3 port separation (both the gNB and the UPF want
:2152), i.e. a namespace topology like `datapath_e2e`; that is a deliberate follow-up.

## What was built

### `nas`

- **`pdu_session_establishment_request(psi, pti)`** — the UE-side 5GSM PDU Session
  Establishment Request N1 container (minimal: the mandatory Integrity Protection Maximum
  Data Rate at full rate). Wrap with `ul_nas_transport_sm`.
- **`ue_ipv4_from_establishment_accept(container)`** — the assigned UE IPv4 from a 5GSM
  Establishment Accept (its PDU Address IE).

### `ngap`

- **`pdu_session_resource_setup_request_params(pdu)`** (gNB side) — parse a standalone
  `PDUSessionResourceSetupRequest` into `(AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, per-session
  (psi, UPF UL N3 TEID, UPF N3 IPv4, NAS-PDU))`. Mirrors the ICS session-id parser but for
  the standalone setup and also returns the relayed NAS. The response builder
  (`pdu_session_resource_setup_response`) already existed.

### `bdd`

- `ScriptedUe::pdu_session_request(psi)` (NAS-protected UL NAS Transport carrying the
  request) and `read_pdu_session_accept(dl_nas)` (unprotect the relayed DL NAS Transport,
  assert it is an Establishment Accept, return `(psi, UE IPv4)`).
- Scenario **116c** in `scripted_registration.feature`: a registered UE requests a PDU
  session → the gNB receives the `PDUSessionResourceSetupRequest` (asserting a non-zero UPF
  uplink F-TEID), answers with its DL F-TEID, and relays the accept → the UE reads back an
  IP in the DN pool `10.45.0.0/16`. The registration prelude reuses the 116a steps; the
  config-update nudge is consumed first so it doesn't collide with the setup message.

## Verification

- `cargo test -p nas -p ngap` — green (nas 35, ngap 22; the 2 new helper roundtrips pass).
- **`cargo test -p bdd` — 2 features / 9 scenarios / 71 steps GREEN** (deterministic across
  reruns): the new scenario drives the full establishment against the live NRF/UDR/UDM/AUSF/
  PCF/SMF/UPF/AMF (SMF↔UPF PFCP over N4); the rest of the scripted registration suite and
  the N6 datapath feature are unaffected.
- `cargo test --workspace --exclude bdd` — green (30 test binaries).
- `cargo clippy -p nas -p ngap -p bdd --tests` — no net-new warnings (22 sites before ==
  after; the setup-request parser carries an `#[allow(clippy::type_complexity)]` on its
  4-tuple-vec return, consistent with the crate's other multi-field parsers).

## Boundaries / next

- Control plane only — the gNB reports a DL F-TEID but no GTP-U flows ride N3 yet. The
  **datapath echo** (scripted-tier equivalent of `datapath_e2e`) is the next slice and needs
  the UPF in a namespace so gNB and UPF don't both bind :2152.
- With an established session in hand, the CM-IDLE arc (116d: AN release → CM-IDLE →
  Service Request resume, then paging + T3513) is now unblocked, plus the remaining
  registration scenarios (D3/D4 GUTI+Identity, D9 area ∪, D10 DNN reject #27).
