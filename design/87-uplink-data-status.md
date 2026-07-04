# Uplink Data Status — Inline UP Reactivation on a Registration Update

> Built 2026-07-04 on branch `feat/uplink-data-status`. Designs
> [76](76-mobility-registration-update.md)/[85](85-periodic-registration.md) left
> a registration update's user plane **deactivated** — only a Service Request
> reactivated PDU sessions. But a UE with pending uplink data flags it in the
> **Uplink Data Status** IE (TS 24.501 §9.11.3.57) of its registration update, and
> the network should bring **those** sessions' user plane back inline. This is the
> last design/76 follow-up.

## What was built

### `nas`

- `uplink_data_status_value(psis)` / `psis_from_uplink_data_status(value)` — the
  two-octet PSI bitmap (octet 3 = PSI 0–7, octet 4 = PSI 8–15; PSI 0 spare).
- `registration_request_of_type` gained an `uplink_data_psis` parameter (sets the
  Uplink Data Status IE, IEI 0x40, when non-empty); the mobility/periodic builders
  pass `&[]`, and `registration_request_with_uplink_data` sets it (UE side / tests).
- `uplink_data_status_from_registration_request` — the AMF-side parser: the PDU
  sessions the UE flagged (empty when the IE is absent).

### `nf-amf` — `on_service_request`

The reactivation set is now driven by what the UE asked for:

- **Service Request** → all retained PDU sessions (unchanged — a UE-initiated
  Service Request wants its data plane back).
- **Registration update** (mobility / periodic) → only the sessions listed in the
  Uplink Data Status IE; the rest stay deactivated. An update with no IE
  reactivates nothing (the design/76/85 behaviour).

The reactivated sessions run the existing resume path (Nsmf `ACTIVATING` → N2 PDU
Session Resource Setup with the retained UPF N3 F-TEID), so the downlink sequence
for such an update is `[ICS(RegistrationAccept), PDUSessionResourceSetupRequest ×
listed]`.

## Boundaries / notes

- **PDU Session Status IE** (the UE's view of which sessions are still up) is not
  cross-checked — the AMF trusts the Uplink Data Status list against its retained
  `sm_refs`.
- A listed PSI the AMF has no context for is simply skipped (the filter is over
  the retained sessions).
- The Service Request still reactivates all sessions rather than honouring its own
  Uplink Data Status — a deliberate simplification (a resume implies the UE wants
  everything back).

## Verification

- `cargo test --workspace --exclude bdd` — green (**176** tests). New:
  - nas `uplink_data_status_bitmap_encoding` — PSI 5 + PSI 8 ⇒ `[0x20, 0x01]` and
    back; out-of-range dropped; empty is all-zero. `mobility_registration_request_
    roundtrips` (extended) — the IE round-trips to its PSI list (5, 9) and is empty
    when absent.
  - nf-amf `registration_update_reactivates_uplink_data_status_sessions` — a
    retained UE with two sessions (5, 6) sends a mobility update flagging only
    PSI 5: the downlinks are the Registration Accept then a **single** PDU Session
    Resource Setup, and the mock SMF sees exactly **one** `ACTIVATING` call (PSI 6
    stays deactivated).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green.**
- Not sim-drivable — free-ran-ue can't go CM-IDLE / re-register (design/64/65
  precedent); integration-tested end to end.

## Known limitations / next steps

- **PDU Session Status** cross-check (reconcile the UE's and AMF's session views;
  release sessions the UE dropped).
- **Uplink Data Status on the Service Request** path (currently reactivates all).
- **Allowed PDU Session Status** in the accept (tell the UE which sessions the
  network reactivated).
