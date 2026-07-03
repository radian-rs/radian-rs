# Mobility Registration Update

> Built 2026-07-04 on branch `feat/mobility-registration-update`. Design
> [75](75-registration-area-list.md) assigned a registration area but had no
> procedure for leaving it — a Service Request from outside merely *extended* the
> area, flagged as a stand-in. This adds the real procedure (TS 24.501 §5.5.1.3):
> a CM-IDLE UE that moved outside its registration area re-registers with type
> **mobility registration updating**, and the AMF **re-assigns** the area around
> the new serving gNB and answers with a Registration Accept carrying the new
> 5GS TAI list.

## What was built

### `nas`

- `registration_request_mobility(mcc, mnc, tmsi)` — a Registration Request of type
  *mobility registration updating* (TS 24.501 §9.11.3.7 type 010), identifying by
  5G-GUTI, ngKSI 0 (current security context). UE side / tests.
- `registration_type_from_request` — reads the registration type back (the
  oxirush `RegistrationType` enum: initial / mobility / periodic / …).

### `nf-amf` — `on_service_request` generalizes into the CM-IDLE-return handler

The 5G-S-TMSI + `RETAINED` dispatch already caught every CM-IDLE return; the
handler now **unprotects once and classifies** the inner NAS:

- **Service Request** → the existing resume flow (Service Accept + user-plane
  reactivation), including the design/75 area-*extension* tolerance for a UE that
  should have sent a mobility update.
- **Registration Request, type = mobility updating** → the new flow:
  - registration area **re-assigned** via `registration_area_for` (the *new*
    serving gNB's Supported TA List ∪ the new TAI) — not extended;
  - a protected **Registration Accept** with the same GUTI, the retained allowed
    NSSAI, T3512, and the **new** 5GS TAI list;
  - **no user-plane reactivation** — PDU sessions stay established, the UP stays
    deactivated until a Service Request (the Uplink Data Status IE that would
    request reactivation inline is not modelled);
  - the pending-AM-policy application (design/73) runs as on any return.
- **Anything else / bad MAC** → re-retain and ignore (unchanged).

A mobility Registration Request whose GUTI resolves to *no* retained context still
falls through to `on_initial_ue`'s GUTI re-registration (design/60): full
re-authentication — the right fallback after e.g. an AMF restart.

## Boundaries / notes

- **Same GUTI is kept** (the spec allows GUTI reallocation at any registration
  update; reallocating would re-key `RETAINED`/`GUTI_DIRECTORY` — deferred).
- **No Uplink Data Status / follow-on request handling** — a UE wanting immediate
  UP after the move sends a Service Request next.
- **No periodic registration handling** (type 011) — still arrives as a GUTI
  re-registration → full re-auth (design/66 boundary, unchanged).
- The security context continues (no horizontal K_AMF derivation).

## Verification

- `cargo test --workspace --exclude bdd` — green (**160** tests). New:
  - nas `mobility_registration_request_roundtrips` — the type + GUTI TMSI survive
    encode→decode; other messages yield no registration type.
  - nf-amf `mobility_registration_update_reassigns_the_area` — a retained UE
    (area `[000001]`, one PDU session, allowed NSSAI) returns via a gNB serving
    TACs 000009/00000b with a protected mobility Registration Request from TAC
    000009: one downlink (the mobility Registration Accept), **zero** UP
    activation calls at the mock SMF, the restored context is CM-CONNECTED with
    the area **re-assigned** to `[000009, 00000b]` and the session intact, and
    the UE verifies the accept and reads the new TAI list + kept NSSAI.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live registration path
  (which shares the restructured handler's dispatch) is unaffected.
- Mobility itself is not live-drivable — free-ran-ue has a single gNB and cannot
  go CM-IDLE or move (design/64/65 precedent); the procedure is
  integration-tested end to end (protect → classify → re-assign → accept →
  UE-side verify).

## Known limitations / next steps

- **GUTI reallocation** on registration update (re-keying the retained store).
- **Uplink Data Status** — reactivate the listed PDU sessions inline with the
  mobility update.
- **Periodic registration updating** (type 011) as a lightweight path (no
  re-auth), stopping/restarting T3512 without a full registration.
- **Operator TAI-list policy**, paging escalation/DRX, full Initial Context Setup
  (standing backlog).
