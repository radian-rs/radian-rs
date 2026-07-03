# Registration Area List Management — 5GS TAI List

> Built 2026-07-04 on branch `feat/registration-area-list`. Design
> [74](74-t3513-registration-area-paging.md) scoped paging to a **single TAI** (the
> TAC the UE registered from) and never told the UE its registration area. This
> assigns a real **multi-TAI registration area** (TS 23.501 §5.3.2.3): the AMF
> computes it at registration, sends it to the UE in the Registration Accept's
> **5GS tracking area identity list** IE (TS 24.501 §9.11.3.9), and pages across
> it.

## What was built

### `nas`

- `registration_accept` gained a `registration_area: &[[u8; 3]]` parameter → when
  non-empty, the accept carries the **5GS TAI list** (IEI 0x54), hand-encoded as
  one **type-00 partial list** (non-consecutive TACs of one PLMN):
  `[0|00|count-1] [PLMN TBCD ×3] [TAC ×3]…`, capped at 16 TACs (`tai_list_value`).
- `registration_area_from_registration_accept` — the UE-side/test parser.

### `ngap`

- `paging` now takes `tacs: &[[u8; 3]]` and builds a **multi-item TAI List for
  Paging** (was a single fixed TAC); `tacs_from_paging` parser for the gNB side.

### `nf-amf`

- **`UeContext.registration_area: Vec<[u8; 3]>`**, assigned at registration by
  `registration_area_for`: the **serving gNB's Supported TA List ∪ the UE's TAI**
  (the association's own `GnbLink` found by channel identity), capped at 16 — the
  UE may roam all of the serving gNB's tracking areas without re-registering.
- The Registration Accept passes it to the UE (5GS TAI list IE).
- **Paging pages the area**: `page_gnbs(tmsi, area)` selects the gNB associations
  whose TA list **intersects** the area, each paged with the **full area** in its
  TAI List for Paging. Fail-open unchanged: a gNB with no NG Setup yet is
  included; an empty area (no ULI ever seen) pages every gNB in the default TAC.
  `page_with_retx` (T3513, design/74) reads the retained context's
  `registration_area`, falling back to `[tac]`.
- **Resume from outside the area extends it**: a Service Request from a TAC not in
  the registration area unions it in (a full re-assignment belongs to the mobility
  registration update procedure, not modelled).

## Boundaries / notes

- One **type-00 partial list** (single PLMN, ≤16 TACs) — multiple partial lists /
  type-01 (consecutive) / type-10 (multi-PLMN) encodings are not modelled.
- The registration-area *policy* is fixed (serving gNB's TA list ∪ UE TAI); a real
  AMF applies operator TAI-list configuration.
- No mobility registration update procedure: the UE is not expected to re-register
  when leaving the area (free-ran-ue can't drive mobility anyway); a resume from
  outside simply extends the area.

## Verification

- `cargo test --workspace --exclude bdd` — green (**158** tests). New/extended:
  - nas `tai_list_value_encodes_type_00` — exact §9.11.3.9 octets
    (`[01][99 f9 07][TAC][TAC]` for 2 TACs of 999/70) + the 16-TAC cap;
    `registration_accept_builds_and_decodes` now round-trips the registration
    area alongside NSSAIs and T3512.
  - ngap `paging_roundtrips` (extended) — a two-TAI area survives the TAI List
    for Paging round trip (`tacs_from_paging`).
  - nf-amf `registration_area_combines_gnb_tas_and_ue_tai` — gNB TAs ∪ UE TAI, no
    duplicates, graceful degradation without NG Setup/ULI;
    `paging_is_scoped_to_the_ue_registration_area` (reworked) — a gNB serving
    *any* TA of the area is paged with the *full* area, one outside is not, empty
    area broadcasts in the default TAC.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` Registration
  Accept now carries the 5GS TAI list and the **real free5gc UE decodes it** and
  still registers + pings (wire-compat proof of the hand-encoded IE).
- **Live loopback (real core + free-ran-ue)** — the AMF logs *"UE 1: registering
  from TAC [00, 00, 01]; registration area [[00, 00, 01]]"* (assembled from the
  gNB's real NG Setup TA list ∪ the UE's real ULI TAI), and the UE logs
  *"UE Registration finished"*.

## Known limitations / next steps

- **Mobility registration update** — a UE leaving its registration area should
  re-register (registration type *mobility registration updating*), and the AMF
  should re-assign the area rather than extend it on resume.
- **Operator TAI-list policy** + multiple partial lists / other list types.
- **Paging escalation + DRX** (design/74 backlog) and a **full Initial Context
  Setup** procedure.
