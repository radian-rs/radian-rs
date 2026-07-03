# T3513 Paging Retransmission + Registration-Area Paging

> Built 2026-07-04 on branch `feat/t3513-registration-area-paging`. Design
> [65](65-paging-dl-buffering.md) introduced paging as a **one-shot broadcast to
> every gNB** with a fixed TAC — both simplifications flagged in its boundary list
> (and design [73](73-idle-am-policy-update.md)'s). This closes both: the page is
> now **scoped to the UE's registration area** (the gNBs whose NG Setup Supported
> TA List covers the UE's TAI) and **retransmitted under T3513** (TS 24.501 §10.2)
> until the UE resumes or the attempts exhaust.

## What was built

### `ngap`

- `supported_tacs_from_ng_setup` — the TACs a gNB advertised in its
  `NGSetupRequest` Supported TA List; plus an `ng_setup_request(mcc, mnc, tacs)`
  builder for tests / a gNB simulator (Global RAN Node ID + Supported TA List +
  Default Paging DRX, the mandatory IEs).
- `tac_from_initial_ue` — the UE's TAC from an `InitialUEMessage`'s User Location
  Information (NR TAI); plus `initial_ue_message_with_nas_at` /
  `initial_ue_message_with_stmsi_at` builder variants carrying a ULI, as a real
  gNB does.

### `nf-amf`

- **`GnbLink { tacs, tx }`** — `GNB_LINKS` entries now carry the tracking areas
  each association serves. Registered with an empty list; filled when the gNB's
  NG Setup arrives (the arm finds its own entry via `UnboundedSender::same_channel`).
- **`UeContext.tac`** — the UE's registration area, captured from the
  InitialUEMessage ULI at registration (both the identified and identity-requested
  paths) and **refreshed on the Service Request resume** (the UE may have moved
  while idle).
- **`page_gnbs(tmsi, ue_tac)`** — the selection: only associations whose TA list
  contains the UE's TAC are paged. Fail-open on both sides: a gNB with no NG Setup
  yet (empty list) is included, and an unknown UE TAC pages everyone (in the
  `AMF_TAC` default). Closed links are swept.
- **`page_with_retx(supi, tmsi, t3513, max_sends)`** — the T3513 loop: page the
  registration area, sleep T3513, check whether the retained context is still
  there (the Service Request consuming it *is* the paging response), retransmit up
  to `max_sends` (3) attempts, then warn and leave the context retained (the
  design/66 eviction remains the backstop). `T3513 = 6 s`, overridable with
  `RADIAN_AMF_T3513_SECS` (`spawn_paging` wraps the env read + spawn).
- Both paging producers — the SMF's downlink-data N1N2 transfer (design/65) and
  the AM-policy UpdateNotify hold (design/73) — now go through `spawn_paging`.
- `UeCmd::Page` gained the TAC: each association now builds the NGAP Paging with
  the **UE's** tracking area in TAI List for Paging, not the fixed `AMF_TAC`.

## Boundaries / notes

- The registration area is a **single TAI** (where the UE last registered/resumed),
  not a multi-TAI Registration Area List; TS 23.501 registration-area management
  (TAI-list assignment in the Registration Accept) is not modelled.
- Paging escalation (first page in the last-seen cell, then the whole registration
  area) and Paging DRX timing are not modelled — every attempt pages the whole
  registration area.
- T3513 exhaustion leaves the context retained: downlink data stays buffered at
  the UPF (bounded, design/65) and a pending AM policy change applies on the next
  natural Service Request — or everything is released by the T3512 implicit
  deregistration (design/66).

## Verification

- `cargo test --workspace --exclude bdd` — green (**156** tests). New:
  - ngap `user_location_and_supported_tas_roundtrip` — the ULI TAC and the NG
    Setup TA list survive APER encode→decode; ULI-less messages yield `None`.
  - nf-amf `paging_is_scoped_to_the_ue_registration_area` — the serving gNB and a
    no-NG-Setup-yet gNB are paged (with the UE's TAC), a gNB outside the area is
    not; an unknown UE TAC broadcasts to everyone.
  - nf-amf `t3513_retransmits_until_resume_or_exhaust` — an unanswered page
    retransmits exactly `max_sends` times and leaves the context retained; a
    resume (retained context consumed) stops the loop early.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green.**
- **Live loopback (real core + free-ran-ue)** — both new parsers are wire-proven
  against free5gc encodings: the AMF logs *"gNB serves TACs [[00, 00, 01]]
  (registration-area paging scope)"* (the sim's real NG Setup) and *"UE 1:
  registering from TAC [00, 00, 01] (registration area)"* (the sim's real
  InitialUEMessage ULI); the UE registers as before. The paging response itself
  isn't sim-drivable (free-ran-ue can't go CM-IDLE) — the T3513/selection logic is
  integration-tested (design/64/65 precedent).

## Known limitations / next steps

- **Registration Area List management** — assign a multi-TAI registration area in
  the Registration Accept (TAI List IE) and scope paging to it.
- **Paging escalation + DRX** — last-cell-first paging, DRX-aligned timing.
- A **full Initial Context Setup procedure** at UE-context establishment.
