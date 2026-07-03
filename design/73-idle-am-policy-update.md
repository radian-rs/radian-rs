# AM Policy Change for a CM-IDLE UE — Hold, Page, Apply on Resume

> Built 2026-07-03 on branch `feat/idle-am-policy-update`. Designs
> [69](69-npcf-am-policy-update-notify.md)/[70](70-signal-rfsp-to-ran.md)/
> [72](72-servarea-update-notify.md) deliver a PCF-initiated AM policy change to a
> **CM-CONNECTED** UE, but a change for a **CM-IDLE** UE returned `404` to the PCF
> and was lost. This closes that gap with the same shape the idle-mode arc used for
> downlink data ([65](65-paging-dl-buffering.md)): **hold** the change in the
> retained context, **page** the UE (network-triggered Service Request, TS 23.502
> §4.2.3.3), and **apply** it on the Service Request resume
> ([64](64-service-request-resume.md)).

## What was built (`nf-amf` only)

- `UeContext.pending_am_policy: Option<PendingAmPolicy>` — a held AM policy change
  (`ue_ambr`, `rfsp`, `area_restriction`). **Latest wins**: a second UpdateNotify
  while idle overwrites the first (only the newest policy matters).
- **`am_policy_notify` fallback**: on a `UE_DIRECTORY` miss the callback now searches
  `RETAINED` by SUPI. On a hit it stores the pending change in the retained context
  and broadcasts `UeCmd::Page(tmsi)` over `GNB_LINKS` (the design/65 paging fan-out),
  returning **`202 Accepted`** (deferred) instead of `404`. Only a UE that is neither
  connected nor retained still yields `404`.
- **`on_service_request` application**: after the context is restored and the
  Service Accept + PDU session reactivations are queued, a pending change is taken
  and run through the existing `on_am_policy_update` — so the resume emits exactly
  the CM-CONNECTED change signalling: `UEContextModificationRequest` (RFSP +
  UE-AMBR, design/70) and the Configuration Update Command's `DownlinkNASTransport`
  with the Mobility Restriction List (design/72).

The PCF needed no change — it already pushes to the notification URI and treats any
response as delivered (only transport failures are logged).

## Boundaries / notes

- **No paging retransmission** (no T3513, same as design/65): if the UE ignores the
  page, the change still applies at its next natural Service Request; if it never
  returns, the T3512 eviction (design/66) implicitly deregisters it and deletes the
  AM policy association — the pending change dies with the context, correctly.
- A pending change survives repeated failed resume attempts (a Service Request that
  fails NAS verification re-retains the context, pending intact).
- The `202` is informational to the PCF — TS 29.507 models this as a plain
  notification; no delivery receipt flows back.

## Verification

- `cargo test --workspace --exclude bdd` — green (**153** tests). New:
  - nf-amf `am_policy_update_for_a_cm_idle_ue_pages_and_applies_on_resume` — a
    retained CM-IDLE UE + a real h2c POST of the UpdateNotify → `202`, the mock gNB
    link receives `Page(tmsi)`, the pending change is held (222/111 Mbps, RFSP 9,
    TAC 000003); an unknown UE still `404`s. The UE then resumes with a protected
    Service Request → downlinks are `[ServiceAccept, UEContextModificationRequest,
    ConfigurationUpdateCommand]`; the restored context carries the new UE-AMBR /
    RFSP / area restriction with the pending slot cleared; the RAN reads the new
    RFSP+AMBR from the UECtxMod and the new service area from the CUC transport's
    Mobility Restriction List; the UE verifies both NAS messages.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green**.
- **Live (real NRF + UDR + PCF + AMF)** — the servAreaRes UpdateNotify smoke re-run
  on the new binaries: change detection + h2c push all green, and the AMF's new
  fallback branch handles the no-context case gracefully (`404`, no transport
  failure). A live retained-context run isn't drivable — free-ran-ue cannot go
  CM-IDLE (design/64/65 precedent) — so hold/page/apply is integration-tested.

## Known limitations / next steps

- **T3513 paging retransmission** + registration-area (rather than all-gNB) paging —
  shared with the design/65 backlog.
- **Richer restrictions** (forbidden areas, RAT restrictions, per-slice).
- **A full Initial Context Setup procedure** at UE-context establishment.
