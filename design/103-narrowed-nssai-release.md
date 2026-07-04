# Release PDU Sessions on a Narrowed Allowed NSSAI

> Built 2026-07-04 on branch `feat/narrowed-nssai-release`. Design
> [102](102-cuc-allowed-nssai.md) delivered a changed allowed NSSAI to the UE, but a
> **narrowed** allowed NSSAI (a slice removed) left the UE's PDU sessions on that
> now-disallowed slice running. This releases them: a subscribed-NSSAI change that
> drops a slice tears down the sessions on it (TS 23.501 §5.15 — the UE may no
> longer use that slice), via the network-initiated release procedure (designs
> 91–94).

## What was built (`nf-amf`)

- `UeContext.session_snssai: HashMap<u8, (SST, Option<SD>)>` — the serving S-NSSAI
  each PDU session runs on, recorded at establishment from the SMF's
  `SmContextCreated` (`snssai_sst` / `snssai_sd`, already in `(u8, Option<[u8;3]>)`
  form). A session with no recorded slice (established before this feature) is left
  alone rather than wrongly released.
- `on_sdm_data_change` now, when the allowed NSSAI **changed to a non-empty set**,
  collects every `sm_refs` session whose recorded slice is **not** in the new
  allowed NSSAI and releases them via `on_network_release` — the N2 PDU Session
  Resource Release Command (+ N1) per session, appended to the RAN/UE downlinks
  (UE-Context-Modification / Configuration-Update). The signalling is computed while
  the context is borrowed, then the release runs on `ues` (the borrow is dropped
  first). The gained `tx` parameter arms each release's guard timer (design/92).

## Boundaries / notes

- **Release cause** is *regular deactivation*; a slice-specific 5GSM cause is a
  refinement.
- **Non-empty guard.** An empty new allowed NSSAI (which `fetch_am_data` never
  produces — it is `None` on a miss) would *not* trigger releases, so an am-data
  fetch failure can't wrongly tear every session down.
- **No re-registration trigger.** The UE gets its new allowed NSSAI (design/102) and
  its disallowed sessions are released, but the AMF doesn't force a re-registration;
  a Configuration Update with the registration-requested indication is a follow-up.
- Only a **CM-CONNECTED** UE is acted on (the notification path, design/99).

## Verification

- `cargo test --workspace --exclude bdd` — green (**195** tests). New:
  - nf-amf `sdm_narrowing_releases_sessions_on_removed_slice` — a UE with sessions on
    slices 1 and 2; removing slice 2 from the allowed NSSAI releases psi 6 (slice 2)
    — one `PDUSessionResourceReleaseCommand` (N1 for psi 6), psi 6 marked
    `releasing`, psi 5 (slice 1) untouched, and the UE told via a Configuration
    Update.
  - `sdm_data_change_pushes_to_ran_and_ue` updated to the new `tx` signature (a UE
    with no sessions releases nothing).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — establishment now records the
  serving slice; the `@sim` triggers no NSSAI change, so nothing is released and the
  datapath is unaffected.

## Known limitations / next steps

- **Re-registration** on a narrowing (Configuration update indication /
  registration-requested), or a slice-specific release cause.
- **Configuration Update Complete** tracking (design/102 follow-up).
- Clean `session_snssai` on release for tidiness (harmless today — a released
  psi's entry is never consulted while absent from `sm_refs`, and is overwritten on
  the next establishment).
