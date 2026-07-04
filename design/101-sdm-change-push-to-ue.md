# Push a Nudm_SDM Change to the RAN/UE

> Built 2026-07-04 on branch `feat/sdm-push-to-ue`. Designs
> [99](99-nudm-sdm-change-subscriptions.md)/[100](100-udr-autonomous-data-change.md)
> delivered a subscriber-data change end to end (UDR → UDM → AMF), but the AMF only
> refreshed its **cached** view (`ctx.ue_ambr` / `ctx.allowed_nssai`) — the change
> reached neither the RAN nor the UE. This pushes it: a changed UE-AMBR updates the
> RAN's enforcement, and any change nudges the UE.

## What was built (`nf-amf`)

`on_sdm_data_change` now, after updating the cached view, emits downlinks **only for
values that actually changed**:

- **UE-AMBR changed** → a **UE Context Modification Request** (TS 38.413 §9.2.2.7)
  carrying the new UE-AMBR (and the current RFSP, re-sent) so the gNB re-rates its
  aggregate enforcement — the design/70 vehicle.
- **Any change** (UE-AMBR or allowed NSSAI) → a **Generic UE Configuration Update**
  (TS 24.501 §5.4.4) in a protected DownlinkNASTransport, telling the UE its
  configuration changed — the design/69 vehicle.

A no-op change (same values), an unknown UE, or a UE with no NAS security context
(the last skips only the UE nudge, the RAN update still lands) signals accordingly.
The downlinks flow through the existing `UeCmd::UpdateSubscribedData` → association
path, so they reach the gNB.

## Boundaries / notes

- The Configuration Update Command is the **generic nudge** — it does not yet carry
  the new Allowed NSSAI IE, so an NSSAI change tells the UE to re-read/re-register
  rather than delivering the list inline. Carrying the NSSAI (and handling a
  narrowed allowed NSSAI → PDU session / registration impact) is a follow-up.
- **PCF interaction.** The subscribed UE-AMBR is the am-data value; a PCF AM-policy
  override (design/70) sets the same `ctx.ue_ambr`. A subscribed-UE-AMBR push and a
  PCF push both write `ctx.ue_ambr` (last wins) — reconciling the two sources is a
  follow-up; today the most recent update is what's signalled.
- Only a **CM-CONNECTED** UE is pushed to (the notification resolves via
  `UE_DIRECTORY`); a CM-IDLE UE re-fetches am-data at its next registration
  (design/99).

## Verification

- `cargo test --workspace --exclude bdd` — green (**194** tests). Updated:
  - nf-amf `sdm_data_change_pushes_to_ran_and_ue` — a UE-AMBR + NSSAI change emits
    `[UEContextModificationRequest, DownlinkNASTransport(ConfigurationUpdateCommand)]`;
    the RAN gets the new UE-AMBR (RFSP re-sent) via `ue_context_modification_params`
    and the UE verifies the Config Update; an NSSAI-only change emits just the UE
    nudge; a no-op change / unknown UE signals nothing.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the `@sim` changes no am-data
  during the run, so `on_sdm_data_change` isn't triggered; registration + datapath
  are unaffected. (The push needs a live am-data change, integration-tested here.)

## Known limitations / next steps

- **Carry the Allowed NSSAI** in the Configuration Update Command; handle a narrowed
  allowed NSSAI (release affected PDU sessions / trigger re-registration).
- **Reconcile subscribed vs PCF UE-AMBR** so a subscribed-data push doesn't clobber
  an active PCF override.
- **UE Configuration Update Complete** tracking (the UE's ack to the command).
