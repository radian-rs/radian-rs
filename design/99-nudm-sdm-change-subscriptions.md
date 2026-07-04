# Nudm_SDM Change Subscriptions

> Built 2026-07-04 on branch `feat/nudm-sdm-subscriptions`. The UDM served
> `Nudm_SDM_Get` (am/sm/smf-select data) but had no change-subscription surface, so
> a mid-registration subscriber-data change never reached the AMF (the only
> UDR→core notification was the subscription-**withdrawal** deviation). This adds
> `Nudm_SDM_Subscribe`/`Unsubscribe` + `Nudm_SDM_Notification` (TS 29.503 §5.3.2):
> the AMF subscribes at registration and refreshes its cached subscription view
> when the UDM notifies a change.

## What was built

### `sbi-core` (UDM side + client)

- `SdmStore` — in-memory `Nudm_SDM` subscriptions keyed by SUPI (`SUPI → [{id,
  callback}]`); the UDM router now carries a `UdmState { udr, sdm }` (via `FromRef`
  so existing handlers keep extracting `State<Arc<UdrClient>>`).
- Routes: `POST …/{supi}/sdm-subscriptions` (subscribe → `201` + `Location` + the
  echoed subscription with its id; SSRF-guarded callback), `DELETE
  …/sdm-subscriptions/{subId}` (unsubscribe → `204`/`404`), and `POST
  …/{supi}/notify-data-change` — the fan-out a data source invokes on a change: it
  POSTs a `ModificationNotification` to every subscriber's callback and reports the
  count.
- `NudmClient::sdm_subscribe(supi, callback) -> id` and `sdm_unsubscribe`.

### `nf-amf`

- `spawn_sdm_subscribe` — on **RegistrationComplete** (beside the UECM
  registration), subscribe with an `sdm-notify` callback and keep the id in
  `SDM_SUBS` (SUPI → id). `spawn_sdm_unsubscribe` — drop it on every
  deregistration path (beside the UECM purge).
- Callback `POST /namf-callback/v1/{supi}/sdm-notify` (`Nudm_SDM_Notification`):
  re-fetch am-data and hand the new UE-AMBR / allowed NSSAI to the owning
  association via `UeCmd::UpdateSubscribedData`. `204` whether or not the UE is
  currently connected.
- `on_sdm_data_change` updates `ctx.ue_ambr` / `ctx.allowed_nssai` in place.

## Boundaries / notes

- **Trigger.** The change is driven by a `POST …/notify-data-change` to the UDM (a
  data source's hook, mirroring the design/69 PCF-trigger pattern). The UDR
  autonomously detecting a provisioned-data change and calling this is a follow-up.
- **AMF reaction.** The cached view is refreshed; **no UE re-signalling** here — a
  subscribed-data change takes effect on the next procedure that reads the view
  (slice admission, a UE-context modification, a re-registration). Pushing the
  change to the UE (UECtxMod / Config Update) is a follow-up.
- **CM-IDLE.** A notification for a UE not currently connected is accepted (`204`);
  the AMF re-fetches am-data at the UE's next registration anyway.

## Verification

- `cargo test --workspace --exclude bdd` — green (**192** tests). New:
  - sbi-core `sdm_change_subscription_fans_out` — subscribe a callback, a
    data-change fans a `ModificationNotification` (resource `am-data`) out to it
    (`notified: 1`); after unsubscribing, a change reaches nobody (`notified: 0`).
  - nf-amf `sdm_data_change_refreshes_the_cached_view` — a change bumps the stored
    UE-AMBR + allowed NSSAI with no downlink; `None` fields keep the current value;
    an unknown UE is a no-op.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` registration
  now also subscribes to `Nudm_SDM` at the real UDM (best-effort, off the signalling
  path); the UE still registers, establishes a session, and pings.

## Known limitations / next steps

- **UDR-autonomous trigger** — the UDR notifies the UDM on a provisioned-data change
  (Nudr subscribe-to-notification / a data-change hook) rather than a direct POST.
- **Push to the UE** — re-signal the RAN/UE (UE-context modification / Configuration
  Update) when the subscribed UE-AMBR or NSSAI changes.
- **Subscription persistence / correlation id**, and monitored-resource filtering
  (currently the AMF re-fetches am-data on any notification).
