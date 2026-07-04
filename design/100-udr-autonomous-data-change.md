# UDR-Autonomous Data-Change Trigger

> Built 2026-07-04 on branch `feat/udr-data-change-notify`. Design
> [99](99-nudm-sdm-change-subscriptions.md) added `Nudm_SDM` change subscriptions
> (UDM ⟷ AMF) but left the change **trigger** manual — a direct POST to the UDM's
> `notify-data-change`. This closes that boundary: a provisioned **am-data** change
> at the UDR now autonomously notifies the UDM, which fans a `Nudm_SDM_Notification`
> out to subscribed AMFs. The full **UDR → UDM → AMF** path (TS 23.502 §4.16 has the
> UDM mediate), via the "data-change hook" option the design/99 boundary sanctioned.

## What was built

### `sbi-core` (UDR side)

- `NudrState` gained `udm_base: Option<String>` — the UDM to notify on a change
  (`None` disables it). `NudrState::notify_udm_data_change(ds, ue_id)` POSTs the
  UDM's `…/{ue_id}/notify-data-change` (design/99's fan-out) — **awaited** so the
  notification is delivered before the PUT returns, but a failure never fails the
  PUT (best-effort).
- The provisioned-data PUT handler notifies on a successful put; gated to
  **am-data** only (the only dataset with a subscriber today — the AMF via
  `Nudm_SDM`). `pub fn router_with_udm(store, udm_base)`; `router(store)` delegates
  with `None` (existing callers / tests unchanged).

### `nf-udr`

- Reads `RADIAN_UDR_UDM` (default `http://127.0.0.1:8004`) and builds the router with
  it, so a live UDR relays am-data changes to the UDM out of the box.

## Boundaries / notes

- **am-data only.** sm-data / smf-selection changes don't notify — no NF subscribes
  to them yet (the SMF has no `Nudm_SDM` subscription). Generalising the resource
  (and telling the UDM *which* dataset changed) is a follow-up.
- **Direct configured UDM, not a tracked subscription.** The UDR notifies the
  configured UDM rather than via a `Nudr_DataRepository` subscribe-to-notification
  the UDM registered — the same incremental posture as the design/24 withdrawal
  deviation. A per-subscriber Nudr subscription is the further-proper step.
- **Awaited notify** adds latency to the (rare, admin) am-data PUT; acceptable and
  makes the delivery deterministic.

## Verification

- `cargo test --workspace --exclude bdd` — green (**194** tests). New:
  - sbi-core `am_data_change_notifies_the_udm` — a UDR am-data PUT notifies the
    (mock) UDM's `notify-data-change` for that SUPI; an sm-data PUT does not.
  - sbi-core `am_data_change_reaches_a_sdm_subscriber` — **end to end**: an AMF
    subscribes at the real UDM, then a UDR am-data change flows UDR → UDM → the
    subscriber's callback (one `ModificationNotification`, resource `am-data`);
    every hop is awaited, so it has arrived when the PUT returns.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — `nf-udr` now configures the
  UDM-notify base; the `@sim` changes no am-data during the run, so registration +
  datapath are unaffected.

## Known limitations / next steps

- **Other datasets** — notify on sm-data / smf-selection changes once the SMF holds
  a `Nudm_SDM` subscription; carry the changed resource to the UDM.
- **Proper Nudr subscribe-to-notification** — the UDM registers a per-subscriber
  Nudr subscription and the UDR notifies its subscribers (vs a configured UDM).
- **Push the change to the UE** (design/99 follow-up) — re-signal the RAN/UE on a
  subscribed UE-AMBR / NSSAI change.
