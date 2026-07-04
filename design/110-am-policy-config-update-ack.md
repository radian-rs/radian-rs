# AM-policy Configuration Update acknowledgement + retransmission

> Built 2026-07-04 on branch `feat/am-policy-config-update-ack`. Extends design/109:
> T3555 retransmission covered only the SDM-NSSAI Configuration Update Command. Now the
> **AM-policy** Configuration Update (the `Npcf_AMPolicyControl_UpdateNotify` nudge,
> which carries a **service area restriction** as an NGAP Mobility Restriction List)
> also requests acknowledgement and is retransmitted — with the MRL preserved across
> each retransmission.

## The wrinkle: the service area rides the transport, not the NAS

The SDM-NSSAI command carries its payload (the allowed NSSAI) **in the NAS message**,
so design/109 could retransmit it with a plain `downlink_nas_transport`. The AM-policy
command's service area rides the **DownlinkNASTransport** as a Mobility Restriction List
(N2, not NAS). So retransmitting it naively would drop the MRL. The fix: the pending
command remembers its service area and the retransmit path re-attaches it.

## What was built

### `nf-amf`

- `PendingConfigUpdate` gained an `area_restriction: Option<AreaRestriction>` — the
  service area (allowed / non-allowed TACs, a new `type AreaRestriction` alias) that
  the command's transport carries, re-sent on each retransmission.
- Two shared helpers:
  - `config_update_downlink(amf_ue_id, ran_ue_id, cuc_bytes, area_restriction)` — builds
    the DownlinkNASTransport, attaching the MRL when the command has a service area.
  - `push_tracked_config_update(ctx, amf_ue_id, cuc, area_restriction, tx)` — protects
    the command, builds the DL, stores the pending state, and arms T3555. Returns the DL.
- `on_am_policy_update` now sends an **acknowledgement-requested** command
  (`configuration_update_command_with_nssai(&[], false, true)` — a bare indication IE,
  no NSSAI) via `push_tracked_config_update`, so every AM-policy nudge is retransmitted
  under T3555 until the UE's Configuration Update Complete. It takes a `tx` to arm the
  timer (threaded from both call sites: the `UpdateAmPolicy` command and the CM-IDLE
  resume path).
- `on_t3555_expiry` rebuilds the retransmission via `config_update_downlink`, so a
  resent AM-policy command **re-attaches its Mobility Restriction List**.
- `on_sdm_data_change`'s NSSAI path now also routes through `push_tracked_config_update`
  (area `None`), sharing one tracking path with the AM-policy side.

## Boundaries / notes

- **Every** AM-policy Configuration Update now requests acknowledgement (the nudge is
  always retransmitted); a plain SDM AMBR-only nudge still doesn't (design/109).
- Single outstanding command per UE (latest-wins): a later AM-policy or SDM update
  replaces the pending command and re-arms, unchanged from design/109.
- The retransmitted MRL is idempotent at the RAN (it re-applies the same restriction);
  re-attaching it is faithful, not a new restriction.

## Verification

- `cargo test --workspace --exclude bdd` — green (**202** tests). Updated:
  - nf-amf `am_policy_update_notify_applies_the_new_ue_ambr` — the AM-policy command
    requests acknowledgement and is tracked, and the tracked service area matches
    (cleared when the policy clears it).
  - nf-amf `config_update_retransmits_then_gives_up` — the pending command now carries a
    service area, and each retransmission re-attaches the MRL (asserted on the DL).
  - nf-amf `pcf_removing_the_ambr_override_falls_back_to_subscribed`,
    `partial_update_notify_keeps_omitted_fields` — moved to `#[tokio::test]` (arming
    spawns the timer) and pass `tx`.
- `cargo clippy --workspace --exclude bdd` — no new warnings (the new
  `Option<(Vec<[u8;3]>, Vec<[u8;3]>)>` occurrences use the `AreaRestriction` alias;
  parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). No
  AM-policy UpdateNotify runs under `@sim` (skipped, `FREE_RAN_UE_BIN` unset).

## Known limitations / next steps

- **Give-up escalation** — a UE that never acknowledges (any tracked command) is still
  silently dropped after the cap; implicit deregistration would be the spec-faithful
  escalation.
- **AreaRestriction alias** applied only where this slice touched — the pre-existing
  `on_am_policy_update` / `UeCmd::UpdateAmPolicy` / `PendingAmPolicy` tuple types could
  adopt it too (cosmetic).
