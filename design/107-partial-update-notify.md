# Partial UpdateNotify Semantics

> Built 2026-07-04 on branch `feat/partial-update-notify`. The remaining Nudm_SDM /
> PCF-arc tail (designs 99–106): an `Npcf_AMPolicyControl_UpdateNotify` was treated as
> the **full** current AM policy — an attribute absent from the notification was read
> as *removed*. This makes the UpdateNotify a **partial** delta: an omitted attribute
> is *kept*, an explicit `null` *clears* it, a value *sets* it (TS 29.507).

## The problem

Design/105 let the PCF **remove** its UE-AMBR override by sending an UpdateNotify with
no UE-AMBR — because the AMF applied the notification as a full replacement (absent =
gone). That's fine when the PCF always sends the complete policy, but it means the PCF
**cannot change one attribute without restating the rest**: an UpdateNotify that
carries only a new RFSP would silently wipe the UE-AMBR override and the service area.
Real PCFs signal a *delta* (TS 29.507 §5.6.2 `PolicyUpdate`) — only what changed.

## What was built

### `sbi-core` (`npcf_am`)

- **`FieldUpdate<T>`** — a three-way attribute delta: `Keep` (omitted → keep the AMF's
  current value), `Clear` (JSON `null` → remove it), `Set(T)` (a value → set it).
  `Default` is `Keep` (a hand-written impl — `#[derive(Default)]` would add a spurious
  `T: Default` bound that `FieldUpdate<Ambr>` can't meet). `apply(current)` resolves
  the delta against the AMF's value.
- **wire format** — a custom `deserialize_with` maps a *present* attribute to `Clear`
  (null) or `Set` (value); an *absent* key falls to `Default` (`Keep`). `serialize_with`
  + `skip_serializing_if = "FieldUpdate::is_keep"` emits `null` for `Clear`, the value
  for `Set`, and omits `Keep` entirely. This is what distinguishes *absent* from *null*.
- **`PolicyUpdate`** — the partial UpdateNotify body: `rfsp`, `ue_ambr`, `serv_area_res`,
  each a `FieldUpdate`.
- **`PolicyAssociation::diff(&self, next) -> Option<PolicyUpdate>`** — the delta from the
  previous decision to the fresh one: a changed attribute is present (new value → `Set`,
  removed → `Clear`), an unchanged one omitted. `None` when nothing changed.
- The **`update` handler** now notifies with `prev.diff(&fresh)` (the partial delta)
  instead of the full `fresh` policy; still returns the full `fresh` to the OAM caller.

### `nf-amf`

- **`am_policy_notify`** deserializes a `PolicyUpdate` (was `PolicyAssociation`) and
  translates each attribute into the AMF's internal `FieldUpdate`, preserving the
  three-way distinction (a `Set` UE-AMBR whose bitrates don't parse → `400`; a `Set`
  service area with no usable TAC → `Clear`, matching the pre-partial behaviour).
- **`UeCmd::UpdateAmPolicy`** + **`PendingAmPolicy`** (the CM-IDLE hold) carry
  `FieldUpdate<…>` for all three attributes (were plain `Option<…>`).
- **`on_am_policy_update`** resolves each delta against the context —
  `ctx.pcf_ue_ambr = ue_ambr.apply(ctx.pcf_ue_ambr)`, likewise `rfsp` and
  `area_restriction` — then signals the resolved policy (UE Context Modification with
  the effective UE-AMBR + RFSP, a Configuration Update Command with the Mobility
  Restriction List) exactly as before. An omitted attribute is now **kept**, not wiped.

## Boundaries / notes

- The PCF sends a **minimal** diff (only changed attributes), so a notify that changes
  only the RFSP no longer disturbs the UE-AMBR override or the service area.
- **`Clear` still means remove** — design/105's UE-AMBR-override removal is now an
  explicit `ueAmbr: null` in the delta rather than "the whole policy omits it".
- The full-policy `PolicyAssociation` is unchanged for **create** (the association still
  returns the complete policy); only the **UpdateNotify** body became partial.
- `triggers` are informational and not diffed.

## Verification

- `cargo test --workspace --exclude bdd` — green (**200** tests, +2). New/updated:
  - sbi-core `policy_update_partial_semantics` — the wire mapping (absent→Keep,
    null→Clear, value→Set), `apply`, and `diff` (a changed attribute present, a removed
    one as `null`, an unchanged one absent; `{rfsp, ueAmbr:null}` on the wire; `None`
    when nothing changed).
  - sbi-core `update_notifies_the_amf_on_a_policy_change` — the pushed body is now a
    partial `PolicyUpdate`: an RFSP-only change carries just `rfsp` (UE-AMBR/service
    area `Keep`); a service-area-only change carries just `servAreaRes` (RFSP `Keep`).
  - nf-amf `partial_update_notify_keeps_omitted_fields` — an RFSP-only delta keeps the
    UE-AMBR override, effective UE-AMBR, and service area (all still signalled).
  - nf-amf `pcf_removing_the_ambr_override_falls_back_to_subscribed` — clearing only
    the UE-AMBR (`Clear`) keeps the RFSP (`Keep`).
  - nf-amf `am_policy_update_notify_applies_the_new_ue_ambr` +
    `am_policy_update_for_a_cm_idle_ue_pages_and_applies_on_resume` — moved to the
    `FieldUpdate` API.
- `cargo clippy --workspace --exclude bdd` — no new warnings (parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). The
  `@sim` e2e was skipped this session (`FREE_RAN_UE_BIN` unset) and doesn't drive the
  AM-policy UpdateNotify path regardless.

## Known limitations / next steps

- **Session-policy (`Npcf_SMPolicyControl`) partial updates** — the same three-way
  delta could apply to the SM-side UpdateNotify (PCC rules, session-AMBR).
- **Configuration Update Complete retransmission** (from design/106) — still open.
