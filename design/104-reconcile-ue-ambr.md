# Reconcile Subscribed vs PCF UE-AMBR

> Built 2026-07-04 on branch `feat/reconcile-ue-ambr`. The subscribed UE-AMBR
> (am-data, via a Nudm_SDM change, design/99/101) and a PCF AM-policy override
> (design/70) both wrote `ctx.ue_ambr` last-wins — so a subscribed-data change could
> clobber an active PCF override (and vice-versa). This tracks the two sources
> separately and derives the effective UE-AMBR with the correct precedence: **PCF
> over subscribed** (TS 23.503 — the PCF's AM policy is authoritative; the subscribed
> value is the default).

## What was built (`nf-amf`)

- `UeContext` gained `subscribed_ue_ambr` (from am-data) and `pcf_ue_ambr` (PCF
  AM-policy override); `ue_ambr` is now the **effective** value, derived by
  `recompute_ue_ambr()` = `pcf_ue_ambr.or(subscribed_ue_ambr)`. Everything that
  signals the UE-AMBR (N2 setup, UE Context Modification) still reads `ctx.ue_ambr`,
  so no other site changed.
- **Registration** (`on_security_mode_complete`): records `subscribed_ue_ambr`
  (fail-open — a failed am-data fetch keeps a previously-known value) and, when a PCF
  AM policy applies, `pcf_ue_ambr`; then recomputes.
- **PCF UpdateNotify** (`on_am_policy_update`): sets `pcf_ue_ambr`, recomputes, and
  signals the effective (= PCF) value to the RAN.
- **Nudm_SDM change** (`on_sdm_data_change`): sets `subscribed_ue_ambr`, recomputes,
  and re-signals **only if the effective changed** — so a subscribed change under an
  active PCF override is stored (for when the policy is later removed) but not
  signalled.

## Boundaries / notes

- **PCF override never cleared mid-session** here — an `UpdateAmPolicy` always
  carries a UE-AMBR, and the AM policy is deleted only at deregistration. So a stored
  subscribed value takes effect only via a future registration (which recomputes).
  A PCF-initiated *removal* of the override (→ fall back to subscribed live) is a
  follow-up.
- Only a **CM-CONNECTED** UE is re-signalled (the notification path, design/99).

## Verification

- `cargo test --workspace --exclude bdd` — green (**196** tests). New/updated:
  - nf-amf `sdm_ambr_change_yields_to_pcf_override` — with a PCF override in effect, a
    subscribed UE-AMBR change is stored (`subscribed_ue_ambr` updated) but signals
    nothing and leaves the effective at the PCF value.
  - `sdm_data_change_pushes_to_ran_and_ue` — a subscribed change with **no** PCF
    override still signals the new value (effective = subscribed).
  - `security_mode_complete_triggers_initial_context_setup` — updated to the source
    field; a failed am-data/PCF fetch keeps the already-known subscribed UE-AMBR in
    the ICS (the fail-open).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` registration
  derives the effective UE-AMBR from the real UDR's subscribed value + the demo PCF
  override (PCF wins); the UE registers, establishes a session, and pings.

## Known limitations / next steps

- **PCF override removal** — a live fall-back to the subscribed value when the PCF
  clears its AM-policy UE-AMBR (rather than only at the next registration).
- **Per-session AMBR** vs UE-AMBR reconciliation (session-AMBR is the SMF/PCF's, this
  is the AMF's UE-level aggregate).
