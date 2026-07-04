# PCF UE-AMBR Override Removal

> Built 2026-07-04 on branch `feat/pcf-ambr-removal`. Design
> [104](104-reconcile-ue-ambr.md) tracked the PCF and subscribed UE-AMBR separately
> (PCF over subscribed), but the PCF override could only be *set*, never *cleared*
> mid-session — a stored subscribed value only took effect at the next registration.
> This lets a PCF `Npcf_AMPolicyControl_UpdateNotify` with **no UE-AMBR** remove the
> override, falling the effective UE-AMBR back to the subscribed value **live**.

## What was built (`nf-amf`)

- `UeCmd::UpdateAmPolicy.ue_ambr` and `PendingAmPolicy.ue_ambr` became
  `Option<(u64, u64)>` — `None` means "the policy carries no UE-AMBR → remove the
  override".
- `am_policy_notify` (the UpdateNotify callback) now treats a policy with **no**
  UE-AMBR as a removal (`ue_ambr = None`) rather than a no-op `204`; a present-but-
  malformed UE-AMBR is still `400`.
- `on_am_policy_update` sets `ctx.pcf_ue_ambr = ue_ambr` (so `None` clears it),
  recomputes the effective (`pcf.or(subscribed)`), and signals the effective value
  to the RAN in the UE Context Modification — so a removal re-signals the subscribed
  UE-AMBR.
- The CM-IDLE path (`PendingAmPolicy`) and the design/73 resume application carry the
  `Option` through unchanged.

## Boundaries / notes

- A UpdateNotify is treated as the **full** current AM policy: an absent UE-AMBR is a
  removal (not "unspecified — keep"). This matches design/69's full-association push.
- The effective UE-AMBR after a removal is the subscribed value, or the default at
  the gNB if neither source is set.
- Only a **CM-CONNECTED** UE is re-signalled immediately; a CM-IDLE UE's removal is
  held (`PendingAmPolicy { ue_ambr: None, .. }`) and applied on resume (design/73).

## Verification

- `cargo test --workspace --exclude bdd` — green (**197** tests). New:
  - nf-amf `pcf_removing_the_ambr_override_falls_back_to_subscribed` — with a PCF
    override `(5G/5G)` over a subscribed `(1M/500k)`, an `on_am_policy_update(None, …)`
    clears `pcf_ue_ambr`, sets the effective back to the subscribed value, and the
    RAN receives it in the UE Context Modification.
  - The existing AM-policy / pending-policy tests updated to the `Option` signature.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` still applies
  the demo PCF UE-AMBR (present) unchanged; the removal path isn't `@sim`-driven
  (integration-tested).

## Known limitations / next steps

- **Partial UpdateNotify** semantics (distinguish "field omitted — keep" from
  "field removed") via a change-indication, rather than treating every UpdateNotify
  as a full replacement.
- **Configuration Update Complete** tracking (the design/102 follow-up).
