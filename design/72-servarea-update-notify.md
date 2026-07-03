# Mid-Connection Service Area Change — UpdateNotify → Mobility Restriction List

> Built 2026-07-03 on branch `feat/servarea-update-notify`. Design
> [71](71-signal-service-area-to-ran.md) signalled the AM-policy **service area
> restriction** to the RAN at registration; design
> [69](69-npcf-am-policy-update-notify.md) built the PCF-initiated AM policy change
> (`Npcf_AMPolicyControl_UpdateNotify`) but only applied the UE-AMBR (+ RFSP from
> [70](70-signal-rfsp-to-ran.md)). This closes the remaining gap: a **mid-connection
> `servAreaRes` change** now rides the UpdateNotify path end to end — the operator
> edits the subscriber's UDR am-policy-data, the PCF pushes the changed policy, and
> the AMF signals the **updated Mobility Restriction List** to the RAN on the
> Configuration Update Command's `DownlinkNASTransport`.

## What was built

### PCF (`sbi_core::npcf_am`) — no code change needed

`PolicyAssociation` already derives `Eq` including `serv_area_res` (design/71), so
the design/69 `update` handler's `fresh == prev` diff **already fires on a
service-area-only change** and the pushed policy already carries the new
`servAreaRes`. This slice adds the test that pins that behaviour (see below).

### AMF (`nf-amf`)

- `UeCmd::UpdateAmPolicy` gained `area_restriction: Option<(allowed, non_allowed)>`
  (3-octet TAC lists).
- The `am_policy_notify` callback now parses `policy.serv_area_res` through the
  design/71 `area_restriction_tacs` and threads it to the association task.
- `on_am_policy_update` stores `ctx.area_restriction` (so later N2 messages see the
  current restriction) and builds the Configuration Update Command's transport with
  `downlink_nas_transport_with_area_restriction` when the policy has a service area
  — the same TS 38.413 §9.2.5.3 vehicle as registration (design/71), now on the CUC.
  A policy without a `servAreaRes` falls back to the plain transport and **clears**
  the stored restriction (the policy no longer restricts the UE).

The downlink sequence for a full AM policy change is now:
1. `UEContextModificationRequest` — RFSP + UE-AMBR at the UE-context level (design/70).
2. `DownlinkNASTransport` — the protected Configuration Update Command for the UE
   **plus** the Mobility Restriction List for the RAN (this slice).

## Boundaries / notes

- Same shape as design/71: one Service Area Information item, serving-PLMN-keyed,
  allowed/non-allowed TACs only.
- The UE's Configuration Update Command payload is unchanged (minimal, no NAS-level
  service-area IE) — the restriction is RAN-facing; the gNB enforces it.
- `RETAINED` (CM-IDLE) contexts are not reached by the UpdateNotify (the callback
  requires the UE in `UE_DIRECTORY`, i.e. CM-CONNECTED) — a policy change for an
  idle UE returns `404` to the PCF, unchanged from design/69.

## Verification

- `cargo test --workspace --exclude bdd` — green (**152** tests). New/extended:
  - npcf_am `update_notifies_the_amf_on_a_policy_change` (extended) — a
    **service-area-only** UDR edit (RFSP unchanged) still triggers the notify, and
    the pushed policy carries the new `servAreaRes` (TAC 000007).
  - nf-amf `am_policy_update_notify_applies_the_new_ue_ambr` (extended) — the
    handler stores the new area restriction, the CUC's `DownlinkNASTransport` carries
    the Mobility Restriction List (TAC 000002) the RAN reads back, the UE still
    verifies the CUC, and a policy without a service area falls back to the plain
    transport and clears the stored restriction.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — registration/PDU/ping unaffected.
- **Live (real binaries)** — NRF + demo-provisioned UDR + PCF + AMF:
  1. Create the demo association (`servAreaRes {ALLOWED_AREAS, ["000001"]}` from the UDR).
  2. Update with no change → `204`.
  3. Edit **only** the service area in the UDR (`000001 → 00000a`; rfsp/ueAmbr kept).
  4. Update → `200` + the new `servAreaRes`; the PCF logs *"AM policy changed —
     notifying the AMF (UpdateNotify)"* and the h2c push to the AMF completes with
     **no transport failure**. (Delivery to a live UE over N2 is unit-tested —
     free-ran-ue can't drive the callback plane, design/50/69 precedent.)

## Known limitations / next steps

- **Richer restrictions** — forbidden areas, RAT restrictions, per-slice areas,
  `maxNumOfTAs`.
- **Reach CM-IDLE UEs** — page (or defer to the next Service Request / registration)
  instead of `404` when a policy changes while the UE is idle.
- **A full Initial Context Setup procedure** — carry MRL + RFSP + security context at
  UE-context establishment, as a production AMF does.
