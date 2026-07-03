# Npcf_AMPolicyControl_UpdateNotify — PCF-initiated AM Policy Change

> Built 2026-07-03 on branch `feat/am-policy-update-notify`. Designs
> [67](67-npcf-am-policy.md)/[68](68-udr-am-policy-data.md) built the AM policy
> association and sourced it from the UDR, but the policy was fixed for the life of
> the association (re-read only at create). This adds the **PCF-initiated** change:
> an operator edits the subscriber's UDR am-policy-data, a trigger re-evaluates the
> association, and — when the policy actually changed — the PCF pushes
> `Npcf_AMPolicyControl_UpdateNotify` (TS 29.507) to the AMF, which applies the new
> UE-AMBR and runs the **Generic UE Configuration Update** procedure toward the UE.
>
> This is the AM analogue of the SM-side Update path ([48](48-pcf-udr-policy.md)'s
> follow-up) and mirrors the SMF→AMF modify callback shape ([50](50-n2n1-pdu-modify.md)):
> a change discovered on the SBI plane is delivered to the per-association N2 task,
> which turns it into signalling.

## What was built

### PCF (`sbi_core::npcf_am`) — the notify producer

- The association store became `HashMap<id, (PolicyAssociationRequest, PolicyAssociation)>`
  — it keeps both the **creating request** (for the AMF's `notificationUri`) and the
  **current decision** (so an Update can tell whether anything changed).
- `PolicyAssociationRequest` gained `notificationUri` — the AMF's callback URI,
  supplied at create (TS 29.507 §5.6.2.2).
- New `POST …/policies/{id}/update` handler (+ `AmPolicyClient::update`): re-runs
  `decide_for(supi)` (re-reading the UDR), and
  - **unchanged** → `204`, no notify;
  - **changed** → store the new decision, `POST` the new `PolicyAssociation` to the
    AMF's `notificationUri` over h2c, return `200` + the fresh policy.
- `PolicyAssociation`/`Ambr` derive `PartialEq`/`Eq` for the change check.

The `update` trigger stands in for the OAM/operator edit path — an external actor
POSTs it after changing the subscriber's am-policy-data.

### AMF (`nf-amf`) — the notify consumer

- `create_am_policy` now sends `notificationUri =
  {scheme}://{advertise}:8001/npcf-callback/v1/am-policy-notify/{supi}`.
- New callback route `POST /npcf-callback/v1/am-policy-notify/{supi}` (`am_policy_notify`):
  parses the pushed `PolicyAssociation`, converts its `ueAmbr` strings to bps
  (`bitrate_to_bps`), resolves the SUPI in `UE_DIRECTORY`, and hands the association
  task a `UeCmd::UpdateAmPolicy { amf_ue_id, ue_ambr }`. `204` if delivered; `404`
  if the UE isn't reachable over N2; `400` on an unparseable bitrate.
- New `serve_gnb` handler `on_am_policy_update`: overwrites `ctx.ue_ambr`, logs the
  new UE-AMBR, and — if the UE has a NAS security context — emits a protected
  **Configuration Update Command** in a `DownlinkNASTransport` (the Generic UE
  Configuration Update procedure, TS 24.501 §5.4.4). The stored `ctx.ue_ambr` is
  what the AMF advertises to the gNB on the next N2 context setup / handover.

The `UeCmd` → per-association-task dispatch is the same callback→N2 bridge used by
paging and the SM modify path — the SBI callback resolves the UE and the owning N2
task produces the signalling.

## Boundaries / notes

- **UE-AMBR + Configuration Update Command is the applied effect.** RFSP re-steering
  and service-area application to the RAN remain deferred (from design/67). The new
  RFSP is carried in the notify and logged, not signalled.
- **The `update` trigger is a stand-in for OAM.** There's no autonomous PCF watch on
  the UDR; an external POST drives re-evaluation (the shape a real Nudr_DataRepository
  subscription/notification would take).
- **`notificationUri` round-trips over h2c**, like every other SBI callback. The live
  smoke confirms the PCF→AMF push completes with no transport error against real
  binaries; delivery to a *live* UE over N2 (a registered UE in `UE_DIRECTORY`) is
  covered by the unit test, matching the design/50 precedent (free-ran-ue can't drive
  this callback plane).

## Verification

- `cargo test --workspace --exclude bdd` — green (**149** tests). New:
  - npcf_am `update_notifies_the_amf_on_a_policy_change` — a real in-process UDR +
    PCF + mock AMF notify surface: unchanged Update → `204`/no notify; after a UDR
    edit → `200` + the AMF receives the new policy exactly once.
  - nf-amf `am_policy_update_notify_applies_the_new_ue_ambr` — `on_am_policy_update`
    overwrites `ctx.ue_ambr` and emits a Configuration Update Command the UE's NAS
    context verifies; an unknown UE yields no downlinks.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the @sim registration path is
  unaffected.
- **Live (real binaries)** — NRF + demo-provisioned UDR + PCF + AMF:
  1. Create the demo AM policy association (UDR policy: RFSP 5, 300/600 Mbps).
  2. Update with no UDR change → `204`.
  3. Edit the UDR am-policy-data (RFSP 9, UE-AMBR 800 Mbps / 1500 Mbps).
  4. Update again → `200` + the new policy; the PCF logs
     *"AM policy changed — notifying the AMF (UpdateNotify)"* and the h2c push to the
     AMF's `am-policy-notify` callback completes with **no transport failure**.

## Known limitations / next steps

- **Signal the new RFSP / service-area to the RAN** — carry the AM policy change into
  N2 (RFSP index, Service Area List) rather than only the UE-AMBR + a UE
  Configuration Update Command.
- **Autonomous UDR-change delivery** — a real Nudr subscription so the PCF re-evaluates
  without an external `update` POST.
- **Richer am-policy-data** (per-slice / per-area policy) from design/67's list.
