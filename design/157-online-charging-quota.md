# 157 — Online charging: CHF quota + FinalUnitIndication → SMF enforcement (G14, first slice)

**Status:** implemented
**Gap item:** [137](137-free5gc-422-gap-survey.md) §3.2 / §3.5 / §8 **G14** (online charging — first slice)
**Builds on:** [153](153-n4-query-urr.md) + [155](155-n4-urr-packet-counts.md) (the URR usage-report machinery), the CHF in `crates/sbi-core/src/nchf.rs`

## Problem

The CHF was, as §3.5 put it, *"a usage accumulator, not a charging function"* — it summed
used-unit containers into a CDR and always answered `SUCCESS`. There was **no quota /
reservation state machine** and no `FinalUnitIndication`, so §3.2's *"online charging
cannot be enforced at the UPF"* held: usage was billed after the fact, never capped.

This first G14 slice makes online charging **enforceable end-to-end**: the CHF grants a
per-session volume quota and, once spent, tells the SMF to stop the session — which the SMF
does, tearing the PDU session down. It reuses the existing VOLTH usage-report loop as the
meter (the UPF already reports every threshold increment, which re-arms), so no new N4
machinery is needed.

## Why this shape (not UPF VolumeQuota)

The "textbook" path installs a PFCP **VolumeQuota** on the UPF's URR so the UPF stops the
datapath itself and raises a VOLQU report. But rs-pfcp 0.3.1's `CreateUrr`/`UpdateUrr` do
not model a `VolumeQuota` IE, so that would need hand-marshaled grouped IEs. This slice
instead enforces at the **SMF** off the existing threshold reports — a clean, fully
supported path that delivers the same capability (traffic stops when quota is spent). UPF
VOLQU enforcement is a follow-up (needs the rs-pfcp gap closed).

## Design

- **CHF (`nchf`):** `ChfState::with_quota(bytes)` grants a per-session volume quota
  (`RADIAN_CHF_QUOTA_BYTES`; unset ⇒ unlimited, the pure-accumulator behaviour is
  unchanged). On each `update`, after absorbing usage, if the CDR's total volume reaches
  the quota the response carries `FinalUnitIndication { finalUnitAction: "TERMINATE" }`
  (new `ChargingDataResponse.final_unit_indication`). `ChfClient::update` now returns the
  parsed `ChargingDataResponse` instead of `()`.
- **SMF (`nf-smf`):** `release_sm_context`'s body is factored into a reusable
  `teardown_sm_context(smf, sm_ref)` (N4-delete every leg, relay final usage + release the
  CHF session, free IP/GFBR/UECM/PCF-policy). In `handle_usage_reports`, when the CHF
  update answers with `TERMINATE`, the SMF calls that teardown — online-charging
  enforcement. The report handler now also captures the `sm_ref` so it can address the
  teardown.

Purely additive: with no quota configured the CHF answers `SUCCESS` exactly as before, so
every existing charging test and the datapath BDD are unchanged.

## Tests

- `nchf::charging_quota_signals_final_unit_indication` — a quota CHF returns no FUI under
  quota and `TERMINATE` once usage reaches it.
- sbi-core/nf-smf/nf-chf build + clippy clean; full workspace build; BDD 47 scenarios /
  518 steps green (the teardown refactor + FUI wiring don't disturb the live paths).

## Follow-ups (rest of G14)

- **SMF/BDD integration test** for the FUI→teardown path (mock CHF-with-quota + a driven
  usage report), and a NAS **PDU Session Release Command** + **SMContextStatusNotify** to
  the AMF/UE on quota teardown (today the datapath is stopped and SMF/CHF/PCF/UDM state
  freed, but the UE/AMF are not notified — that notify is [G15](137-free5gc-422-gap-survey.md)).
- **Incremental grants** (updateGrantedQuota: grant the next quota instead of terminating),
  per-rating-group quotas + `MultipleUnitInformation`/`GrantedServiceUnit`, `REDIRECT`/
  `RESTRICT_ACCESS` final-unit actions, and validity-time triggers.
- **UPF VolumeQuota + VOLQU** enforcement once rs-pfcp models the IE (the datapath half).
