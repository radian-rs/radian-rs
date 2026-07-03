# GFBR Admission Control + URR Usage Reporting — Implementation Notes

> Built 2026-07-02 on branch `feat/gfbr-urr`. Two QoS-resource features that
> complete the QoS-enforcement story: **GFBR admission control** (the SMF refuses a
> PDU session whose guaranteed bit rate can't be met) and **URR usage reporting**
> (the UPF measures a session's volume and reports it at deletion).

## GFBR admission control (SMF-side)

The SMF is the 3GPP admission point — it decides whether to accept a session given
the guaranteed bit rate. So the budget + reservation live in `SmfState`:

- **`SmfState.gfbr_budget_bps` + `reserved_gfbr_bps`** — a `(downlink, uplink)`
  budget (bits/sec) and the currently reserved total. `with_gfbr_budget` sets it;
  `nf-smf` reads `RADIAN_SMF_GFBR_BUDGET_MBPS` (absent ⇒ unlimited).
- **`try_reserve_gfbr`** (atomic check-and-add), **`release_gfbr`**, **`adjust_gfbr`**.
- **CreateSMContext**, before any N4 state, sums the decision's GBR flows' GFBR
  (`decision_gfbr`) and reserves it; if either direction would exceed the budget it
  **refuses the session** (`503` + cause `INSUFFICIENT_RESOURCES`). The reservation
  is stored on the `SmContext`, released at teardown (and if the N4 establishment
  fails), and adjusted on a mid-session policy change (no re-admission — the PCF
  already authorized it).
- **AMF**: a new `CreateSmError::InsufficientResources` (SMF `503`) maps to a 5GSM
  **PDU Session Establishment Reject cause #26** (insufficient resources), no
  back-off (capacity may free up). `nas::sm_cause::INSUFFICIENT_RESOURCES = 26`.

## URR usage reporting (UPF-side)

- **`pfcp`**: the establishment always provisions a **session-level volume URR**
  (`CreateUrr`, measurement method = volume, id 1); both match-all PDRs reference it
  by `urr_id`. The `Session` counts **forwarded (admitted) bytes** per direction in
  `Session::admit` (where policing already happens). On **Session Deletion**, `remove`
  returns the session's `(uplink, downlink)` volume and `handle_n4` attaches a
  **Usage Report** (`VolumeMeasurement` total/ul/dl) to the deletion response.
- **`pfcp::usage_from_deletion_response`** parses it back to `(total, ul, dl)` bytes.
- **`nf-smf`**: on release, parses the deletion response's usage report and logs the
  session's volume (a charging / Nchf stand-in).

## Boundaries / notes

- **GFBR admission is establishment-time.** A mid-session GBR *increase* isn't
  admission-refused (the PCF authorized it); the reservation is adjusted for
  accounting. Only the aggregate per-direction GFBR is checked (no per-flow
  admission, no slice/DNN-scoped budgets).
- **URR is a single session-level volume URR**, reported only **at deletion** — no
  per-flow/per-QER URRs, no volume-threshold triggers or periodic reporting, and the
  report is logged (no Nchf/charging interface).
- Byte counting is over **admitted** (forwarded) bytes at the UPF; the live path is
  the real `nf-upf`, so the demo `@sim` ping is measured end to end.

## Verification

- `cargo test --workspace --exclude bdd` — green (111 tests). New:
  - `pfcp::urr_measures_volume_and_reports_at_deletion` — forward 3×1000 B uplink +
    2×500 B downlink, then the deletion response reports `(4000, 3000, 1000)` bytes.
  - `nf-smf::gfbr_admission_control_refuses_when_budget_exhausted` — with a budget of
    one demo GBR flow (100 Mbps): the first GBR session is admitted, the second is
    **refused (503)**, and after releasing the first the budget frees and a new
    session is admitted again.
- **BDD, 5 scenarios / 25 steps green**, incl. the live **`@sim`** e2e — the demo now
  provisions the URR (byte counting + a usage report at teardown) and GFBR admission
  is unlimited (no env budget), so registration + PDU session + ping are unaffected.

## Known limitations / next steps

- **Per-flow / per-QER URRs**, **volume-threshold + periodic** reporting (Session
  Report Request), and a real **Nchf** charging interface.
- **Per-flow GFBR admission** and slice/DNN-scoped budgets; mid-session GFBR
  re-admission (refuse an increase that no longer fits).
