# "Come Back Later" — AMF Registration Admission Pacing

> Built 2026-08-07 on branch `feat/136-come-back-later`. Ports the **CBL
> ("Come Back Later") overload-control mechanism** from the `l5g_log_ai`
> research prototype (free5GC `cbl_admission_pacing` + free-ran-ue) into the
> radian AMF: bound the AMF's concurrent registration work under a
> registration storm by deferring excess attempts with an explicit retry
> indication, instead of admitting everything and letting timeouts collapse
> the core.

## Background (the l5g_log_ai reference)

The prototype (`../l5g_log_ai/free5gc-4.2.2/NFs/amf/internal/{context,ngap}`,
`../l5g_log_ai/free-ran-ue/gnb/cbl.go`, experiment plan
`../l5g_log_ai/cbl_experiment_plan.md`) gates `InitialUEMessage` on the number
of **in-progress registrations** C(t) against a threshold M(t). At the
threshold, the AMF sends a tiny **SCTP-layer indication** on the N2 association
— below NGAP, with its own PPID — carrying the RAN-UE-NGAP-ID and a retry timer;
the gNB relays it to the UE, which backs off exactly that long and re-attempts
with a fresh connection. Deferred UEs return as a paced stream rather than a
synchronized timeout herd.

The plan's **P0-1** (the meta-review's first acceptance condition) requires the
threshold check and the counter increment to be **one atomic
check-and-reserve** — the earlier check-then-increment had a TOCTOU that
admitted past M(t) under concurrency. Radian implements that design directly.

## Decisions

- **D1 — gate position and scope.** The gate sits at the top of the AMF's
  `Id_InitialUEMessage` arm, before any NAS work, but **after** the
  retained-context resume check: a Service Request / mobility-update resume is
  not a registration, would never send the Registration Complete that frees a
  slot, and deferring it would break CM-IDLE resume. (Deviation from the
  prototype, which gates every InitialUEMessage; its storm workloads were all
  initial registrations, so the distinction never showed there.)
- **D2 — wire compatibility.** The indication is byte-identical to the
  prototype: PPID `0xcb000000`, payload (big-endian, 10 bytes)
  `magic 0xCB,0x01 | RAN-UE-NGAP-ID u32 | retry timer ms u32`. The magic never
  begins a valid NGAP PDU (those start 0x00/0x20/0x40), so a receiver can branch
  on either the PPID or the prefix. A CBL-capable free-ran-ue gNB/UE therefore
  works against the radian AMF unchanged (golden-bytes unit test).
- **D3 — slot lifecycle is RAII + a decay lease.** An admitted registration
  holds a `CblSlot` in its `UeContext`; the slot decrements C(t) **exactly
  once** (CAS-guarded) on the first of: Registration Complete (`cbl_slot =
  None`), *any* context-teardown path (reject, release, NG Reset, association
  loss — the context drops, and `Drop` releases), or the **decay lease**
  expiring (default 10 s — a UE that silently vanishes mid-registration cannot
  leak C(t) and permanently throttle admissions; counted as `stale`, the
  prototype's downstream-saturation signal). The prototype needs explicit
  `CblUncount()` calls at each removal site; Rust ownership collapses them all
  into `Drop`.
- **D4 — configuration: env + OAM, no config file.** `RADIAN_AMF_CBL_THRESHOLD`
  arms the gate at boot (absent ⇒ disabled, zero overhead);
  `RADIAN_AMF_CBL_RETRY_MS` (default 2000) and `RADIAN_AMF_CBL_DECAY_SECS`
  (default 10; 0 disables the lease) tune it. At runtime,
  **`GET`/`POST /oam/v1/cbl`** on the existing OAM surface (next to design/132's
  `/oam/v1/overload`) exposes telemetry and control: `{"threshold": N[,
  "retry_ms": M]}` arms/retunes, `{"enable": false}` stands down. This is the
  prototype's external-controller seam (its `GET /cbl` + `POST /cbl/threshold`),
  by which the threshold policy can live outside the AMF (the l5g_log_ai
  MCP/LLM controller experiments).
- **D5 — overshoot accounting.** `max_overshoot` records the largest observed
  C(t) − M(t) at admits and threshold changes. The CAS makes racing-admit
  overshoot structurally 0; a positive value can arise only when an operator
  lowers M below the live count — which is legal (existing admissions kept, new
  admits stop, C(t) converges as slots free) and deliberately distinguishable
  in runs (P0-1's acceptance evidence).
- **Non-goals (research harness, not core):** the prototype's adaptive
  threshold controllers (reactive AIMD / feedforward curve / external mode),
  the comparison baselines (token-bucket, NGAP Overload Start shedding,
  NAS Registration Reject #22 + T3346 — radian already has the T3346 machinery
  from design/36), backlog-paced retry timers (tpace), and the AMF-load
  bottleneck simulator stay out. The telemetry counters and the OAM seam are
  exactly what an external controller needs, so those experiments can run
  against radian without further AMF surgery.

## What was built

- **`nf-amf/src/cbl.rs`** — the gate. `CblState::admit()` is the P0-1 atomic
  check-and-reserve (one `compare_exchange` covers threshold check +
  increment); returns `Disabled` / `Admitted(CblSlot)` / `Deferred{retry_ms}`.
  `CblSlot` = `Arc<SlotLease>` with a CAS-idempotent release, armed with the
  decay timer; counters (`admitted/deferred/stale_total`, `max_overshoot`) and
  the `snapshot()`/`apply_control()` OAM surface. `send_come_back_later()`
  writes the 10-byte payload with `SendInfo{ppid: 0xcb000000}` and emits the
  structured `event=cbl_defer` log line (the prototype's ECS-JSON analogue).
- **`nf-amf/src/main.rs`** — wiring: the gate in the `Id_InitialUEMessage` arm
  (resume-exempt, D1); the reserved slot bound into the new `UeContext`
  (`cbl_slot` field) right after `on_initial_ue`; released on Registration
  Complete; `/oam/v1/cbl` routes on the callback router.
- **BDD** — `ScriptedGnb::recv_come_back_later()` (decodes the raw SCTP
  payload exactly like free-ran-ue's `gnb/cbl.go`); operator steps driving
  `/oam/v1/cbl`; a `scripted_reg` scenario: threshold 0 ⇒ the registration is
  deferred with the configured 1500 ms retry timer, threshold restored ⇒ the
  same UE's retry is admitted and completes the full 5G-AKA registration, after
  which the gate reports 0 ongoing (the slot was released), and CBL is stood
  down.

## Verification

- `cargo test -p nf-amf cbl` — 6 new unit tests:
  - `concurrent_admits_never_exceed_the_threshold` — 64 racing admits against
    M=8 on a multi-thread runtime: exactly 8 admitted, 56 deferred,
    `max_overshoot == 0` (P0-1 acceptance), freed slots readmit.
  - `a_slot_releases_exactly_once` / `the_decay_lease_reclaims_a_stalled_slot`
    — drop⇄decay race frees once; a stalled slot is reclaimed as stale and a
    late drop of it is a no-op.
  - `lowering_the_threshold_below_the_live_count` — admits stop, existing
    stay, overshoot recorded.
  - `the_payload_matches_the_free_ran_ue_decoder` — golden bytes.
  - `oam_control_arms_and_stands_down_the_gate`.
- **BDD `scripted_reg`: 21 scenarios / 233 steps green** (20 pre-existing
  unaffected + the CBL arc above).
- `cargo test --workspace --exclude bdd` — green (46 test binaries, 0
  failures). Clippy: no findings in the new code.

## Known limitations / next steps

- **Fresh registrations only** (D1): a storm of Service Requests is not paced.
  The prototype's evidence is registration storms; extending the gate to
  resumes would need its own completion signal (Service Accept) to free slots.
- **The retry indication is trust-the-UE**: nothing enforces the back-off (same
  posture as T3346, design/36). A non-compliant UE retrying early just meets
  the gate again.
- **No adaptive controller in-core** — by design (D4): drive the threshold
  externally via `/oam/v1/cbl`. Porting the prototype's reactive (AIMD-on-stale)
  loop as an opt-in would be a small follow-up if wanted.
- The OAM endpoint is unauthenticated, matching the existing
  `/oam/v1/overload`; the SBI OAuth/mTLS work (design/46/56) does not yet cover
  the OAM routes.
- **`@sim` interop not yet exercised**: the scripted-gNB scenario proves the
  wire format against a from-spec decoder; the symmetric proof — the real
  CBL-capable free-ran-ue (`../l5g_log_ai/free-ran-ue`, the v2 module) as
  `FREE_RAN_UE_BIN`, many UEs, a low threshold — is the natural next step for a
  live storm-interop scenario.
