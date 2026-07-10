# BDD Scripted T3513 Paging Retransmission (idle arc complete)

> Built 2026-07-09 on branch `feat/bdd-scripted-t3513`. Tenth BDD slice of the design/116
> plan and the last piece of the idle arc: an **unanswered page is retransmitted under
> T3513** (design/74). A CM-IDLE UE that is paged but never resumes is paged again, up to the
> AMF's max-sends, driven and asserted from the scripted tier. Pure test code; no crate
> behaviour changed.

## What was built (all in `bdd`)

- `start_core` now spawns the AMF with **`RADIAN_AMF_T3513_SECS=2`** so the retransmission
  scenario runs in a few seconds. Two seconds is comfortably longer than a scripted resume
  takes, so the buffer-flush scenario (whose UE resumes) still stops paging before the first
  retransmit — verified: the whole suite stays green and deterministic.
- **Step** "the gNB is paged N times for the UE": the scripted gNB reads N successive `Paging`
  messages on its association, asserting each carries the UE's 5G-S-TMSI.
- **Scenario** "An unanswered page is retransmitted under T3513" in `scripted_datapath.feature`:
  register → PDU session → AN release → inject a downlink packet → the gNB is paged **3 times**
  (`T3513_MAX_SENDS`), because the UE never resumes.

`page_with_retx` loops up to `max_sends`: page the registration area, sleep T3513, and stop
early if the retained context is gone (a resume answered the page). With no resume, all three
attempts fire, T3513 apart.

## Ordering

The scenario runs **last** (before teardown): its UE never resumes, so its context stays
retained. Since every scripted UE reuses the demo SUPI, a later same-SUPI scenario's `page_ue`
(SUPI → retained 5G-TMSI) would resolve this stale UE first — the same constraint the
buffer-flush scenario documented. Placing it last, with teardown next, avoids that.

## Verification

- **`cargo test -p bdd` — 3 features / 18 scenarios / 191 steps GREEN** (deterministic across
  three runs): the new scenario observes the three T3513-spaced pagings; the buffer-flush
  scenario still passes with the shrunk timer; the rest of the suite is unaffected.
- `cargo clippy -p bdd --tests` — no net-new warnings (1 site before == after).
- No workspace crate changed.

## The idle arc is complete

The scripted tier now covers the whole CM-IDLE lifecycle end to end: AN release → CM-IDLE →
downlink data → **buffer + page** → (resume → flush) **or** (no resume → T3513 retransmit
until max-sends). Together with the datapath echo (design/124) it exercises every user-plane
and idle path the core implements, CI-runnable, with no external simulator.

## Next

The remaining design/116 fronts are **per-flow QoS / GBR** traffic policing over the datapath
(designs 49/51 — drive rate-limited/classified traffic and assert the UPF policer) and the
**handover / lifecycle** features (Xn / N2 handover need two scripted gNBs; deregistration and
the dereg/config-update timers are control-plane).
