# NRF Heartbeat-TTL Expiry — Implementation Notes

> Built 2026-07-02 on branch `feat/nrf-heartbeat-expiry`. Step 1 (NRF half) of the
> DB design study ([24](24-db-subscriber-nf.md)): NF profiles are soft state — make
> the registry behave that way.

Since [04](04-sbi-spine-nrf.md) the NRF accepted heartbeats but never used them: a
crashed NF stayed discoverable forever. This slice makes registrations expire and
gives the registering NFs a maintenance loop, closing the loop on the TS 29.510
heartbeat contract. Deliberately **no database** — per doc 24, NRF state is
rebuilt by re-registration, so persistence would buy nothing.

## What was built

- **`NrfStore` liveness** (`sbi_core::nnrf`) — each entry now carries `last_seen`;
  the store holds a configurable `heartbeat_timer` (default **10s**,
  `NrfStore::with_heartbeat_timer`). An entry whose silence exceeds **2×** the
  timer (one missed heartbeat tolerated) is evicted **lazily** on
  discovery/list/heartbeat — no background sweeper task.
- **Assigned `heartBeatTimer`** — NFRegister responses now carry the interval
  (whole seconds, clamped ≥ 1), so NFs learn the contract from the NRF instead of
  assuming it.
- **Heartbeat semantics** — PATCH refreshes `last_seen`; a PATCH after eviction
  returns `404`, which is the client's signal to re-register.
- **`register_and_maintain(nrf_base, profile)`** — client-side helper: registers,
  then spawns a task that heartbeats at the assigned interval and re-registers
  on failure/eviction. The **AUSF and SMF** now use it instead of a one-shot
  register.
- **`nf-nrf`** — heartbeat interval overridable via `RADIANT_NRF_HEARTBEAT_SECS`.

## Verification

- `cargo test --workspace --exclude bdd` — green. New `sbi-core` tests, all over
  real h2c (axum + reqwest on ephemeral ports):
  - `register_assigns_heartbeat_timer` — response carries the store's interval.
  - `stale_nf_is_evicted_and_heartbeat_404s` — 50ms timer: registered NF is
    discoverable, goes silent, discovery is empty after the TTL and heartbeat
    returns `404`.
  - `heartbeat_keeps_nf_discoverable_past_ttl` — manual heartbeats every 40ms
    keep the NF alive well past the 100ms TTL.
  - `register_and_maintain_survives_eviction` — the maintenance loop (1s assigned
    interval) keeps the NF discoverable past the 2s TTL.

## Known limitations / next steps

- **Eviction, not `SUSPENDED`** — TS 29.510 also allows marking a profile
  suspended before removal; we evict directly. Fine at this scale.
- **The wire field is whole seconds** — sub-second store timers (used in tests)
  are advertised as 1s; the store still enforces its true sub-second TTL.
- **No NFStatusSubscribe** — peers poll discovery; push notifications on
  registration/eviction are a later slice (doc 24 notes Redis pub/sub or etcd
  watch if the NRF ever needs to scale out).
- **AMF does not register** — it only discovers, so it has no heartbeat loop yet;
  UDM/UDR registration comes with the Nudr relocation slice.
