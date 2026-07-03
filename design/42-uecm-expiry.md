# UECM Stale-Registration Expiry — Implementation Notes

> Built 2026-07-03 on branch `feat/uecm-expiry`. Closes the "no UECM
> heartbeat/expiry" gap from [40](40-uecm.md)/[41](41-smf-uecm.md): a crashed
> AMF/SMF's serving-NF registration lingered until the subscriber was withdrawn.

## The approach: inherit the NRF's heartbeat, don't add a second one

A per-UE UECM heartbeat would be absurd (an AMF serving thousands of UEs
heartbeating thousands of records). Instead the UDR **reuses the liveness the
NRF already tracks** ([25](25-nrf-heartbeat-expiry.md)): each UECM record already
names its serving NF (`amfInstanceId` / `smfInstanceId`), so "is this
registration still valid?" reduces to "is that NF still registered with the
NRF?". A crashed NF stops heartbeating → the NRF evicts it → the UDR's sweep
drops any record naming a now-absent instance. **One NRF query per sweep, not per
registration.**

## What was built

- **`subscriber-db`** — `list_amf_registrations()` / `list_smf_registrations()`
  enumerate the context data as `(key, document)` for the sweep.
- **`sbi_core::nnrf`** — `NrfClient::list_instances()` (NFListRetrieval); the NRF
  purges heartbeat-expired NFs lazily on read, so the result is the live set.
- **`sbi_core::nudr::sweep_stale_registrations(store, nrf_base)`** — one pass:
  fetch the live instance-id set, evict every UECM record whose serving id isn't
  in it, return the count. **Fail-safe:** an unreachable NRF evicts nothing (it
  must not be read as "every NF is dead").
- **`nf-udr`** — a background loop runs the sweep every
  `RADIAN_UDR_UECM_SWEEP_SECS` (default 30s).
- **Consistency fix:** `nf-smf` now registers with the NRF using its stable
  `SMF_INSTANCE_ID` (was a fresh UUID per call) so the NRF profile id matches the
  UECM `smfInstanceId` — otherwise the sweep would think every SMF was dead.
  (The AMF already used a stable id for both.) Also dropped the unused
  `SmContext.dnn` field.

## Verification

- `cargo test --workspace --exclude bdd` — green (26 suites). New:
  - `subscriber-db::list_registrations_enumerates_context_data` (both backends).
  - `sbi-core::nudr::uecm_sweep_evicts_dead_nf_registrations` — one live AMF at
    the NRF; a live AMF record is kept, a dead AMF record and a dead SMF record
    are evicted; the pass is idempotent; an unreachable NRF evicts nothing.
- **Live crash demo** (fast timers: NRF heartbeat 2s, UDR sweep 3s): a
  registered UE's `amf-3gpp-access` reads `200`; **SIGKILL the AMF** (no
  deregistration, no UECM purge); the NRF logs "evicting stale NF … AMF" on
  heartbeat expiry, and the UDR logs "evicted stale serving-AMF registration
  (NF gone)" — the record is purged without the subscriber ever being withdrawn.
- **BDD, 5 scenarios / 25 steps green** (regression).

## Known limitations / next steps

- **Eviction latency = NRF TTL (2× heartbeat) + sweep interval** — bounded, not
  instant. Fine for a stale-record cleaner.
- **No NFStatusNotify** — the UDR polls the NRF on a timer rather than being
  pushed evictions; a subscription-based UDR would be tighter but heavier.
- Multiple PDU sessions per UE, UE-AMBR from am-data, AMF-side SMF selection,
  and SBI security hardening remain open.
