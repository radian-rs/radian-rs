# SMF IPAM: releasable UE address pool (design/137 G6)

> Built 2026-08-08 on branch `free5gc`. Closes the **leak** half of **G6** from
> [137](137-free5gc-422-gap-survey.md) §8 (Major severity — a long-lived SMF
> exhausts its address space). Per-DNN pools and per-subscriber static IPs are
> scoped out (see §Follow-ups).

## The gap

The SMF allocated UE addresses from two **monotonic `AtomicU32` counters**
(`next_ue_ip`, `next_ue_ipv6`) with `fetch_add` and **never freed them**. Two
problems:

1. **Leak.** A released PDU session's address was never reclaimed, so a
   long-lived SMF marches through `10.45.0.0/16` and eventually can hand out no
   more usable addresses.
2. **Unbounded.** The counter had no upper bound — past `10.45.255.255` it would
   wrap into unrelated ranges / the broadcast address rather than reporting
   exhaustion.

free5gc (`ue_ip_pool.go` + `lazyReusePool`) and open5gs (`ogs_pfcp_ue_ip_alloc`
/ `_free` over per-DNN subnets) both allocate *and* release.

## What this slice does

A small **lazy-reuse pool** replaces each counter:

```
struct U32Pool { next: u32, end: u32, freed: BTreeSet<u32> }
```

- `alloc()` — returns the lowest previously-freed value if any (so a busy SMF
  churns a small working set of addresses), else the next never-used value from
  the high-water mark, else `None` when `[start, end)` is exhausted.
- `release(v)` — returns `v` to `freed`. A `BTreeSet` makes a **double-release a
  no-op**, so the same address can never be handed to two live sessions; a value
  that was never allocated (`>= next`) is ignored.

`SmfState` now holds `ue_ipv4_pool` / `ue_ipv6_pool` (`Mutex<U32Pool>`):
- IPv4: `10.45.0.2 ..= 10.45.255.254` (skips the network and broadcast).
- IPv6: the /64-index space `1 .. u32::MAX` (the index rides the 3rd+4th hextets
  of the prefix and the interface identifier, exactly as before).

`alloc_ue_ip` / `alloc_ue_ipv6` return `Option`; exhaustion refuses the session
with `503 INSUFFICIENT_RESOURCES` (→ 5GSM #26), mirroring the existing GFBR
admission refusal.

### Leak-free failure paths (the release-correctness risk)

[137](137-free5gc-422-gap-survey.md) §7 flagged the trap: *release on the wrong
path and you re-allocate a live address*. `create_sm_context` has several early
returns between allocation and storing the context (UPF no-response, PFCP
reject, chain rollback). Rather than thread a release into each, an RAII guard
owns the correctness:

```
struct IpLease<'a> { smf: &'a SmfState, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>, committed: bool }
```

The lease is created right after allocation and **frees the address(es) on drop
unless `commit()`ed**. It is committed only once the `SmContext` is inserted into
the table — from that point the stored context owns the addresses, released
exactly once in `release_sm_context` (after the context is removed). So:

- any early return before insert → the guard drops → addresses freed;
- success → committed → addresses live in the context → freed at release;
- no path frees an address a live context still holds, and none leaks.

## Decisions

- **D1 — lazy reuse, lowest-first.** `pop_first()` makes allocation
  deterministic (nice for tests) and keeps the working set compact. Matches
  free5gc's `lazyReusePool` intent.
- **D2 — one global pool per family**, not per-(S-NSSAI, DNN, UPF). radian's UPF
  N6 subnet is a single `10.45.0.0/16` today, so one pool suffices; per-DNN
  pools are a config-driven follow-up ([G5](137-free5gc-422-gap-survey.md) +
  G6's remainder).
- **D3 — RAII guard over scattered releases.** The failure paths are the risky
  part; a `Drop`-based lease is robust to future edits adding new early returns.
  Its `Drop` only locks a `Mutex` (no async), and it holds `&SmfState` (Sync)
  across awaits, so the handler future stays `Send`.
- **D4 — exhaustion is `INSUFFICIENT_RESOURCES` (503 → 5GSM #26)**, the same
  cause the GFBR admission check already uses for "can't serve this session".

## Tests

- `u32_pool_reuses_freed_and_bounds_the_range` — sequential alloc, exhaustion,
  lowest-first reuse, idempotent/spurious release.
- `ip_pools_round_trip_through_alloc_release` — the IPv4 pool hands out
  `10.45.0.2`, `.0.3`, and reuses a released `.0.3`.
- The single-UPF end-to-end test now creates a session (gets `10.45.0.2`),
  releases it, and asserts a **fresh session reuses `10.45.0.2`** rather than
  advancing to `.0.3` — the leak fix proven through the real Nsmf create/release
  handlers.
- `nf-smf` 34 green; clippy clean; BDD `scripted_datapath` (7 scenarios) passes
  against the rebuilt SMF.

## Follow-ups (the rest of G6)

- **Per-(S-NSSAI, DNN, UPF) pools** and **static pools**, keyed from config
  (needs [G5](137-free5gc-422-gap-survey.md)'s config surface).
- **Per-subscriber static IP** from UDM `staticIpAddress` (the SMF would honour
  it instead of allocating, and select the UPF whose pool serves it).
- **Overlap detection** between dynamic and static ranges.
