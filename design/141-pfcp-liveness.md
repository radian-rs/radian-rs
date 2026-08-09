# N4 liveness: PFCP heartbeat + UPF-restart recovery (design/137 G4)

> Built 2026-08-08 on branch `free5gc`. Closes the **liveness core** of **G4**
> from [137](137-free5gc-422-gap-survey.md) §8 (Major/robustness — *"a UPF
> restart silently strands every session"*). The remaining G4 items (UPF
> association-state enforcement, the PFCP transaction layer, UPF error causes)
> are scoped out — see §Follow-ups.

## The bug

Two halves conspired:

1. **The UPF regenerated its recovery timestamp on every message** — both the
   Association Setup Response and the Heartbeat Response used
   `SystemTime::now()` (`handle_n4`). The PFCP recovery timestamp is meant to be
   *the moment the node started*, constant until it restarts; regenerating it
   made the UPF look, to any conformant peer, like it was restarting
   continuously.
2. **The SMF never heartbeat the UPF** — `pfcp::heartbeat_request` existed with
   no caller — and never recorded or compared the UPF's recovery timestamp. So
   when a UPF actually restarted (losing all its PDR/FAR/URR state), the SMF's
   SM contexts — and the UE IPs they leased ([140](140-smf-ipam-pool.md)) — kept
   pointing at sessions the UPF had forgotten. The datapath was dead and nothing
   noticed.

Both reference stacks detect this: free5gc's `doPfcpHeartbeat` compares
`node.remote_recovery` and runs `releaseAllResourcesOfUPF`; open5gs pins
`local_recovery` at startup (`lib/pfcp/context.c:51`) and runs
`pfcp_restoration()` on a changed peer recovery timestamp.

## What this slice does

### UPF — pin the recovery timestamp (`crates/pfcp`)

`UpfState` gains a `recovery_time: SystemTime`, set once in `new()` (and
injectable via `with_recovery_time` for tests). Both the Association Setup and
Heartbeat responses now echo `state.recovery_time` instead of `now()`. A new
`pfcp::parse_recovery_timestamp(msg)` reads the IE back out — the SMF's detector.

### SMF — heartbeat, detect, recover (`nf-smf`)

- **`N4Peer`** records the UPF's recovery timestamp (`recovery: Mutex<Option<SystemTime>>`),
  learned first at `associate()`. `note_recovery(ts) -> Recovery` classifies each
  reported value: the baseline (or an equal/stale one) is `Unchanged`; a strictly
  *newer* one is `Restarted`.
- **`N4Peer::heartbeat()`** sends one Heartbeat Request and classifies the reply.
- **`run_heartbeats(smf, interval)`** — spawned once at startup
  (`RADIAN_SMF_HEARTBEAT_SECS`, default 10s) — calls `heartbeat_round()` on a
  timer, which heartbeats every peer.
- **`recover_from_upf_restart(peer)`** — on a `Restarted` verdict: re-associate
  the peer (so it accepts new sessions), then drop every SM context whose
  `SessionPath::uses(peer)`, returning each session's UE address(es) and GFBR
  reservation to the pools and purging its serving-SMF registration (Nudm_UECM).
  The UE re-establishes on its next activity. Mirrors `releaseAllResourcesOfUPF`.

## Decisions

- **D1 — recovery is "drop and let the UE re-establish", not "rebuild".** A
  restarted UPF has forgotten the sessions' rule state; the SMF cannot
  resurrect them (it would have to replay every PDR/FAR/QER/URR, re-learn the
  gNB F-TEIDs, etc.). Dropping them and reclaiming the SMF-local resources is
  what both reference stacks do and what keeps the address pool honest.
- **D2 — match affected sessions by peer identity** (`Arc::ptr_eq` on the
  `SessionPath`'s anchor/intermediate/breakout), so a multi-UPF deployment only
  drops the sessions that actually used the restarted node.
- **D3 — a single missed heartbeat is not a restart.** `heartbeat()` returns
  `None` on no reply; the loop logs and moves on. Only a *newer recovery
  timestamp* triggers recovery, so transient packet loss can't tear down live
  sessions.
- **D4 — leave PCF/CHF teardown to the normal release path.** `recover_*` only
  reclaims SMF-local resources (context, IP, GFBR, UECM). The PCF policy and CHF
  charging associations for a dropped session are cleaned up when the AMF later
  releases the context. Keeping the recovery path local avoids a fan-out of
  best-effort SBI calls on every restart; a fuller teardown pairs naturally with
  SMContextStatusNotify (G15).

## Tests

- `crates/pfcp`: `upf_recovery_timestamp_is_pinned_across_messages` — the
  Association and Heartbeat responses from one `UpfState` carry the *same*
  timestamp, and a fresh (restarted) state reports a strictly later one.
- `nf-smf`: `note_recovery_flags_only_a_newer_timestamp` — the classification
  (baseline / same / newer / stale-reordered).
- `nf-smf`: `upf_restart_drops_stranded_sessions_and_frees_addresses` — an
  end-to-end test: a session leases `10.45.0.2`; the mock UPF is swapped for a
  fresh state with a newer recovery timestamp; one `heartbeat_round()` drops the
  stranded context so a new session **reuses `10.45.0.2`** and the old context's
  modify returns 404.
- pfcp 26, nf-smf 36 green; clippy clean; BDD `scripted_datapath` + `n6_datapath`
  pass against the rebuilt SMF (heartbeat loop live).

## Follow-ups (remaining G4)

- **UPF association state** — reject a Session Establishment that arrives with no
  prior association; purge stale sessions on re-association; validate the Node ID
  (open5gs `pfcp-path.c`, free5gc `node.Reset()`).
- **PFCP transaction layer** — request retransmission + response dedup on both
  sides (open5gs `lib/pfcp/xact.c`). Today a lost request is a single 2s timeout
  and a retransmitted Establishment would double-allocate.
- **UPF error causes** — answer a malformed / unsupported N4 message with a
  Cause + Offending IE instead of silence (`handle_n4` currently returns `None`).
- **SMContextStatusNotify on restart** (G15) — proactively tell the AMF the
  dropped sessions are gone, instead of waiting for its next release.
