# Configuration Update Give-up Escalation

> Built 2026-07-04 on branch `feat/config-update-giveup-escalation`. The open follow-up
> from designs 109/110: when T3555 exhausts (the UE never acknowledges a tracked
> Configuration Update Command after the full retransmission run), the AMF silently
> dropped the pending command. Now it **implicitly deregisters** the unreachable UE —
> the same escalation T3522 exhaustion already performs.

## What was built

### `nf-amf`

- **`implicit_deregister(ues, amf_ue_id)`** — extracted from the T3522 exhaustion path
  into a shared helper: purge the UE's GUTI, its Nudm state (SDM change subscription +
  UECM registration), and its PCF AM-policy association; drop the local context; and
  release the RAN-side context with a `UEContextReleaseCommand` (cause deregister).
- `on_t3522_expiry`'s exhaustion branch now calls the helper (behaviour unchanged — it
  was already this cleanup, now DRY).
- `on_t3555_expiry`'s give-up branch calls the helper instead of clearing the pending
  command — a UE that ignores the whole retransmission run is treated as unreachable and
  implicitly deregistered.

## Why implicit deregistration

TS 24.501 §5.4.4.3 requires only that the network *abort* the procedure on T3555
exhaustion; it doesn't mandate deregistration. But a UE that ignores the initial command
plus four retransmissions (~30 s at the default interval) is effectively unreachable,
and leaving it half-updated (its network-side config changed but unconfirmed) is worse
than forcing a clean re-attach. This mirrors the codebase's existing T3522-exhaustion
behaviour, so both retransmission procedures now escalate consistently. It's a
deliberate design choice, not a bare-spec requirement.

## Boundaries / notes

- Applies to **every** tracked Configuration Update Command (SDM-NSSAI from design/109,
  AM-policy/service-area from design/110) — they share `pending_config_update` and thus
  the same give-up path.
- The release cause is **deregister** (as T3522 uses), signalling an implicit
  deregistration to the RAN.
- A stale expiry after the context is gone is a no-op (the `ues` lookup misses).

## Verification

- `cargo test --workspace --exclude bdd` — green (**202** tests). Updated:
  - nf-amf `config_update_retransmits_then_deregisters` (renamed from
    `…_then_gives_up`) — after the retransmission run, the next expiry returns a
    `UEContextReleaseCommand` and drops the local context (was: empty + pending cleared).
  - nf-amf `t3522_retransmits_then_aborts` — unchanged and still green, guarding the
    extracted `implicit_deregister` helper.
- `cargo clippy --workspace --exclude bdd` — no new warnings (parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). No
  Configuration Update runs to exhaustion under `@sim` (skipped, `FREE_RAN_UE_BIN`
  unset).

## Known limitations / next steps

- **No grace before escalation** — exhaustion escalates immediately to deregistration;
  a real deployment might first mark the UE unreachable and page before deregistering.
- The give-up is unconditional — even a purely informational nudge that goes unacked
  deregisters the UE. A future refinement could escalate only for commands that changed
  UE-affecting state (allowed NSSAI, re-registration request).
