# SCTP COMM_LOST / SHUTDOWN → gNB Teardown (G35)

> Built 2026-08-09 on branch `open5gs`. From [138](138-open5gs-gap-survey.md) §2.1:
> an SCTP **COMM_LOST/SHUTDOWN** notification was only *logged*, so a vanished gNB's
> association task ran on forever, leaking its UE contexts and its `GNB_LINKS` entry
> ("radian logs the notification and does nothing"; open5gs tears down on
> `amf-sm.c` COMM_LOST).
>
> (The NAS retransmission-timer half that originally shared this slice — G7,
> T3550/T3560/T3570 + Service Reject — was landed independently on `main` in
> `design/142-amf-nas-retransmission.md`, so it is dropped here to avoid duplicating
> it. This doc is the G35 half only.)

## What was built (`nf-amf/src/main.rs`)

The gNB association receive loop (`serve_gnb`) now inspects SCTP **notifications**
(RFC 6458 §6.1) instead of only logging them:

- A **terminal** `AssociationChange` — **COMM_LOST** (the gNB crashed / the link
  failed), `SHUTDOWN_COMPLETE`, `CANT_START_ASSOC` — or a peer-initiated **Shutdown**
  breaks the loop; the gNB is gone. `COMM_UP` / `RESTART` are non-terminal and keep
  the association serving (logged).
- Breaking runs the association teardown, which was also hardened:
  - the UE contexts (`ues`) are dropped, which **releases each UE's CBL admission
    slot** (RAII) and AM-policy handle — so a crashed gNB can't leak AMF memory or
    wedge the CBL admission gate;
  - the stale **`GNB_LINKS` entry is now removed** (swept by `tx.is_closed()` once the
    receiver is dropped) — pre-G35 a dead gNB left a link the paging path kept trying
    (the security audit's LOW `GNB_LINKS`-leak finding);
  - the UE directory is pruned (as before), so a later subscription withdrawal for one
    of the gNB's UEs answers 404 instead of queueing on a dead channel.

## Boundaries / notes

- **CM-CONNECTED UEs are forgotten on a gNB crash** rather than retained for
  reconnection — a reasonable simplification (the UEs lost their RAN link and will
  re-register; their UECM record self-heals when they do). Purging UECM/SDM at the
  UDM on teardown, or retaining contexts across a gNB restart, is a possible
  refinement.
- No behavior change on the graceful paths already handled (an empty-payload DATA is
  still "association closed"; a `sctp_recv` error still breaks) — this adds the
  notification path that fell through before.

## Verification

- `cargo test --workspace --exclude bdd` — green; `cargo clippy -p nf-amf` — clean.
- **BDD 45/45 (501 steps) green** — the gNB-shutdown scenarios exercise the teardown
  path (the association ends and its UEs are released) with no regression.

## Known limitations / next steps

- UECM/SDM purge on an SCTP teardown; retaining CM-CONNECTED UEs across a gNB restart
  (open5gs keeps the UE contexts and re-associates).
