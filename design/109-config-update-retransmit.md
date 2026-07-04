# Configuration Update Command Retransmission (T3555)

> Built 2026-07-04 on branch `feat/config-update-retransmit`. The open follow-up from
> design/106: the AMF recognised the UE's Configuration Update **Complete** but never
> *awaited* it — a command that requested acknowledgement was sent once and forgotten.
> This tracks the outstanding command and **retransmits it under T3555** (TS 24.501
> §5.4.4.3) until the UE acknowledges or the network gives up.

## What was built

### `nas`

- The Configuration update indication IE gained its **acknowledgement-requested** bit
  (bit 2, §9.11.3.18) alongside registration-requested.
  `configuration_update_command_with_nssai(allowed, registration_requested,
  acknowledgement_requested)` sets each bit independently (the IE is emitted when
  either is set). `configuration_update_acknowledgement_requested(msg)` reads it back.

### `nf-amf`

- `UeContext.pending_config_update: Option<PendingConfigUpdate>` holds the outstanding
  command — the **plaintext** command (re-protected with a fresh NAS COUNT on each
  retransmit) + a transmission count.
- `on_sdm_data_change`: an NSSAI-carrying command now **requests acknowledgement**,
  stores the pending command, and arms **T3555** (`arm_t3555`, `RADIAN_AMF_T3555_SECS`,
  default 6 s). A plain AMBR nudge needs no ack.
- `on_t3555_expiry` (mirrors `on_t3522_expiry`): while transmissions remain
  (`T3555_MAX_SENDS` = 5 = initial + 4), re-protect and resend the command, bump the
  count, re-arm; at the cap, warn and drop the pending state (§5.4.4.3 abort).
- `dispatch_uplink_nas`'s Configuration Update **Complete** arm clears
  `pending_config_update`, so T3555 stops (a pending expiry then no-ops).
- The association loop routes `UeCmd::T3555Expiry` to `on_t3555_expiry`.

## Boundaries / notes

- Only the **NSSAI-carrying** SDM-change command requests acknowledgement (it changes
  the UE's allowed slices, so the UE must confirm — TS 24.501 §5.4.4.1). The
  registration-time command (design/69) and a plain AMBR nudge don't, so they aren't
  tracked or retransmitted.
- **Re-protection uses a fresh NAS COUNT** on each retransmit (matching the T3522
  deregistration-retransmit path) rather than replaying identical ciphertext.
- **Give-up is silent** beyond a warning — the AMF drops the pending command after the
  cap; it doesn't deregister the UE or escalate (the changed config stays applied
  network-side; a compliant UE re-registers if it was asked to).
- Latest-wins: a second SDM change while one command is outstanding replaces the
  pending command (and re-arms), consistent with the single-outstanding-procedure model.

## Verification

- `cargo test --workspace --exclude bdd` — green (**202** tests, +1). New/updated:
  - nas `configuration_update_command_round_trips` — the acknowledgement-requested bit
    round-trips independently of registration-requested (both set, each alone, neither).
  - nf-amf `config_update_retransmits_then_gives_up` — `on_t3555_expiry` retransmits
    the command (the UE decodes each, sees the NSSAI + ack request) up to the cap,
    bumping the count, then abandons it (no downlink, pending cleared); a stale expiry
    is a no-op.
  - nf-amf `config_update_complete_is_recognised` — a Complete clears the outstanding
    command (T3555 stops).
  - nf-amf `sdm_data_change_pushes_to_ran_and_ue` — an NSSAI command requests
    acknowledgement and is tracked (`pending_config_update` set, attempts = 1); moved to
    `#[tokio::test]` (arming spawns the timer).
- `cargo clippy --workspace --exclude bdd` — no new warnings (parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). The
  registration-time command is unchanged; `@sim` (skipped, `FREE_RAN_UE_BIN` unset)
  drives no NSSAI-carrying Configuration Update, so it exercises no ack/retransmission.

## Known limitations / next steps

- **Ack for other commands** — an AM-policy or service-area Configuration Update could
  also request acknowledgement and be retransmitted (currently only the SDM-NSSAI one).
- **Give-up escalation** — a policy for a UE that never acknowledges (e.g. implicit
  deregistration) rather than silently dropping the pending command.
