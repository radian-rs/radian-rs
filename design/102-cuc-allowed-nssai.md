# Carry the Allowed NSSAI in the Configuration Update Command

> Built 2026-07-04 on branch `feat/cuc-allowed-nssai`. Design
> [101](101-sdm-change-push-to-ue.md) pushed a Nudm_SDM change to the UE with a
> **generic** Configuration Update Command — a nudge to re-read. This delivers the
> new allowed slice set **inline**: the Configuration Update Command now carries the
> **Allowed NSSAI** IE (TS 24.501 §9.11.3.37) when the subscribed NSSAI changes.

## What was built

### `nas`

- `configuration_update_command_with_nssai(allowed)` — a Configuration Update
  Command (TS 24.501 §8.2.19) carrying the Allowed NSSAI IE (IEI 0x15, reusing
  `nssai_value`); empty `allowed` degrades to the plain command.
- `allowed_nssai_from_configuration_update_command` — the UE-side parser (mirrors
  `allowed_nssai_from_registration_accept`).

### `nf-amf`

- `on_sdm_data_change`: when the **allowed NSSAI changed**, the pushed Configuration
  Update Command now uses `configuration_update_command_with_nssai(&allowed)` so the
  UE gets the new list; a UE-AMBR-only change still sends the plain command.

## Boundaries / notes

- **Delivery, not enforcement.** The UE receives its new allowed NSSAI, but a
  *narrowed* allowed NSSAI (a slice removed) doesn't yet release the affected PDU
  sessions or trigger a re-registration — that impact handling is a follow-up.
- **No Configuration Update Complete tracking** — the UE's ack to the command isn't
  awaited (as elsewhere in the stack).
- The registration-time Configuration Update Command (design/69) is unchanged (the
  plain command); only the Nudm_SDM-change push carries the NSSAI.

## Verification

- `cargo test --workspace --exclude bdd` — green (**194** tests). Updated:
  - nas `configuration_update_command_round_trips` — a plain command carries no
    allowed NSSAI; a command built with `[(1, sd), (2, —)]` round-trips to that
    slice set via `allowed_nssai_from_configuration_update_command`.
  - nf-amf `sdm_data_change_pushes_to_ran_and_ue` — the UE decodes the Configuration
    Update Command and its Allowed NSSAI matches the changed set (both on the
    combined UE-AMBR+NSSAI change and a subsequent NSSAI-only change, the second
    verified against the advanced DL NAS COUNT).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the registration-time command
  is unchanged and the `@sim` triggers no Nudm_SDM change, so registration +
  datapath are unaffected.

## Known limitations / next steps

- **Narrowed-NSSAI impact** — on a slice removal, release PDU sessions on the lost
  slice and/or trigger re-registration.
- **Configuration Update Complete** tracking + a retransmission timer.
- **Configuration update indication** (registration-requested bit) when the change
  warrants the UE re-registering.
