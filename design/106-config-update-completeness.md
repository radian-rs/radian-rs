# Configuration Update Command Completeness

> Built 2026-07-04 on branch `feat/config-update-completeness`. Two small tails of
> the Nudm_SDM arc (designs 99–105): the Configuration Update Command carried a
> changed allowed NSSAI (design/102) but never asked the UE to **re-register** on a
> narrowing, and the AMF never recognised the UE's **Configuration Update Complete**.
> This adds both.

## What was built

### `nas`

- `configuration_update_command_with_nssai(allowed, registration_requested)` — gained
  a flag that sets the **Configuration update indication** IE (IEI 0xD0, TS 24.501
  §9.11.3.18) with the *registration requested* bit, telling the UE to re-register.
- `configuration_update_registration_requested(msg)` — reads that bit back (UE side /
  tests).
- `configuration_update_complete()` — the UE's acknowledgement message (message type
  0x55, §8.2.20).

### `nf-amf`

- `on_sdm_data_change` computes `narrowed` — whether a previously-allowed slice is no
  longer in the new allowed NSSAI — and, on a narrowing, sets *registration
  requested* in the Configuration Update Command (so the UE re-registers and
  renegotiates its slices, complementing the design/103 session release). A widening
  (a slice added, none removed) does not.
- `dispatch_uplink_nas` recognises the UE's **Configuration Update Complete**
  (logs the acknowledgement, no downlink) instead of letting it fall through as an
  unhandled uplink NAS message.

## Boundaries / notes

- **Narrowing = a previously-allowed slice removed** (including a slice whose SD
  changed — the exact `(SST, SD)` no longer matches). A widening or an unchanged set
  doesn't request re-registration.
- **No retransmission timer / acknowledgement-requested tracking** — the Complete is
  recognised, not awaited; a UE that never Completes isn't retried (a follow-up).
- The registration-time Configuration Update Command (design/69) is unchanged (the
  plain command, no re-registration request).

## Verification

- `cargo test --workspace --exclude bdd` — green (**198** tests). New/updated:
  - nas `configuration_update_command_round_trips` — the registration-requested bit
    round-trips (set / unset), and the Configuration Update Complete round-trips.
  - nf-amf `sdm_data_change_pushes_to_ran_and_ue` — a narrowing Configuration Update
    Command requests re-registration; a widening does not.
  - nf-amf `config_update_complete_is_recognised` — the UE's Configuration Update
    Complete is acknowledged (no downlink) via `dispatch_uplink_nas`.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the registration-time command
  is unchanged; the `@sim` triggers no Nudm_SDM change.

## Known limitations / next steps

- **Configuration Update Complete retransmission** — track outstanding commands (the
  acknowledgement-requested bit) and retransmit if the UE doesn't Complete.
- **Partial-UpdateNotify semantics** (the remaining Nudm_SDM tail) — distinguish
  "field omitted, keep" from "field removed" in a PCF UpdateNotify, rather than
  treating each as a full replacement.
