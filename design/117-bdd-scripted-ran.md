# BDD Scripted gNB/UE — Tier B enablers + first proof (116a)

> Built 2026-07-09 on branch `feat/bdd-scripted-ran`. First implementation slice of the
> design/116 test plan: the `@scripted` harness tier — the test process plays gNB **and**
> UE against the live core using radian's own crates — plus scenario **D1** (full 5G-AKA
> registration) as its proof. No external simulator binary required, so it runs anywhere
> the core builds (sudo + a loopback SCTP stack).

## Why a second tier

The `@sim` feature (free-ran-ue) proves true wire interop but can't be driven into most
states — it won't go CM-IDLE, re-register, or run two gNBs — so ~30 shipped procedures
were only ever unit/integration-tested. Tier B closes that: it scripts the RAN/UE side
from the same crates the core is built on, so it can walk any procedure the AMF supports.

Honest boundary (restated from design/116): Tier B tests radian against **its own
codecs** — a bug symmetric in a builder and its parser is invisible to it. Tier A keeps
the wire-compat role; the two are complementary, and `datapath_e2e` (@sim) is untouched.

## What was built

### `bdd/src/ran.rs` (new)

- **`ScriptedGnb`** — one real SCTP association to the AMF's N2 (`sctp-rs` 0.3, the same
  crate `nf-amf` serves with; NGAP PPID 60). `connect`, `ng_setup(gnb_id, mcc, mnc, tacs)`
  (sends the request, requires the NGSetupResponse), `send`/`recv` (APER via the `ngap`
  crate; `recv` is bounded by a 10s timeout so a silent AMF fails the step, never hangs),
  `recv_downlink_nas` → `(amf_ue_id, raw NAS)`. `downlink_nas()` extracts the pair from a
  DownlinkNASTransport.
- **`ScriptedUe`** — the demo subscriber's USIM (TS 35.208 test key, hard-coded so the bdd
  crate needs no hex dep) and the UE-side key chain. `registration_request()` (plain SUCI),
  `authenticate(auth_req)` (verify AUTN → RES* → K_AUSF → K_SEAF via the new
  `aka::ue_authenticate`), `complete_security(smc)` (read the announced algorithms from the
  integrity-only SMC, derive the algorithm-bound NAS keys, verify the MAC, return the
  protected Security Mode Complete + stash K_AMF/**K_gNB**/`NasSecurityContext`),
  `read_downlink`/`protected_uplink` for the post-security NAS both ways.

### Small public helpers on the shared crates (each unit-tested)

- **`aka::ue_authenticate(sub, rand, autn, mcc, mnc) -> (RES*, K_AUSF)`** — the full USIM
  output of one challenge, so a UE peer holds the same K_AUSF the ARPF derived and can
  continue the chain (verified in `ue_authenticate_matches_the_network_key_chain`).
- **`nas::registration_request_suci(mcc, mnc, msin, ue_sec_cap)`** — the initial plain-SUCI
  Registration Request (UE side; complements the existing GUTI/mobility/periodic builders).
- **`nas::security_mode_selection(msg) -> (nea, nia, replayed_cap)`** — the UE reads the
  SMC's announced algorithms + replayed capability (its bidding-down check input).

### `bdd/src/netns.rs`

- **`spawn_host_env_logged(...)`** — like `spawn_host_env` but captures the NF's
  stdout+stderr to a file, and **`log_contains(path, needle)`** — so a scenario can assert
  on a core-side effect (e.g. the AMF logging `REGISTERED`). `start_core` now spawns every
  NF logged to `/tmp/<tag>_<nf>.log` and also waits on the PCF (:8006) in its readiness gate
  (the AM policy — RFSP / UE-AMBR / servAreaRes — must be up for D1's ICS assertions).

### `nf-amf`

- **`RADIAN_AMF_T3522_SECS`** env (via `t3522_secs()`) — T3522 was the last fixed-const
  timer; the future dereg-retransmission scenario (design/116 G3) shrinks it so a 5-send
  run doesn't take ~30s. Behaviour unchanged when unset.

### `bdd/tests/features/scripted_registration.feature` + steps

Scenario **D1**: clean env → start the core → gNB NG Setup → UE SUCI registration from TAC
000001 → assert the AMF's Authentication Request → answer RES* → assert NEA2/NIA2 SMC →
complete security → assert the InitialContextSetupRequest and, crucially, that its
**Security Key equals the UE's own K_gNB** (the whole K_AUSF→K_SEAF→K_AMF→K_gNB chain meets
here) plus allowed NSSAI = subscribed slice, RFSP 5, UE-AMBR 600/300 Mbps (PCF override),
the servAreaRes Mobility Restriction List, and no inline sessions → the accept (read UE-side)
grants the slice + a GUTI + the registration area + T3512 → gNB confirms + UE completes →
assert the post-registration Configuration Update Command → assert the AMF logged
`REGISTERED`. Ends with the mandated `Scenario: Teardown topology`.

## Verification

- `cargo test -p aka -p nas` — green (aka 7, nas 31; the 3 new UE-side helper tests pass).
- `cargo test --workspace --exclude bdd` — green (30 test binaries, no failures).
- **`cargo test -p bdd` — 2 features / 4 scenarios / 26 steps GREEN**, clean teardown:
  the scripted registration completes the full 5G-AKA against the **live** NRF/UDR/UDM/
  AUSF/PCF/SMF/AMF over real SCTP + SBI, and the pre-existing N6 datapath feature is
  unaffected. (The `@sim` feature stays skipped without `FREE_RAN_UE_BIN`.)
- `cargo clippy -p aka -p nas -p nf-amf -p bdd --tests` — no new warnings (a fresh
  compile shows none citing the new code; nf-amf's 22 are pre-existing).

## Boundaries / next

- One SCTP endpoint plays both gNB and UE (the split is internal to `ran.rs`); no RRC/Uu.
- D1 only — the rest of `scripted_registration` (D2–D10: GUTI/Identity, AUTS resync,
  reject paths, NSSAI intersection) and the idle/handover/lifecycle features are the
  following slices (design/116 phases 116b–e). The `ScriptedGnb`/`ScriptedUe` surface is
  deliberately minimal and grows per slice as procedures demand.
