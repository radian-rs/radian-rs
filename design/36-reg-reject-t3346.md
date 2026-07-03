# T3346 Back-off on the Registration Reject — Implementation Notes

> Built 2026-07-03 on branch `feat/reg-reject-t3346`. Closes the back-off gap
> carried since [34](34-registration-reject-62.md): a #62-rejected UE was free to
> re-register immediately (and be re-rejected in a loop). The reject now carries
> the **T3346 value** IE (IEI 0x5F) — the 5GMM analogue of the session-level
> T3396 from [30](30-reject-backoff-timer.md).

## What was built

- **`nas::GprsTimer2`** (TS 24.008 §10.5.7.4) — one octet, 3-bit unit + 5-bit
  multiple, but with the *coarser* Timer-2 unit table (2s / 1min / decihour vs
  Timer 3's seven units). `from_secs` picks the finest fitting unit, rounds up,
  clamps at 31 decihours; `deactivated()` for the 0b111 encoding.
- **`nas::registration_reject`** gains an optional back-off, emitted as the
  T3346 IE; `parse_registration_reject` now also yields the T3346 octet.
- **AMF** — the #62 reject carries `REG_REJECT_BACKOFF_SECS = 600` (encodes as
  10 × 1 min): re-registering can't succeed until the slice subscription
  changes, so hold the UE off.

## Verification

- `cargo test --workspace --exclude bdd` — green. New:
  - `nas::gprs_timer2_unit_selection` — unit choice/round-up/clamp (60s = 30×2s,
    63s → 2×1min, 1h = 10×decihour, overflow clamps) and the deactivated form.
  - The reject round trip asserts the exact T3346 octet (`0b001_01010` for
    600s); the AMF #62 integration test asserts the UE-side decode sees it.
- **BDD, 5 scenarios / 25 steps green** — live path untouched.

## Known limitations / next steps

- **The core doesn't enforce T3346** — same posture as T3396 (design/30): a
  non-compliant UE re-registering inside the timer is simply re-processed (and
  re-rejected). Tracking back-off state per SUPI would be future hardening.
- Deregistration procedure (reusing the design/35 release machinery), per-slice
  NSSAI rejection causes, UE-AMBR from am-data, and AMF-side SMF selection
  remain open.
