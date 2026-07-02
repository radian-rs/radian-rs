# Reject Back-off Timer (T3396) — Implementation Notes

> Built 2026-07-02 on branch `feat/reject-backoff-timer`. Closes the first "next
> step" of [29](29-pdu-session-reject.md): a subscription-refused UE is now told
> how long to back off instead of being free to retry immediately.

## What was built

- **`nas::GprsTimer3`** (TS 24.008 §10.5.7.4a) — the one-octet 3-bit-unit +
  5-bit-multiple encoding. `from_secs` picks the *finest* unit whose multiple
  fits (2s → 30s → 1min → 10min → 1h → 10h → 320h), rounding up so the UE backs
  off at least the requested duration; out-of-range clamps to 31 × 320h;
  `deactivated()` for the 0b111 encoding.
- **`nas::pdu_session_establishment_reject`** gains an optional back-off — the
  T3396 **back-off timer value** IE (IEI 0x37, TLV) after the cause octet.
- **AMF policy** — cause #27 (subscription refusal) carries a
  `REJECT_BACKOFF_SECS = 600` back-off, since retrying cannot succeed until
  provisioning changes; cause #31 (transient/upstream failure) carries none, so
  the UE may retry once the network recovers.

## Verification

- `cargo test --workspace --exclude bdd` — green. New: `gprs_timer3_unit_selection`
  (unit choice + round-up + clamp, e.g. 63s → 3 × 30s, 24h → 24 × 1h) and exact
  wire bytes for the reject with the IE (`… 0xC3 27 0x37 0x01 0b011_11110` for a
  60s test value).
- **BDD, 5 scenarios / 25 steps green** (with `FREE_RAN_UE_BIN`) — the negative
  unsubscribed-DNN scenario now carries the back-off IE on the wire (free-ran-ue
  doesn't implement reject handling, so behaviour is unchanged: no `ueTun0`).

## Known limitations / next steps

- **The core doesn't enforce the back-off** — a non-compliant UE that retries
  inside T3396 is re-processed (and re-rejected); tracking per-UE back-off state
  in the AMF is future hardening.
- Requested S-NSSAI and per-subscriber default DNN remain open (design/28).
