# Registration Reject #62 — Implementation Notes

> Built 2026-07-03 on branch `feat/reg-reject-62`. Closes the first "next step" of
> [33](33-nssai-intersection.md): a UE whose requested slices are all unsubscribed
> used to *register anyway* (with an empty allowed NSSAI, every session doomed to
> a #70 reject) — per TS 24.501 §5.5.1.2.8 it must be **refused registration**
> with 5GMM cause **#62 *no network slices available***.

## What was built

- **`nas::registration_reject(cause, rejected_nssai)`** (TS 24.501 §8.2.9) — the
  mandatory 5GMM cause plus, when non-empty, the **rejected NSSAI** (IEI 0x69 in
  this message, same §9.11.3.46 value encoding as the accept's 0x11) so the UE
  learns *which* slices were refused. `nas::mm_cause::NO_NETWORK_SLICES_AVAILABLE`
  (62); `parse_registration_reject` for the UE side.
- **AMF** — in `on_security_mode_complete`, when the subscription was fetched and
  the intersection is empty (only possible when the UE requested slices —
  am-data with no defaults reads as fetch-failure/fail-open), the AMF NAS-protects
  a Registration Reject #62 carrying the rejected NSSAI, sends it down, and
  **releases the UE context**. The fail-open path (UDM unreachable) still accepts.
- `on_security_mode_complete` / `fetch_subscribed_nssai` / `discover_nf` now take
  the NRF base as a parameter (production passes `NRF_BASE`) — which is what
  makes the reject path integration-testable against an ephemeral NRF.

## Verification

- `cargo test --workspace --exclude bdd` — green. New:
  - `nas::registration_reject_roundtrips` — cause + rejected NSSAI (and
    cause-only) through encode/decode.
  - `nf-amf::unsubscribed_slices_reject_registration_with_cause_62` — full
    integration: a secured UE context requesting only slice 9, a real
    NRF + UDR (am-data: slice 1/010203) + UDM chain over h2c; asserts the
    downlink is a Registration Reject, the **UE context is released**, and the
    UE-side unprotect yields cause **62** with rejected NSSAI
    `[((9, None), not-available-in-PLMN)]`.
- **BDD, 5 scenarios / 25 steps green** — the live path is unchanged
  (free-ran-ue requests no NSSAI → defaults branch → accept, per design/33's
  coverage note).

## Known limitations / next steps

- **No NGAP UE Context Release** — the AMF drops its context but doesn't send
  the gNB a UE Context Release Command; the RAN-side UE context lingers until
  the gNB times it out. Future NGAP slice.
- **No T3346/T3502 back-off on the reject** — a rejected UE may re-register
  immediately (and will be re-rejected).
- Per-slice rejection causes, UE-AMBR from am-data, and AMF-side SMF selection
  remain open (design/33, design/32, design/27).
