# Requested-NSSAI Intersection + Rejected NSSAI — Implementation Notes

> Built 2026-07-03 on branch `feat/nssai-intersection`. Closes the first "next
> step" of [32](32-allowed-nssai.md): the allowed NSSAI is no longer simply the
> subscribed defaults — the UE's **requested NSSAI** (Registration Request IEI
> **0x2F**) is intersected with the subscription, and what doesn't intersect
> comes back in the **rejected NSSAI** IE (IEI **0x11**).

## What was built

- **`nas`**:
  - `requested_nssai_from_registration_request` — extracts the 0x2F IE (same
    §9.11.3.37 NSSAI value encoding as the allowed NSSAI).
  - Rejected-NSSAI plumbing (TS 24.501 §9.11.3.46): `rejected_nssai_value` /
    `parse_rejected_nssai_value` — each entry is one octet
    `(contents-length << 4) | cause` + SST (+ SD); `nssai_cause::
    NOT_AVAILABLE_IN_PLMN` (0) is the cause this stack emits.
  - `registration_accept` gains a `rejected_nssai` parameter (IE emitted when
    non-empty) and `rejected_nssai_from_registration_accept` for the UE side.
- **AMF**:
  - `registration_identity` also yields the requested NSSAI; it is stored in
    `UeContext.requested_nssai` when the UE is identified.
  - `compute_nssai(requested, subscribed)` — pure: requested empty → grant the
    subscribed defaults, reject nothing; otherwise allowed = requested ∩
    subscribed, rejected = requested \ subscribed.
  - `on_security_mode_complete` runs the intersection against the am-data fetch
    (renamed `fetch_subscribed_nssai`) and sends both IEs. **`UeContext.
    allowed_nssai` is now `Some(allowed)` even when the intersection is empty**
    — a UE that requested only unsubscribed slices gets every subsequent
    slice-bearing PDU request rejected locally (cause #70). Fail-open on fetch
    failure is unchanged (no IEs, SMF gate applies).

## Verification

- `cargo test --workspace --exclude bdd` — green. New:
  - `nas::requested_nssai_extraction_from_registration_request` — oxirush-built
    Registration Request with/without the IE, through encode/decode.
  - `nas::rejected_nssai_value_roundtrips` — head-octet layout, truncation-safe.
  - Registration Accept round trip now covers both IEs (and their absence);
    the `nf-amf` full-registration test asserts allowed + rejected arrive
    through NAS security.
  - `nf-amf::nssai_intersection` — the three `compute_nssai` branches (no
    request, partial overlap, no overlap).
- **BDD, 5 scenarios / 25 steps green**; loopback AMF log:
  `Registration Accept (allowed NSSAI: [(1, Some([1, 2, 3]))], rejected: [])`.
- **Honest coverage note:** free-ran-ue passes `nil` for the requested NSSAI
  (`ue/ue.go` → `getUeRegistrationRequest(..., nil, ...)`), so the **live** e2e
  exercises the no-request→defaults branch only; the intersection and rejection
  branches are pinned by the unit tests above, and the rejected IE never
  appears on the live wire.

## Known limitations / next steps

- **No Registration Reject on empty allowed NSSAI** — a UE whose requested
  slices are all rejected still registers (with an empty allowed NSSAI); per
  TS 24.501 the network should reject with 5GMM cause #62 *no network slices
  available*. Future slice.
- **Single rejection cause** — everything is *not available in the current
  PLMN*; per-slice causes (registration area, NSSAA) unmodeled.
- **UE-AMBR from am-data** and **AMF-side SMF selection** remain open
  (design/32, design/27).
