# Periodic Registration Updating

> Built 2026-07-04 on branch `feat/periodic-registration`. Design
> [76](76-mobility-registration-update.md) handled *mobility* registration
> updating and left a **correctness hole**: a periodic registration (type 011)
> fell through the CM-IDLE-return classifier and was dropped as an unrecognised
> NAS message. So a CM-IDLE UE that dutifully re-registered when T3512 expired was
> **still evicted** by the design [66](66-t3512-implicit-dereg.md) implicit-
> deregistration sweep — the exact opposite of what periodic registration is for.
> This accepts it (TS 24.501 §5.5.1.3.2): lightweight, no re-authentication, and
> the retained context is refreshed so the UE stays alive.

## What was built

### `nas`

- `registration_request_of_type(reg_type, mcc, mnc, tmsi)` — the shared GUTI
  Registration Request builder (factored out of the design/76 mobility builder).
- `registration_request_periodic(mcc, mnc, tmsi)` — type *periodic registration
  updating* (UE side / tests). `registration_request_mobility` now delegates to
  the shared builder.

### `nf-amf` — the CM-IDLE-return handler generalizes again

The design/76 classifier split Service Request vs mobility update; it now also
recognises **periodic** (`is_periodic`), and mobility ∪ periodic form
`is_registration_update`. The shared registration-update path (context restore,
fresh K_gNB, Registration Accept, **no** user-plane reactivation) applies to
both; the differences are exactly two:

- **Registration area**: mobility re-assigns it (`registration_area_for`);
  **periodic keeps it unchanged** (the UE hasn't moved); Service Request still
  extends it if it came back from outside.
- **Accept label**: `…(RegistrationAccept — periodic)` vs `— mobility update`.

Because the return removes the context from `RETAINED` (clearing `retained_at`)
and restores it CM-CONNECTED, the periodic registration **refreshes the
implicit-deregistration deadline** — the UE re-idles later with a fresh
`retained_at`, and the design/66 sweep no longer evicts it.

## Boundaries / notes

- **No auto AN-release after the accept.** A real network releases the connection
  and the UE returns to CM-IDLE; here the UE (or a subsequent AN release) drives
  that, as with the other return paths — free-ran-ue can't drive it anyway.
- The security context continues (no re-auth, no key change beyond the normal
  idle-resume K_gNB re-derivation, design/78) — exactly the point of "lightweight".
- No T3512-value renegotiation in the periodic accept (the same `T3512_SECS`).

## Verification

- `cargo test --workspace --exclude bdd` — green (**174** tests). New:
  - nas `mobility_registration_request_roundtrips` (extended) — the periodic type
    round-trips with its GUTI TMSI.
  - nf-amf `periodic_registration_update_refreshes_without_reauth` — a retained
    CM-IDLE UE (area `[000001, 000002]`, `retained_at` set, one session) checks in
    with a protected periodic Registration Request from the same TAC: one downlink
    (the ICS carrying the periodic Registration Accept), **no** UP reactivation,
    the restored context is CM-CONNECTED with `retained_at` cleared, the area
    **unchanged**, the session kept, and the UE verifies the accept (same area,
    kept NSSAI); `RETAINED` no longer holds it (eviction deadline reset via the
    connected cycle).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green.**
- Not sim-drivable — free-ran-ue can't go CM-IDLE (design/64/65 precedent);
  integration-tested end to end.

## Known limitations / next steps

- **Explicit AN release after the periodic accept** (return the UE to CM-IDLE
  from the core side).
- **GUTI reallocation** on a registration update (the standing design/76
  follow-up).
- **Uplink Data Status** — a periodic/mobility update requesting immediate UP for
  listed sessions.
