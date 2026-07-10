# BDD Scripted GUTI Re-registration + Identity Request (D3/D4)

> Built 2026-07-09 on branch `feat/bdd-scripted-guti`. Fifth BDD slice of the design/116
> plan: two more `@scripted` registration scenarios exercising the GUTI-based re-entry paths
> (design/60) — D3 (GUTI re-registration → re-authenticate) and D4 (unknown GUTI → Identity
> Request → SUCI → register). Both are genuinely scripted-only: free-ran-ue cannot
> re-register. D4 also surfaced and fixed a real AMF gap.

## What was built

### `bdd` (`ScriptedUe` + steps)

- **`ScriptedUe::guti_registration_request(tmsi)`** — a Registration Request identifying by
  5G-GUTI (sent plain, ngKSI 7); **`identity_response()`** — an Identity Response carrying
  the UE's SUCI.
- **Scenario D3**: a fully registered UE re-registers with the 5G-GUTI the AMF assigned it;
  the AMF resolves it via its GUTI directory and **re-authenticates** (fresh 5G-AKA), and
  the flow completes with a new Initial Context Setup + accept.
- **Scenario D4**: a UE presents an **unknown** 5G-GUTI (`0xDEADBEEF`); the AMF's directory
  misses, so it sends an **Identity Request**, the UE answers with its **SUCI**, and the AMF
  resumes at authentication → registration completes.

Both reuse the 116a auth/security/ICS steps once the identity is resolved (the AMF keys UE
contexts by AMF-UE-NGAP-ID, so reusing the RAN-UE-NGAP-ID across the two registrations in one
scenario is harmless). The UE's `complete_security` builds a fresh NAS security context each
time, so the re-registration's NAS COUNTs — and its resume K_gNB cross-check — line up.

### `nf-amf` — fix a gap D4 found

The **Identity-Request path never assigned the registration area.** `on_initial_ue`'s
identified branch (direct SUCI or GUTI hit) sets `ctx.registration_area` via
`registration_area_for(...)`, but the unknown-GUTI branch defers to an Identity Request and
the `IdentityResponse` handler resolved the SUPI **without** setting the area — so the
Registration Accept for any UE that went through an Identity Request carried **no 5GS TAI
list**, leaving paging nothing to scope to. The fix assigns the registration area in the
`IdentityResponse` handler once the SUPI is known, mirroring the identified branch. This is a
real correctness fix the scripted tier caught (the D4 accept-grants assertion failed on an
empty registration area before it).

## Verification

- **`cargo test -p bdd` — 2 features / 12 scenarios / 116 steps GREEN** (deterministic
  across reruns): D3 and D4 drive their flows against the live core; the rest of the suite
  is unaffected.
- `cargo test -p nf-amf` — green (51; the registration-area fix broke no existing test).
- `cargo test --workspace --exclude bdd` — green (30 test binaries).
- `cargo clippy -p nf-amf -p bdd --tests` — no net-new warnings (23 sites before == after).

## Boundaries / next

- D3 re-registers a UE that is still CM-CONNECTED (the RAN context from the first
  registration lingers, harmlessly, under a reused RAN-UE-NGAP-ID); a real gNB would use a
  fresh id, but the AMF's correlation is by AMF-UE-NGAP-ID so the test is faithful to the
  control-plane exchange.
- `scripted_registration` now has D1/D3/D4/D5/D6/D7/D8 + the PDU-session (116c) and CM-IDLE
  (116d) scenarios. Remaining registration gaps: **D9** (registration area = gNB TA ∪ UE
  TAI, needs a UE arriving from a TAC the gNB doesn't serve) and **D10** (unsubscribed DNN →
  5GSM reject #27 + T3396). Then paging + T3513 and the datapath echo.
