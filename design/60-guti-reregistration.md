# 5G-GUTI Re-registration + Identity Response

> Built 2026-07-03 on branch `feat/guti-reregistration`. First slice of the
> registration-lifecycle audit: the 5G-GUTI the Registration Accept assigned was
> **cosmetic** (never stored, never resolvable), and the Identity Request the AMF
> sent for an unidentifiable UE was a **dead end** (the Identity Response had no
> handler). Both are now real: a returning UE re-registers with its GUTI
> (TS 24.501 §5.5.1.2 — the SUCI is only for first contact), and an unknown
> identity is resolved over the Identity Request ⇄ Response round trip.

## What was built

### GUTI directory + re-registration (nf-amf)

- **`GUTI_DIRECTORY`** (5G-TMSI → SUPI, process-wide like `UE_DIRECTORY`): the
  Registration Accept path records the GUTI it assigns (the TMSI is the
  AMF-UE-NGAP-ID, already globally unique via `NEXT_AMF_UE_ID`); a **fresh GUTI
  supersedes** any earlier one held by the same SUPI.
- `registration_identity` now classifies the mobile identity —
  `Supi` (deconcealed SUCI) / `GutiTmsi` / `Unknown` — and captures the UE
  security capabilities + requested NSSAI **regardless** of which it is.
- `on_initial_ue` resolves a GUTI against the directory: a hit is **Identified**
  and re-authenticated like any first registration (fresh 5G-AKA + NAS security
  — spec-valid and much simpler than security-context reuse); a miss (e.g. an
  AMF restart lost the mapping) falls back to the Identity Request, keeping the
  caps/NSSAI from the original request for the resume.
- **Lifecycle**: the GUTI survives UE-initiated deregistration (the UE keeps it
  in its USIM and registers with it next time) and is dropped on subscription
  withdrawal (both the Deregistration-Accept and T3522-exhaustion exits).

### Identity Response handling (nas + nf-amf)

- nas: `identity_response_suci` / `supi_from_identity_response` (null-scheme
  SUCI encode/deconceal), `registration_request_with_guti` +
  `guti_tmsi_from_registration_request`, and a shared `suci_mobile_identity`
  builder (the encode inverse of `suci_to_supi`).
- The uplink dispatcher gained an **IdentityResponse arm**: valid only in
  `RegState::IdentityRequested`, it deconceals the SUCI, records the UE in
  `UE_DIRECTORY`, and resumes the paused registration at **authentication**
  (the same `amf_auth.begin` leg as a direct identification). The
  deregistration command channel now threads through `on_uplink_nas` →
  `dispatch_uplink_nas` so the arm can register the UE's reachability.

## Boundaries / notes

- **Re-authentication, not context reuse** — a GUTI hit runs full 5G-AKA + a new
  NAS security context. TS 24.501 allows reusing the existing context (integrity-
  protected initial message, ngKSI match); that optimization needs ngKSI
  management and is deferred with algorithm negotiation.
- **No GUTI reallocation mid-registration** — the GUTI changes only when a new
  Registration Accept assigns one; the Configuration Update Command still carries
  none.
- The directory is in-memory: an AMF restart forgets mappings, which is exactly
  the fallback the Identity Request path now covers.
- free-ran-ue always registers with a SUCI, so the new paths are pinned by
  integration tests over real NAS/NGAP encodings (the design/33 precedent), not
  the live sim.

## Verification

- `cargo test --workspace --exclude bdd` — green (**127** tests). New:
  - nas `guti_registration_request_round_trips` (GUTI in, TMSI out, caps intact;
    SUCI requests yield no TMSI) and `identity_response_carries_the_suci`.
  - nf-amf `guti_reregistration_resolves_without_identity_request` — a seeded
    GUTI resolves straight to Identified (caps captured, `UE_DIRECTORY` wired);
    an unknown GUTI yields the Identity Request with caps kept for the resume.
  - nf-amf `identity_response_resumes_registration_at_authentication` — against
    a real NRF/UDR/UDM/AUSF backend: the response advances the UE to
    `Authenticating` with a decodable Authentication Request downlink; a
    response outside `IdentityRequested` is ignored.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live SUCI registration
  path is unchanged.

## Known limitations / next steps

- **SQN resync (AUTS)** — Authentication Failure handling is still absent (the
  next lifecycle slice).
- **Security-context reuse on re-registration** (ngKSI management) + algorithm
  negotiation.
- **Periodic/mobility registration** (T3512, TAI list) and the idle-mode arc
  (Service Request, paging) from the same audit.
