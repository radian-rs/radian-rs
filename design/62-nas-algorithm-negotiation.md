# NAS Algorithm Negotiation

> Built 2026-07-03 on branch `feat/algo-negotiation`. Registration-lifecycle
> audit slice 3. The AMF **hardcoded** 128-NEA2 / 128-NIA2 and selected them
> regardless of the UE's advertised capabilities — a UE that didn't support
> exactly those algorithms could never complete Security Mode. This makes the AMF
> actually **negotiate** (TS 33.501 §6.7.1): pick the strongest algorithm the UE
> and the AMF both support, from an operator preference order.

## What was built (`nf-amf`)

- **Preference lists** — the AMF's supported algorithms in priority order:
  - ciphering `NEA_PRIORITY = [2, 1, 3, 0]` (128-NEA2 ≻ 128-NEA1 ≻ 128-NEA3 ≻ NEA0
    null, last resort);
  - integrity `NIA_PRIORITY = [2, 1, 3]` — **NIA0 (null) is never offered**;
    integrity is mandatory outside unauthenticated emergency, so a UE supporting
    no real integrity algorithm is rejected rather than run unprotected.
- **`ue_supports_algo(cap, id)`** — reads the UE security-capability byte
  (MSB-first: EA0/IA0 is bit `0x80`, EA1 bit `0x40`, … TS 24.501 §9.11.3.54).
- **`select_algo(cap, priority)`** — the first algorithm in the AMF's order that
  the UE also advertises; `None` if there's no common one.
- **`establish_security`** now negotiates `(nea, nia)` from the UE capabilities
  (falling back to the default caps when the Registration Request omitted the IE),
  derives the **algorithm-bound** NAS keys (TS 33.501 Annex A.8 — the key depends
  on the algorithm id), builds the NAS context, and announces the selection in the
  Security Mode Command (which also replays the UE capabilities for its
  bidding-down check). It returns the selected algorithms.

Because the NAS keys are algorithm-bound, the UE derives matching keys from the
algorithms the SMC announces — so a UE and AMF that negotiate NEA1/NIA1 share a
working context, which the old hardcoded path made impossible.

## Boundaries / notes

- **Preference lists are compile-time constants** — a real deployment makes them
  operator config; the values here are the sensible defaults (AES first).
- **ngKSI stays 0** — a fresh key set per AKA run. Proper ngKSI cycling and
  **security-context reuse** (skipping AKA on GUTI re-registration when the UE's
  ngKSI still matches) remain the deferred half of this audit item.
- **Emergency / null integrity** isn't special-cased: NIA0 is simply never
  selected, so an unauthenticated-emergency UE (which the core doesn't support
  yet anyway) would be rejected here.

## Verification

- `cargo test --workspace --exclude bdd` — green (**134** tests). New:
  - `algorithm_negotiation_picks_the_best_common` — NEA2/NIA2 from the default
    caps; NEA1/NIA1 from an NEA1-only UE; NEA0 selectable but NIA0 never; NEA3/NIA3
    below 2 and 1; the bit test.
  - `security_mode_uses_the_negotiated_algorithms` — end to end through real
    NRF/UDR/UDM/AUSF: a UE advertising only 128-NEA1/128-NIA1 gets those selected,
    a UE deriving keys with the **negotiated** algorithms verifies the SMC, and —
    the proof the selection binds the keys — keys derived with the old default
    NEA2/NIA2 **reject** the NEA1 SMC.
- **BDD 2 features / 5 scenarios / 25 steps green** — free-ran-ue advertises
  NEA2/NIA2, which the AMF still negotiates (unchanged behaviour for the common UE).
- **Live (real stack)** — with the sim's UE reconfigured to advertise **only
  128-NEA1 / 128-NIA1**, the full @sim e2e still passes: the UE registers,
  establishes a PDU session, and pings the data network. Before this slice that
  UE could never have completed Security Mode (the AMF forced NEA2/NIA2). Fixture
  reverted to the standard NEA2/NIA2 after the run.

## Known limitations / next steps

- **Security-context reuse / ngKSI management** — the deferred half: reuse an
  existing NAS context on GUTI re-registration (integrity-protected initial
  message, ngKSI match) instead of always re-running AKA.
- **Operator-configurable preference lists** (env / config).
- **Periodic/mobility registration** (T3512, TAI list) and the idle-mode arc
  (Service Request, paging) remain from the audit.
