# SUCI→SUPI deconcealment + capability echo — live-UE registration

> Built 2026-06-30 on branch `feat/live-ue-suci-deconceal`. The two AMF fixes that let a
> real free5GC-based UE (the **free-ran-ue** simulator) complete registration end to end.

Slices 2–7 built a full registration that passed with radian-rs's *own* in-process test UE.
Pointing a real external simulator ([free-ran-ue](https://github.com/free-ran-ue/free-ran-ue))
at the AMF surfaced two gaps that the self-test never exercised. Both are fixed here; the
live UE now reaches **REGISTERED**.

## Gap 1 — the SUCI was never deconcealed

The AMF turned the UE's SUCI into a canonical *string* (`suci-0-999-70-…-<msin>`) and used
**that** as the UDM lookup key. Subscribers are provisioned under their **SUPI**
(`imsi-999700000000001`), so the live UE's authentication failed at the UDM (surfacing as an
AUSF `500`). The self-test masked this because it asserted the SUCI string form directly.

**Fix:** `nas::suci_to_supi(&Suci)` deconceals the **null protection scheme** (TS 33.501) —
the scheme output is the MSIN in BCD (low nibble first, `0xF` filler dropped), yielding
`imsi-<MCC><MNC><MSIN>`. ECIES schemes (profiles A/B) need the home-network private key and
fall back to the canonical string (inspectable, won't resolve) until implemented. The AMF now
identifies the UE by the deconcealed SUPI.

## Gap 2 — the replayed UE security capability was hardcoded

The Security Mode Command must **replay the UE's own advertised** security capabilities so the
UE can detect a bidding-down attack (TS 24.501 §8.2.25). The AMF hardcoded `0xE0,0xE0`
(EA0-2/IA0-2); the live UE advertises just `0x20,0x20` (NEA2/NIA2), so it would reject the SMC.

**Fix:** the AMF extracts the UE's `ue_security_capability` from the RegistrationRequest
(`[ea_byte, ia_byte]`), stores it on the UE context, and replays it verbatim in the SMC
(falling back to the AMF default only if the UE sent none).

## The live flow (proven against free-ran-ue)

```
gNB → AMF  InitialUEMessage        → identified imsi-999700000000001 (deconcealed)
AMF → UE   AuthenticationRequest   → 5G-AKA (UDM AV, RES* confirmed)  [Nausf/Nudm]
AMF → UE   SecurityModeCommand     → SecurityModeComplete (replayed caps accepted)
AMF → UE   RegistrationAccept      → RegistrationComplete → REGISTERED
```

NGAP (free5gc-ngap APER ↔ oxirush-ngap) and NAS (free5gc-nas ↔ oxirush-nas) are wire-compatible
across NG Setup, InitialUEMessage, and the full DL/UL NAS transport exchange.

## Verification

- `cargo test` — green (47 workspace-wide, +2). New: `nas::null_scheme_suci_deconceals_to_supi`,
  `nas::ecies_suci_falls_back_to_canonical_string`. `full_registration_completes` still passes
  (the self-test UE uses null-scheme SUCI + NEA2/NIA2, so it exercises both fixes).
- **Live interop:** free-ran-ue UE `imsi-999700000000001` registers against the radian core
  (NRF+UDM+AUSF+AMF) over loopback SCTP/GTP-U. See the interop harness notes in memory.

## Known limitations / next steps

- **Null scheme only.** ECIES SUCI deconcealment (profiles A/B, home-network key) is future.
- **No SQN resync.** The UE's configured SQN must be below the network's next SQN (the store
  starts at 1); a real AUTS/resync path is future.
- **AUSF/UDM don't self-register with the NRF** — the interop run registers the AUSF manually.
  NF self-registration (like the SMF already does) is a small follow-up.
- **PDU session over the live RAN is untested** — after REGISTERED the UE proceeds to PDU
  session establishment, which needs SMF+UPF and the privileged N3/N6 data plane (next milestone).
