# 5G-AKA Authentication (AUSF + UDM) — Implementation Notes

> Built 2026-06-29 on branch `feat/aka-auth`. The first NF↔NF flow that joins crypto + SBI.

Stands up **UE authentication** the network-internal way: the AMF/SEAF asks the
**AUSF**, which asks the **UDM/ARPF** for an authentication vector, and 5G-AKA runs
to completion (RES* ⇄ XRES* → K_SEAF). Built on validated MILENAGE + TS 33.501 crypto.

## What was built

- **`aka` crate** — network-side 5G-AKA crypto: `generate_5g_he_av` (RAND, AUTN,
  XRES*, K_AUSF), `hxres_star`, `kseaf`, and `ue_compute_res_star` (UE side, verifies
  AUTN). Built on [`milenage`](https://crates.io/crates/milenage) (f1–f5, TS 35.205/6)
  and [`oxirush-security`](https://crates.io/crates/oxirush-security) (KDFs, TS 33.501).
- **UDM** (`sbi_core::nudm`) — `Nudm_UEAuthentication_Get` (TS 29.503): an in-memory
  subscriber DB (K/OPc/AMF + SQN) generating the 5G HE AV.
- **AUSF** (`sbi_core::nausf`) — `Nausf_UEAuthentication` (TS 29.509): `authenticate`
  (fetch AV from UDM, derive HXRES*, return RAND/AUTN/HXRES* + ctx) and `confirm`
  (compare UE RES* to XRES* → SUPI + K_SEAF).
- **NF binaries** — `nf-udm` runs the UDM with a demo subscriber (TS 35.208 test key);
  `nf-ausf` runs the AUSF pointed at the UDM.

## The flow (TS 33.501 §6.1.3.2)

```
AMF/SEAF ──POST nausf-auth/v1/ue-authentications {supi, snn}──▶ AUSF
                                AUSF ──POST nudm-ueau/.../generate-auth-data──▶ UDM
                                AUSF ◀── 5G HE AV {rand, autn, xresStar, kausf} ──
AMF/SEAF ◀── {rand, autn, hxresStar, ctxId} ──  (5G SE AV)
   │ (sends RAND/AUTN to UE over N2/NAS — the join slice; here the test plays the UE)
   ▼
AMF/SEAF ──PUT .../{ctx}/5g-aka-confirmation {resStar}──▶ AUSF
AMF/SEAF ◀── {authResult: AUTHENTICATION_SUCCESS, supi, kseaf} ──
```

## Crypto, grounded in test vectors

- `milenage_test_set_1` validates f1–f5 against **3GPP TS 35.208 Test Set 1**
  (MAC-A, RES, CK, IK, AK), confirming correct usage of the `milenage` crate.
- `five_g_aka_roundtrip_succeeds` proves the AKA logic end-to-end (RES* == XRES*,
  HRES* == HXRES*); `ue_rejects_tampered_autn` proves AUTN MAC verification.
- K_AUSF uses FC = 0x6A (Free5GC / UERANSIM convention).

## Verification

- `cargo test -p aka -p sbi-core` — green:
  - `aka`: 3 crypto tests (above).
  - `nausf::five_g_aka_over_sbi_succeeds` — the **full flow over real h2c**: spin
    UDM + AUSF, AMF authenticates, UE computes RES*, confirm → SUCCESS + K_SEAF.
  - `nausf::wrong_res_star_fails` — a bad RES* → AUTHENTICATION_FAILURE.
- Runtime smoke test of the `nf-ausf` + `nf-udm` binaries: `POST` authenticate
  returns a real AV (AUSF calls UDM over HTTP/2); `PUT` confirm with a bogus RES* →
  `AUTHENTICATION_FAILURE` (http/2 200).

## Known limitations / next steps

- **SUCI not deconcealed** — `supiOrSuci` is treated as the SUPI; resolving a SUCI to
  a SUPI (home-network private key) is a separate UDM concern.
- **AUSF → UDM is a fixed URL** — NRF-based discovery of the UDM is a small follow-up
  (the NRF and discovery already exist from `design/04`).
- **No SQN resync** — the UE's AUTS / synchronisation-failure path isn't handled; the
  SQN is a simple in-memory counter.
- **In-memory state** — subscriber DB and AUSF auth contexts are non-persistent.
- **Not yet joined to N2** — the AMF doesn't yet send the NAS Authentication Request
  to a real UE. **Next slice:** on registration, the AMF discovers the AUSF via NRF,
  calls `Nausf`, sends the NAS Authentication Request over N2, receives RES* from the
  UE, and confirms — the first end-to-end *authenticated* registration joining N2 + SBI.
