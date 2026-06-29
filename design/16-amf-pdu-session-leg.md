# AMF Leg of the PDU-Session Call Flow + SMF NRF Registration

> Built 2026-06-29 on branch `feat/amf-pdu-session-leg`. The UE→AMF→SMF half of the call flow, and the SMF's discovery registration. Also folds in the PR #16 security review.

Slice 15 made the SMF drive the UPF (`Nsmf → N4`). This slice connects the **AMF** to
that: a UE's NAS-SM **UL NAS Transport** now makes the AMF **discover the SMF** (NRF)
and call **`CreateSMContext`**. With the SMF now **registered** with the NRF, the
signaling chain runs UE → AMF → SMF → UPF.

## What was built

- **`nas`** — 5GMM **UL NAS Transport** build (`ul_nas_transport_sm`) and parse
  (`sm_container_from_ul_nas_transport` → `(pdu_session_id, N1 SM container)`).
- **`nf-amf`** — `pdu_session::AmfSmf`: discover the SMF via the NRF and POST
  `Nsmf_PDUSession_CreateSMContext`. The N2 `UplinkNASTransport` dispatch gains a
  `UlNasTransport` arm: extract the UE's SUPI + PDU session id, relay to the SMF.
- **`nf-smf`** — registers its `nsmf-pdusession` service with the NRF on startup
  (`RADIANT_SMF_NRF`), so the AMF can discover it.
- **PR #16 security review fixes** (`nf-smf`):
  - PFCP `transact` now **correlates responses by sequence number**, discarding stale
    datagrams (no state drift).
  - **SUPI is masked** in logs (PII): `imsi-99970***`.
  - The downlink sink (gNB F-TEID) is **validated** (reject zero TEID / unspecified /
    broadcast / multicast) — defence-in-depth atop the (deferred) SBI authorization.

## The flow now

```
UE → AMF   N2 UplinkNASTransport { NAS-SM: PDU Session Establishment Request }
AMF        discover SMF (NRF) → Nsmf_PDUSession_CreateSMContext
SMF → UPF  N4 Session Establishment → UPF N3 F-TEID
   ── still to do: AMF → gNB N2 PDU Session Resource Setup (UPF N3 F-TEID + N1 SM),
      then gNB F-TEID → Nsmf UpdateSMContext (slice 14/15 already handle the N4 side) ──
```

## Verification

- `cargo test` — green (38 tests workspace-wide). New:
  - `nas::ul_nas_transport_round_trips` — build → decode → `(psi, container)`.
  - `nf-smf::smf_registers_and_is_discoverable` — register, then NRF `discover("SMF")`.
  - `nf-amf::amf_discovers_smf_and_creates_sm_context` — the AMF discovers a (mock)
    SMF via the NRF and drives CreateSMContext over h2c.
  - `nf-smf::rejects_bogus_gnb_targets`, `masks_supi_for_logging` (review fixes).
  - The full registration flow (`full_registration_completes`) still passes through the
    re-threaded N2 handlers.

## Known limitations / next steps

- **SM container relayed opaquely** — the AMF doesn't parse the 5GSM message, and
  bodies are simplified JSON (no TS 29.502 multipart with binary N1/N2 SM containers).
- **DNN hard-coded** `"internet"`; no S-NSSAI handling.
- **No N2 PDU Session Resource Setup yet** — the AMF doesn't send the downlink to the
  gNB (with the UPF N3 F-TEID + the N1 SM Accept), nor learn the real gNB F-TEID to
  drive `UpdateSMContext`. That's the next slice and completes the round trip.
- **AMF test uses a mock SMF** (contract-level); the real SMF `Nsmf → N4` is covered by
  slice 15's test. A unified end-to-end would want the Nsmf service in a shared crate.
- **SBI still unauthenticated** (OAuth2/TLS deferred, TS 33.501).
