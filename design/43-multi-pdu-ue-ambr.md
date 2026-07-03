# Multiple PDU Sessions per UE + UE-AMBR to the RAN — Implementation Notes

> Built 2026-07-03 on branch `feat/multi-pdu-ambr`. Two long-standing
> single-session simplifications retired: the AMF tracked one PDU session per UE,
> and the subscribed UE-AMBR from am-data was never signalled to the gNB.

## Multiple PDU sessions per UE

- **`UeContext.sm_ref: Option<String>` → `sm_refs: HashMap<u8, String>`** — the
  SM-context ref keyed by PDU session id. Each `UlNasTransport` PDU-session
  request inserts its `(psi → sm_ref)`; the SMF already allocated a distinct
  UE-IP / N4 session / UECM registration per session ([41](41-smf-uecm.md)), so
  the AMF's single ref was the only thing forcing one-per-UE.
- **N2 setup response** now looks up the SM ref **by the response's PDU session
  id** (`sm_refs.get(&psi)`) to drive the right session's UpdateSMContext.
- **Deregistration** (UE- and network-initiated) releases **every** session —
  `std::mem::take(&mut ctx.sm_refs)` then release each — so no N4 session leaks.

## UE-AMBR to the RAN (via NGAP)

- **am-data fetch extended** — `fetch_am_data` (was `fetch_subscribed_nssai`)
  returns both the default NSSAI (fail-open contract unchanged) and the
  `subscribedUeAmbr`, parsed to bits/sec by `bitrate_to_bps` ("2 Gbps" →
  2 000 000 000). The UE-AMBR is stored in `UeContext.ue_ambr` at registration.
- **NGAP** — `pdu_session_resource_setup_request` gains the
  **UEAggregateMaximumBitRate** IE (TS 38.413 §9.3.1.58, DL/UL `BitRate` =
  bits/sec), so the gNB enforces the UE's non-GBR rate cap. When am-data carried
  no UE-AMBR (fail-open), the AMF sends `DEFAULT_UE_AMBR_BPS` (1 Gbps each way).

## Verification

- `cargo test --workspace --exclude bdd` — green (26 suites). New/updated:
  - `ngap::pdu_session_resource_setup_request_roundtrips` — the UE-AMBR IE
    survives the APER round trip.
  - `nf-amf::bitrate_to_bps_parsing`; the deregistration test now sets up **two**
    sessions (psi 5 + 6) and asserts **both** are released at the SMF.
- **Live loopback + BDD** (`@sim`): the free-ran-ue gNB accepts the
  `PDUSessionResourceSetupRequest` **with the UE-AMBR IE** — the UE logs "PDU
  session establishment complete" and the datapath ping round-trips (5 scenarios
  / 25 steps green), proving the IE is wire-compatible with a free5GC-based gNB.

## Known limitations / next steps

- **UE-AMBR only in the PDU setup** — sent per PDU Session Resource Setup, not in
  an InitialContextSetupRequest (this core has no ICS message; the setup-request
  IE is the pragmatic carrier).
- **No live multi-session exercise** — free-ran-ue establishes one session, so
  the multi-session paths are unit-pinned; the infra supports N sessions.
- **QoS still one match-all flow** — per-flow 5QI/GBR beyond the session AMBR and
  UE-AMBR is future; AMF-side SMF selection and SBI security hardening remain
  open.
