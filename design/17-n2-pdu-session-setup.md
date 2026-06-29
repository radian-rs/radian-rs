# N2 PDU Session Resource Setup — closing the round trip

> Built 2026-06-29 on branch `feat/n2-pdu-session-setup`. The AMF↔gNB leg that learns the gNB F-TEID and completes both tunnel ends.

Slice 16 ran UE → AMF → SMF (CreateSMContext, N4 establishment). This slice adds the
**AMF → gNB** leg: the AMF sends a **PDU Session Resource Setup Request** carrying the
UPF's N3 F-TEID, the gNB replies with **its own N3 F-TEID**, and the AMF feeds that to
**UpdateSMContext** (slice 15's N4 modification). The PDU-session **signaling round trip**
is now complete end to end.

## The hard part: N2 SM information transfer-IEs

The "N2 SM information" is carried as **separately-APER-encoded sub-PDUs** embedded as
octet strings inside the NGAP message — `PDUSessionResourceSetupRequestTransfer`
(UL N3 F-TEID + PDU type + QoS) and `...ResponseTransfer` (the gNB's DL N3 F-TEID). The
`ngap` crate now encodes/decodes these (via `asn1-codecs` + `bitvec` for
`TransportLayerAddress`), with the F-TEID as an NGAP `GTPTunnel`.

## What was built

- **`ngap`** —
  - `pdu_session_resource_setup_request(amf_ue_id, ran_ue_id, psi, qfi, upf_teid, upf_addr, nas)`
    — the AMF→gNB message + request transfer (UPF F-TEID, PDU type IPv4, one 5QI-9 flow).
  - `pdu_session_resource_setup_response(...)` — for a gNB simulator / tests.
  - `gnb_fteid_from_setup_response(&NGAP_PDU) → (psi, gNB TEID, gNB IPv4)`.
- **`nf-amf`** — `AmfSmf::create_sm_context` now returns the UPF N3 F-TEID; `update_sm_context`
  drives the SMF's N4 modification. The `UlNasTransport` arm sends the N2 setup (returning
  it as the downlink); a new `SuccessfulOutcome` dispatch arm handles the setup response →
  extracts the gNB F-TEID → `UpdateSMContext`. The SM context ref is tracked per UE.

## The complete chain (signaling)

```
UE  → AMF   UL NAS Transport (NAS-SM)
AMF → SMF   CreateSMContext → N4 Establishment → UPF UL N3 F-TEID
AMF → gNB   PDU Session Resource Setup Request (UPF F-TEID + N1 SM)
gNB → AMF   PDU Session Resource Setup Response (gNB DL N3 F-TEID)
AMF → SMF   UpdateSMContext → N4 Modification (gNB F-TEID, Outer Header Creation)
            ⇒ uplink + downlink tunnels established
```

## Verification

- `cargo test` — green (40 tests workspace-wide). New:
  - `ngap::pdu_session_resource_setup_request_roundtrips` — build → APER encode → decode → equal.
  - `ngap::setup_response_yields_gnb_fteid` — build a gNB response → decode →
    `gnb_fteid_from_setup_response` returns `(psi, teid, addr)`.
  - `nf-amf::amf_discovers_smf_and_creates_sm_context` now also exercises `update_sm_context`
    (mock SMF: create + modify).
  - `full_registration_completes` still passes (the new dispatch arm is additive).

## Known limitations / next steps

- **N1 SM Accept is stubbed** — the SMF doesn't return a PDU Session Establishment Accept,
  so the AMF sends a placeholder N1 container to the UE. Modeling the SMF's N1 (and TS 29.502
  multipart) is future.
- **Single QoS flow / single PDU session per UE**, DNN hard-coded, PDU type IPv4 only.
- **No single end-to-end test** of UE→gNB→AMF→SMF→UPF — it needs a gNB simulator driving N2;
  each leg is tested in isolation (NGAP round-trips, AMF↔SMF over HTTP, SMF↔UPF over PFCP).
- **Datapath still not forwarding** — only GTP-U encap/decap is proven; **N6 (a TUN device)**
  is the last piece before user packets actually move.
