# SMF — Nsmf_PDUSession driving the N4 datapath

> Built 2026-06-29 on branch `feat/smf-pdu-session`. The SMF becomes a real NF: an SBI service that orchestrates the UPF over PFCP.

The PFCP "SMF-side" builders (slices 09/15) had no NF behind them — only tests called
them. This slice makes **`nf-smf`** a real NF: it serves **`Nsmf_PDUSession`** (the AMF
calls it) and acts as a **PFCP client** to the UPF, tying the SBI control plane to the
N4 datapath. It's the first leg of the PDU-session call flow.

## What was built

- **`nf-smf`** — SBI server (`:8002`) + PFCP client (one connected N4 socket,
  transactions serialized by a mutex):
  - on startup, **PFCP Association** with the UPF (`RADIAN_SMF_UPF_N4`, default
    `127.0.0.1:8805`).
  - **`CreateSMContext`** → N4 **Session Establishment** → returns the UPF-allocated
    **N3 F-TEID** (which the AMF will put in the N2 SM info for the gNB) + a
    `smContextRef`.
  - **`UpdateSMContext`** → N4 **Session Modification** installing the gNB's downlink
    F-TEID (Outer Header Creation, slice 14).
- **`pfcp`** — SMF-side response parsers: `parse_session_establishment_response`
  (UP-SEID + the Created PDR's N3 F-TEID/addr) and `response_accepted` (Cause = success).

## The flow this is part of

```
AMF → SMF  CreateSMContext  ──►  SMF → UPF  N4 Session Establishment
                               ◄──  UPF N3 F-TEID (→ N2 SM info → gNB)
   ... N2 PDU Session Resource Setup; gNB returns its F-TEID ...
AMF → SMF  UpdateSMContext   ──►  SMF → UPF  N4 Session Modification (gNB F-TEID)
                                  → uplink + downlink tunnels established
```

## Verification

- `cargo test` — green (33 tests workspace-wide). New:
  - `pdu_session_create_then_update_drives_n4` — an in-process UPF (N4 UDP loop over a
    shared `UpfState`), the SMF as PFCP client + SBI server, driven over **real HTTP
    (h2c) + real PFCP (UDP)**: CreateSMContext returns the UPF's N3 TEID and the UPF
    tracks the session; UpdateSMContext installs the gNB downlink target
    (`downlink_for(up_seid)` is set on the UPF).

## Known limitations / next steps

- **Simplified SBI bodies** — JSON with the essentials, not TS 29.502 multipart with
  binary **N1/N2 SM containers**. Those arrive with the NAS-SM + N2-SM-info slices.
- **UPF address is config**, not NRF-based UPF selection; **the SMF isn't registered
  with the NRF**, so the AMF can't discover it yet — that's the next leg.
- **The AMF leg is missing** — UL NAS Transport (a NAS-SM PDU Session Establishment
  Request) → AMF selects the SMF → CreateSMContext; then the N2 **PDU Session Resource
  Setup** (NGAP) to learn the *real* gNB F-TEID → UpdateSMContext. Today the gNB F-TEID
  is supplied to UpdateSMContext directly.
- **No PFCP retransmission / T1 timers**, single UPF, transactions serialized.
