# N1 SM PDU Session Establishment Accept — the UE completes

> Built 2026-06-30 on branch `feat/n1-sm-accept`. The real N1 SM Accept that lets the
> **free-ran-ue** UE finish its PDU session — parsing its IP/DNN/S-NSSAI and reaching the
> operational "UE started" state against the live radian core.

Slice 20 completed the PDU-session *signaling* (SMF/N4/N2/gNB tunnel), but the AMF still
handed the UE a **4-byte stub** N1 container — the UE crashed decoding it. This slice builds
the real **PDU Session Establishment Accept** and wraps it correctly, so the UE completes.

## What the UE requires (learned by driving it)

free-ran-ue's UE decodes the DL NAS Transport, then reads — **unconditionally** — the PDU
address, authorized QoS rules, S-NSSAI, and DNN from the 5GSM accept. Missing any of those
panics the UE. So the accept must carry all of them, byte-compatible with `free5gc/nas`.

## What was built

- **`nas::pdu_session_establishment_accept(psi, pti, ue_ip, dnn)`** — the 5GSM accept as raw
  N1 SM bytes, **hand-encoded to the exact TS 24.501 layout** (sidestepping any codec-vs-codec
  disagreement with free5gc): SSC-mode-1 + IPv4, a default match-all QoS rule (LV-E), a
  Session-AMBR, the **PDU address** (the UE's IPv4), the **S-NSSAI**, and the **DNN**
  (RFC 1035 labels). `pti` echoes the request's procedure transaction id.
- **`nas::dl_nas_transport_sm(psi, n1_container)`** — the 5GMM DL NAS Transport carrying it
  (payload container type = N1 SM), plus `sm_container_from_dl_nas_transport` for tests.
- **`nf-amf`** — the `UlNasTransport` arm now: takes the UE IP from the SMF's CreateSMContext
  response (`SmContextCreated.ue_ip`, parsed from `ueIpv4Addr`), echoes the request PTI, builds
  the accept, **NAS-protects** a DL NAS Transport carrying it, and places that as the N2
  PDU Session Resource Setup NAS-PDU. The gNB relays it to the UE.

## Proven live (end to end)

```
UE  → AMF  PDU Session Establishment Request
AMF → SMF  CreateSMContext (UE IP 10.45.0.x, N3 F-TEID)
AMF → gNB  N2 Setup + protected DL NAS Transport(PDU Session Establishment Accept)
gNB → UE   relays the accept
UE:        "PDU session UE IP: 10.45.0.x"  "DNN: internet"  "SNSSAI sst 1 sd 123"
UE:        "PDU session establishment complete" → "UE started"
```

The UE parsed its assigned IP, DNN, and slice, connected to the RAN data plane, and reached the
operational state — a full registration **and** PDU session against the greenfield core.

## Verification

- `cargo test` — green (49 workspace-wide, +1: `nas::dl_nas_transport_carries_pdu_session_accept`).
  `cargo clippy` clean.
- **Live interop:** free-ran-ue UE completes PDU session establishment (IP/DNN/S-NSSAI) and
  reaches "UE started".

## Known limitations / next steps

- **No user packet yet.** The signaling is complete and the UE is operational, but an actual
  end-to-end **ping** needs the UPF's N6 TUN and the UE's TUN both up (privileged) over the
  live N3 path — the last datapath piece. This run used `ignoreSetupTunnel` on the UE and a
  UPF without its TUN.
- **Accept values are fixed** — one match-all QoS rule, a placeholder Session-AMBR, and a
  hard-coded S-NSSAI (SST 1 / SD 010203). Deriving QoS/AMBR/S-NSSAI from policy (PCF) and the
  request is future.
- **The SMF doesn't build the N1** — the AMF constructs the accept (using the SMF's UE IP);
  architecturally TS 29.502 has the SMF produce the N1 SM container. Moving it there is future.
