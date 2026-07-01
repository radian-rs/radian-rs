# Live PDU-session signaling — configurable UPF bind + Configuration Update Command

> Built 2026-06-30 on branch `feat/upf-configurable-bind`. Two fixes that carry the
> **free-ran-ue** simulator from REGISTERED through the **full PDU-session signaling chain**
> against the live radiant core.

Slice 19 got the live UE to REGISTERED. Driving it on to a PDU session surfaced two more
gaps; both are fixed here, and the **entire PDU-session control plane now completes end to
end with a real free5GC gNB** — the only remaining step is the N1 SM *Accept* the UE decodes
(a follow-up).

## Gap 1 — GTP-U port collision on one host

GTP-U uses port 2152 on both ends, so a co-located UPF (`0.0.0.0:2152`) and gNB can't both
bind it. The UPF's N3/N4 bind address and advertised N3 address are now env-configurable
(`RADIANT_UPF_BIND`, `RADIANT_UPF_N3_ADDR`; defaults unchanged: bind `0.0.0.0`, advertise
loopback). For the loopback test the UPF binds `127.0.0.1` and the gNB uses the `127.0.0.2`
alias, so both keep port 2152.

## Gap 2 — the UE waits for a Configuration Update Command

After Registration Complete a compliant UE (matching free5GC AMF behaviour) **blocks waiting
for a NAS Configuration Update Command** before it initiates a PDU session. The AMF sent
nothing, so the UE hung. Added `nas::configuration_update_command()` (minimal — all IEs are
optional, no acknowledgement requested) and the AMF now sends it (protected, via
DownlinkNASTransport) right after Registration Complete.

## What the live run proved

With both fixes, the free-ran-ue UE ran the whole control plane against the radiant core:

```
UE → AMF   UL NAS Transport (PDU Session Establishment Request)
AMF → SMF  CreateSMContext → N4 Session Establishment
           ⇒ UPF allocates N3 F-TEID + UE IP 10.45.0.2  (sessions=1)
AMF → gNB  PDU Session Resource Setup Request (UPF F-TEID + N2 SM info)
gNB → AMF  PDU Session Resource Setup Response (gNB F-TEID 0x1)  ← real gNB accepted our IEs
AMF → SMF  UpdateSMContext → N4 Session Modification (downlink installed)
gNB        set up its N3 GTP-U tunnel (DL/UL TEID 1)
```

This is an independent conformance check of slices 15–18 (Nsmf_PDUSession, PFCP session
establishment/modification, the N2 PDU Session Resource Setup transfer-IEs, UE-IP allocation)
— a real free5GC gNB parsed our N2 SM info, set up its tunnel, and returned a response the AMF
consumed.

## Verification

- `cargo test` — green (48 workspace-wide, +1: `nas::configuration_update_command_round_trips`).
  `full_registration_completes` still passes. `cargo clippy` clean.
- **Live interop:** free-ran-ue completes registration → Configuration Update → PDU session
  signaling (SMF SM context + UPF N4 session + gNB N3 tunnel) against the radiant core.

## Known limitations / next steps

- **N1 SM Accept is still a 4-byte stub.** The UE decodes the DL NAS Transport carrying the
  PDU Session Establishment Accept and crashes on the stub. A real 5GSM **PDU Session
  Establishment Accept** (PDU address = UE IP, authorized QoS rules, session AMBR) wrapped in
  a **DL NAS Transport** is the next slice — it's what lets the UE finish and bring up its TUN.
- **No N6 data forwarding yet in the live run** — the UPF ran without its TUN (no
  `CAP_NET_ADMIN` in that run); an end-to-end ping needs the UPF's N6 TUN + the UE's TUN
  (both privileged) and the real N3 data path.
