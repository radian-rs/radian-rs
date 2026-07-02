# N4: PFCP (SMF to UPF)

**N4** is the interface between the SMF (control) and the UPF (user plane). It
carries **PFCP** (Packet Forwarding Control Protocol, TS 29.244) — binary TLV over
UDP (**:8805**), not ASN.1. Over N4 the SMF tells the UPF how to treat packets:
which tunnels to match, where to forward, what headers to add.

The `pfcp` crate wraps `rs-pfcp` and provides SMF-side request builders plus a
stateful UPF-side handler.

## Association and heartbeat

Before any session, the SMF and UPF establish a node-level **association**:

```
SMF → UPF   Association Setup Request
UPF → SMF   Association Setup Response (accepted)
```

`nf-smf` does this on startup and logs `PFCP association established with UPF`.
Heartbeats keep the association live.

## Session establishment

For each PDU session the SMF sends a **Session Establishment Request** that
provisions the forwarding rules and carries the SMF-allocated **UE IP**:

- an **uplink PDR** (Packet Detection Rule) matching packets from the access side,
  with a placeholder F-TEID that the UPF replaces;
- a **downlink PDR** matching packets destined to the UE's IP (a **UE IP Address**
  IE), whose FAR the later modification points at the gNB;
- the corresponding **FARs** (Forwarding Action Rules).

The UPF **allocates the real N3 F-TEID** and a UP-SEID, records the session
(N3 TEID, UE IP), and answers with a **Created PDR** carrying the allocated
F-TEID and its UP F-SEID:

```
SMF → UPF   Session Establishment Request (UE IP 10.45.0.2)
UPF → SMF   Session Establishment Response (N3 F-TEID, UP F-SEID)
```

The SMF reads the allocated F-TEID out of the response and hands it up to the AMF
for the [N2 setup](ch-03-00-pdu-session.md).

## Session modification (the downlink)

Once the gNB returns its own N3 F-TEID, the SMF sends a **Session Modification
Request** with an **Update FAR** carrying an **Outer Header Creation** (GTP-U/IPv4)
that points at the gNB's F-TEID. This is what completes the downlink path — the
UPF now knows where to send packets headed for the UE.

```
SMF → UPF   Session Modification Request (Outer Header Creation → gNB F-TEID)
UPF → SMF   Session Modification Response (accepted)
```

## UPF session state

The UPF (`pfcp::UpfState`) keeps a table of sessions, each holding its uplink N3
TEID, the UE IP, and (once installed) the gNB downlink target. Two lookups drive
the [datapath](ch-03-03-n6-forwarding.md):

- `route_downlink(ue_ip)` — the gNB target for a packet destined to that UE IP;
- `ue_ip_for_teid(teid)` — the UE IP that owns an uplink TEID (for the
  anti-spoofing check).

## Addressing on one host

GTP-U uses port 2152 on both ends, so a UPF and a gNB on the same host would
collide. The UPF's bind and advertised addresses are configurable so they can sit
on distinct addresses:

```
RADIAN_UPF_BIND=127.0.0.1      # bind N3/N4 here (default 0.0.0.0)
RADIAN_UPF_N3_ADDR=10.0.1.1    # advertise this as the N3 F-TEID address
```

## Security

PFCP is **unauthenticated** (TS 29.244) and relies on a trusted/isolated N4
network, or IPsec per TS 33.501 — which radian-rs does not yet implement. The
UPF's N4 handler logs and continues on a malformed datagram rather than failing
open.
