# N3: GTP-U

**N3** carries user data between the gNB and the UPF. The encapsulation is
**GTP-U** (GPRS Tunnelling Protocol, user plane, TS 29.281) — a small binary
header over UDP (**:2152**). The same protocol is used on N9 (UPF↔UPF). It is not
ASN.1.

The `gtpu` crate is a minimal, purpose-built codec.

## The G-PDU

A user packet on N3 is wrapped in a **G-PDU**: an 8-byte GTP-U header (version,
message type `0xFF`, length, and the **TEID** that identifies the tunnel) followed
by the inner IP packet.

```
encap(teid, inner) → [ GTP-U header | inner IP packet ]
decap(g_pdu)       → (teid, inner)
```

The TEID is the whole point: it tells the receiver which session (and therefore
which UE) a packet belongs to. The [N4](ch-03-01-n4-pfcp.md) exchange is what
assigns the TEIDs — the UPF allocates the uplink TEID, the gNB the downlink one.

## Path management

GTP-U also carries **Echo** messages for path management. The `gtpu` crate builds
and parses Echo Request/Response (the response carries a Recovery IE), and the
UPF answers Echo Requests on N3 so a gNB can probe liveness.

```rust
pub enum N3Message<'a> {
    GPdu { teid: u32, payload: &'a [u8] },
    EchoRequest { sequence: u16 },
    EchoResponse { sequence: u16 },
    Other(u8),
}
```

## In the UPF

The UPF serves N3 as one of its concurrent UDP loops. On a received datagram:

- an **Echo Request** is answered directly;
- a **G-PDU** is decapsulated to `(teid, inner)` and handed to the
  [N6 forwarding plane](ch-03-03-n6-forwarding.md) — which checks the TEID belongs
  to a known session before doing anything with the packet.

Extension headers and N-PDU numbers are parsed around but not yet interpreted;
the codec handles the mandatory header plus the optional sequence field.

## Verification

When the UPF forwards a real packet, its N3 activity shows in the log alongside
the [N6](ch-03-03-n6-forwarding.md) side:

```
N3→N6 uplink forwarded   teid=1          bytes=84
N6→N3 downlink forwarded gnb_ip=10.0.1.2 bytes=84
```
