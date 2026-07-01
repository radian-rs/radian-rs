# N6: Forwarding to the Data Network

**N6** is the UPF's link to the **data network** (the DN — the internet, or a
private network). It is where a *signalled* PDU session becomes a *forwarding*
one: user packets actually leave the mobile network and come back. In radiant-rs
the N6 interface is a real Linux **TUN** device, and the forwarding logic that
bridges N3 (GTP-U) and N6 lives in the `n6` crate.

## The two decisions

The UPF makes two forwarding decisions, both pure functions over the
[PFCP session table](ch-03-01-n4-pfcp.md):

**Uplink** — a G-PDU arrived on N3, was decapsulated, and its inner packet is
headed out to the DN:

- if the TEID belongs to no session → drop (`UnknownTeid`);
- if the inner packet's source is **not** the UE's assigned IP → drop as spoofed
  (`Spoofed`) — a basic anti-spoofing guard;
- otherwise write the inner packet to N6 (`ToN6`).

**Downlink** — an IP packet arrived from the DN on N6:

- look up the session that owns the **destination IP** (`route_downlink`);
- encapsulate the packet toward that session's gNB N3 tunnel (`ToN3`);
- if no session owns the destination, or it is not IPv4 → drop.

```rust
pub fn uplink(state: &UpfState, teid: u32, inner: &[u8]) -> Uplink
pub fn downlink(state: &UpfState, pkt: &[u8]) -> Downlink
```

## The TUN device

The concrete N6 device is a Linux TUN (`n6upf0`, `10.45.0.1/16`), opened via the
`tun` crate. The UPF's own address sits **inside the UE IP pool** so the kernel
routes the pool to `n6upf0` and return traffic arrives here.

Opening a TUN needs **`CAP_NET_ADMIN`**, so the UPF is run under `sudo` (or with
the capability granted). Without it the UPF degrades gracefully: N3 and N4 keep
serving, but user-plane forwarding is disabled and logged. This privileged edge
is deliberately thin — the forwarding *decisions* above are plain, testable
functions; only the device I/O needs privilege.

## The path a packet takes

```
uplink:    gNB → UPF:N3   G-PDU(teid) ─decap→ n6::uplink (anti-spoof) → n6upf0 → DN
downlink:  DN  → UPF:N6   IP(dst=UE) ─n6::downlink (route by UE IP)→ encap → N3 → gNB
```

A `ping` from the UE to the DN exercises the whole loop: the UE's packet is
GTP-U-encapsulated by the gNB, decapsulated by the UPF, written to `n6upf0`,
answered by the kernel, routed back by UE IP, re-encapsulated, and returned to the
UE.

## Verification

The end-to-end ping (see [free-ran-ue interop](ch-04-00-free-ran-ue-interop.md))
is answered, and the UPF logs one forward each way per packet:

```
N3→N6 uplink forwarded   teid=1          bytes=84
N6→N3 downlink forwarded gnb_ip=10.0.1.2 bytes=84
```

The same round trip is automated in the [datapath BDD test](ch-04-01-bdd-tests.md).

## Limitations

IPv4 only; one session per UE; the anti-spoofing check is L3 best-effort (a
non-IPv4 inner packet is forwarded as-is on the assumption the DN device drops
what it cannot route). QER-based rate limiting, buffering, and IPv6 are future
work.
