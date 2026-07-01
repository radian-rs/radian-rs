# N6 forwarding — user packets finally move

> Built 2026-06-30 on branch `feat/n6-tun-forwarding`. The UPF's data-network interface and
> the forwarding plane that bridges N3 (GTP-U) ↔ N6 (the DN), turning a *signaled* PDU
> session into an actual forwarding datapath.

Through slice 17 the whole PDU session was **signaled** — both tunnel ends established —
but no user packet moved: the UPF only logged `"→ N6, TODO"`. This slice makes the UPF
forward. It gains the two datapath decisions it was missing, and a real Linux **TUN**
device on N6 to carry packets to and from the data network.

## The missing fact: the UE's IP

To route a **downlink** packet (arriving from the DN, destined to a UE) the UPF must map
the packet's destination IP back to the session that owns it. That means the UPF has to
learn each session's **UE IP** — which the **SMF allocates**. So this slice threads UE-IP
allocation through the control plane:

- **SMF** allocates a UE IPv4 from a `/16` pool (`10.45.0.2+`) per `CreateSMContext`,
  returns it as `ueIpv4Addr`, and carries it into the N4 **Session Establishment** inside a
  **downlink PDR's** PDI (a UE IP Address IE).
- **UPF** (`pfcp`) reads that IE and records the UE IP on the session, exposing two lookups:
  `route_downlink(dst) → (gnb_teid, gnb_ip)` and `ue_ip_for_teid(teid) → ue_ip`.

## What was built

- **`pfcp`** — `Session` gains `ue_ip`; establishment provisions an uplink **and** a
  downlink PDR (the latter carrying the UE IP); `route_downlink` / `ue_ip_for_teid` accessors.
- **`n6`** (new crate) — the forwarding plane as pure functions over the session table:
  - `ipv4_addrs(pkt) → (src, dst)` — minimal bare-IPv4 header inspection.
  - `uplink(state, teid, inner)` — known TEID? source == the UE's IP (**anti-spoof**)? →
    `ToN6` / `UnknownTeid` / `Spoofed`.
  - `downlink(state, pkt)` — route by destination UE IP → `gtpu::encap` toward the gNB →
    `ToN3 { gnb_ip, gpdu }` / `NoRoute` / `NotIpv4`.
  - `tun::N6Tun` — a real Linux TUN (via the `tun` crate, tokio-async), the privileged edge.
- **`nf-upf`** — wires it together: an N3 uplink loop (decap → `n6::uplink` → TUN) and an
  N6 downlink loop (TUN read → `n6::downlink` → N3 `send_to` the gNB). The TUN is opened
  best-effort; without `CAP_NET_ADMIN` the UPF logs and keeps N3/N4 serving with
  forwarding disabled.

## The datapath (now real)

```
uplink:    gNB → UPF:N3   G-PDU(teid) ─ decap → n6::uplink (anti-spoof) → TUN → DN
downlink:  DN  → UPF:TUN  IP(dst=UE) ─ n6::downlink (route by UE IP) → encap → UPF:N3 → gNB
```

## Why a TUN can't be in the headline test

Opening a TUN needs `CAP_NET_ADMIN` (root / `setcap`), unavailable in CI. So the split is
deliberate: **all forwarding *decisions* are pure functions, fully unit-tested**; the TUN
(`n6::tun`) is a thin I/O adapter exercised only at runtime with privileges. To verify the
live path manually: run `nf-upf` as root, and packets to `10.45.0.0/16` route via `n6upf0`.

## Verification

- `cargo test` — green (45 tests workspace-wide, +5). New / changed:
  - **`n6`** (5) — `ipv4_addrs` parse/reject; `downlink` routes-to-gNB / NoRoute / NotIpv4;
    `uplink` forwards-matching-source / UnknownTeid / Spoofed.
  - **`pfcp`** — establishment records the UE IP; `route_downlink` resolves only after the
    modification and only for the owning UE IP.
  - **`nf-upf`** — a UE-sourced G-PDU decaps and forwards to N6; a DN packet to the UE IP
    encaps to the gNB TEID (both through the real N4 establishment path).
  - **`nf-smf`** — `CreateSMContext` allocates `10.45.0.2`; end-to-end the UPF can
    `route_downlink` by that UE IP after the modification.
- `cargo clippy` — clean.

## Known limitations / next steps

- **UE IP not delivered over NAS** — the SMF returns `ueIpv4Addr`, but the AMF still sends a
  stubbed N1 PDU Session Establishment Accept; a real NAS-SM slice would put the address (and
  DNN/QoS) in the accept so the UE configures its stack.
- **One pool, IPv4 only, no release** — a flat `/16`, no IP reuse on session teardown, no
  IPv6/dual-stack; UE-IP allocation should be DNN/slice-scoped and coordinated with the UPF.
- **Anti-spoof is L3 best-effort** — a non-IPv4 inner packet is forwarded as-is (IPv4
  sessions shouldn't carry one; the TUN drops what it can't route).
- **No live end-to-end test** — the forwarding *logic* is covered, but a privileged
  netns/BDD test (or a gNB/UE simulator) is needed to prove packets traverse a real TUN.
  That simulator is now the natural next investment.
