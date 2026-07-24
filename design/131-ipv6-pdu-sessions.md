# IPv6 & IPv4v6 PDU Sessions — Design

> Research date: 2026-07-23. Branch `feat/131-ipv6-pdu-sessions`.
> Executes the **P1 "IPv6 PDU sessions"** slice of [130-free5gc-functionality-gap.md](130-free5gc-functionality-gap.md).
> Oracle: **free5gc** — but only for NAS/GSM message shape + the session-type negotiation state machine. free5gc's IPv6 *datapath* is a stub (no prefix/IID allocation, no SLAAC/RA — see §2), so radian-rs builds the working parts greenfield and ends up *ahead* of the oracle.
> 3GPP: TS 24.501 §9.11.4.11/§9.11.4.1 (PDU Session Type / PDU Address / PCO), TS 23.501 §5.8.2.2 (IPv6 SLAAC, one /64 per PDU session), RFC 4861/4862 (ND/SLAAC).

## TL;DR

- radian-rs is **IPv4-only end to end**, and worse than "missing IPv6" — it **never reads the requested PDU Session Type** (the SM container is opaque to the AMF, and the SMF request has no `pduSessionType` field), hard-codes IPv4 in the N1 accept (`nas::pdu_session_establishment_accept`), and has **no PCO/DNS path at all**. The datapath core (`crates/n6`) parses a 20-byte IPv4 header directly.
- 3GPP IPv6 is **SLAAC, one /64 per PDU session**: the SMF allocates a /64 + an 8-byte interface identifier, returns the **IID** in the PDU Address IE, and the network sends an **ICMPv6 Router Advertisement** carrying the /64 (A-flag) down the N3 tunnel; the UE forms `prefix::IID`. free5gc implements *none* of the allocation/RA parts.
- **GTP-U needs no change** — the inner packet is opaque (`crates/gtpu` treats payload as raw bytes). The work is concentrated in **NAS** (type IE + IID encoding + PCO), **SMF** (negotiation + /64/IID pool), **AMF** (thread the requested type through), **PFCP/UPF** (v6 PDI + v6 classifier + v6 session table + **the RA injector**), and **N6** (v6 TUN + v6 parser).
- **Decision: build a *real* IPv6/IPv4v6 datapath in four phases — A signalling scaffold (control-plane, no datapath) → B v6 user plane (v6 ping) → C RA/SLAAC (real prefix delivery) → D PCO-DNS + IPv4v6 dual-stack + interop. Model NAS/negotiation on free5gc; implement prefix allocation, IID encoding, v6 PFCP, and the ICMPv6 RA from the 3GPP/RFC specs (free5gc stubs all four). The UPF is the RA injector (it already owns a userspace datapath — a structural advantage over free5gc's gtp5g kernel module).**

Size legend: **S** ≈ days · **M** ≈ 1–2 weeks · **L** ≈ several weeks.

## 1. What 3GPP requires (the SLAAC model)

For an **IPv6** or **IPv4v6** PDU session (TS 23.501 §5.8.2.2, TS 24.501):

1. **Session-type negotiation.** UE requests a PDU Session Type in the Establishment Request. The network intersects it with the DNN/subscription **allowed session types** and its own capability, and returns the **selected** type in the Accept. On a downgrade (e.g. requested IPv4v6, only IPv6 allowed) the Accept carries 5GSM cause **#50 "PDU session type IPv4 only allowed"** / **#51 "…IPv6 only allowed"**.
2. **One /64 prefix per PDU session.** The SMF allocates a unique **/64** and an **8-byte interface identifier (IID)**. Unlike IPv4, the network does *not* hand the UE a full address — it hands the UE the IID and the prefix (via RA), and the UE forms `prefix ‖ IID`.
3. **PDU Address IE encoding** (TS 24.501 §9.11.4.10):
   - IPv4: `type=1`, 4 address bytes (IE len 5).
   - IPv6: `type=2`, **8-byte interface identifier** (IE len 9). *No* full address, *no* prefix in this IE.
   - IPv4v6: `type=3`, **8-byte IID ‖ 4-byte IPv4** (IE len 13).
4. **Router Advertisement / SLAAC.** After the user plane is up, the network sends an **unsolicited ICMPv6 RA** over the N3 GTP-U tunnel carrying the /64 as a Prefix Information option with the **A-flag (autonomous/SLAAC)** set, **M=O=0** (no DHCPv6), and answers **Router Solicitations** with the same RA. The UE runs SLAAC to form its global address. (DNS may be delivered via PCO and/or an RDNSS option in the RA.)
5. **PCO DNS.** The UE may request DNS server addresses via PCO (IPv6 DNS = container **0x0003**); the network returns them in the ePCO of the Accept.

## 2. What free5gc actually does (oracle reality-check)

free5gc is a reference for the **message construction and the negotiation state machine only**. Measured (see the free5gc dig): it has `IsAllowedPDUSessionType` (`smf/internal/context/sm_context.go`) doing proper requested×allowed×capability negotiation with the #50/#51 downgrade causes, and it returns IPv6 DNS in PCO (`gsm_build.go`). But:

- **No IPv6 pool** — `ue_ip_pool.go` is 32-bit (`uint32` math); there is no /64 or IID allocator. `smContext.PDUAddress` is a single `net.IP` from the IPv4 pool.
- **`PDUAddressToNAS` is stubbed for v6** — pure IPv6 sets `addrLen = 0` (empty PDU Address!), IPv4v6 sets len 13 but zero-fills the IID and misplaces the IPv4.
- **No RA/SLAAC/DHCPv6 anywhere** — exhaustive grep across SMF/UPF/AMF for `RouterAdvertisement|icmpv6|slaac|dhcpv6|ndp` is empty. The gtp5g Go binding only emits IPv4 PDI/flow-description attributes.

**Conclusion:** free5gc's own IPv6 sessions don't produce a working v6 datapath. This corrects [130](130-free5gc-functionality-gap.md)'s "free5gc ✅ IPv6" to "free5gc = signalling scaffold only". radian-rs's userspace UPF lets us do the parts free5gc punts on — so this slice makes radian-rs *lead* on IPv6, not merely reach parity.

## 3. What radian-rs has today (measured)

IPv4-only, with two gaps beyond "no v6": the requested PDU Session Type is dropped on the floor, and there is no PCO path. Key sites (full inventory in the change-surface table, §5):

- **NAS** (`crates/nas/src/lib.rs`): accept builder hard-codes `0x11` (SSC1+IPv4) at `:1122` and a fixed IPv4 PDU Address `[0x29,5,0x01, a,b,c,d]` at `:1134-1138`; param is `Ipv4Addr` (`:1111`); reader `ue_ipv4_from_establishment_accept` scans for the v4 layout (`:1098-1106`); request builder carries no type/PCO (`:1092`).
- **SMF** (`nf/nf-smf/src/pdu_session.rs`): IPv4 pool constant `:34`, `alloc_ue_ip -> Ipv4Addr` `:230`; `SmContextCreateData` has **no `pduSessionType`** (`:274`); response field is `ueIpv4Addr` (`:329`).
- **AMF** (`nf/nf-amf/src/main.rs`): builds the N1 accept at `:3313` with an `Ipv4Addr`; **never parses the requested PDU type** from the container; NGAP hard-codes `PDUSessionType::IPV4` (`crates/ngap/src/lib.rs:1937`).
- **PFCP/UPF** (`crates/pfcp/src/lib.rs`): DL PDR matches `UeIpAddress::new(Some(v4), None)` `:822`; `transport_key` guards `pkt[0]>>4 != 4` `:151`; `UpfState`/`Session` are `Ipv4Addr`-typed throughout (`:301-471`, `:596-740`).
- **N6** (`crates/n6/src/lib.rs`): `ipv4_addrs` parses a 20-byte v4 header `:27-35`; `N6Tun::open` takes `Ipv4Addr` (`tun.rs:28`).
- **GTP-U** (`crates/gtpu`): inner packet **opaque — no change needed.**
- **Subscriber data**: `crates/subscriber-db/src/lib.rs:813` and `nf/nf-udr/src/main.rs:140` set `"defaultSessionType": "IPV4"` — the authoritative "session type" today.

## 4. Design decisions

**D1 — SLAAC, one /64 per PDU session.** Follow 3GPP exactly. Configure an operator IPv6 prefix pool (e.g. a `/56`), carve one **/64 per session**; derive an 8-byte **IID** per session (from a per-session counter, EUI-like, never the MAC). The UE's global address is `prefix::IID`. *Rejected:* handing the UE a single /128 (not how 5G IPv6 works — breaks real UE SLAAC stacks).

**D2 — the UPF is the RA injector.** The RA is a user-plane ICMPv6 packet and must go over N3 GTP-U, so the SMF/N1N2 path is wrong for it. The UPF (PSA) already owns a userspace datapath — it builds the ICMPv6 RA and encaps it to the gNB TEID. It (a) sends one **unsolicited RA** as soon as the downlink FAR (gNB TEID) is installed, and (b) answers **Router Solicitations** seen on the uplink. The /64 + IID reach the UPF via the **PFCP UE IP Address IE** (IPv6 prefix) on session establishment/modification. *Rejected:* SMF-crafted RA relayed via N1N2 (RA is not NAS; it's ICMPv6 on the user plane).

**D3 — PDU Address IE carries the IID (v6) / IID‖IPv4 (v4v6).** Fix the NAS builder to emit `type=2` len-9 (IID) and `type=3` len-13 (IID‖v4) per TS 24.501 — the encoding free5gc gets structurally-wrong. The v4 path is unchanged.

**D4 — thread the requested PDU Session Type AMF→SMF.** The AMF already parses the SM container for `psi`/`pti`/`dnn`; extend it to read the requested PDU Session Type IE and pass it as a new `pduSessionType` field on `SmContextCreateData`. The SMF negotiates the **selected** type against the subscriber's `allowedSessionTypes` (new UDR/subscriber-db field) + an SMF capability, returns it (+ any #50/#51 cause) and the allocated address(es); the AMF emits the Accept with the right PDU Address IE. *Rejected:* moving N1-accept construction into the SMF now — larger refactor, out of scope for this slice (tracked separately).

**D5 — dual-stack IPv4v6 = the union of both single-stack paths.** An IPv4v6 session gets *both* a v4 address (existing pool) and a v6 /64+IID; the datapath routes each family independently; the RA covers only the v6 half. Build v6 first (Phase B), then v4v6 falls out (Phase D).

**D6 — DNS via PCO, RDNSS optional.** Return IPv6 DNS in the Accept ePCO (container 0x0003) from a configured per-DNN DNS address; optionally also advertise it as an RDNSS option in the RA (Phase D). Introduces the first PCO code in the stack.

## 5. Change surface by layer

| Layer | File(s) | Change | Phase |
|---|---|---|---|
| NAS type/address | `crates/nas/src/lib.rs:1108-1167` | read+emit PDU Session Type; PDU Address IID (v6 len-9) / IID‖v4 (v4v6 len-13); v6 reader | A |
| NAS PCO | `crates/nas/src/lib.rs` (new) | parse UE PCO DNS request; emit ePCO DNS response | D |
| SMF alloc | `nf/nf-smf/src/pdu_session.rs:34,230-232` | /64 prefix pool + IID allocator alongside the v4 pool | A |
| SMF negotiate | `nf/nf-smf/src/pdu_session.rs:274-341` | `pduSessionType` in request; negotiate selected type + #50/#51; v6 fields in response | A |
| AMF thread-through | `nf/nf-amf/src/main.rs:3204-3322`, `pdu_session.rs:22,47` | parse requested type from container; pass to SMF; build Accept w/ correct PDU Address | A |
| NGAP | `crates/ngap/src/lib.rs:1937` | set N2 `PDUSessionType` from the selected type | A |
| Subscriber | `crates/subscriber-db/src/lib.rs:813`, `nf/nf-udr/src/main.rs:140` | `allowedSessionTypes` incl. `IPV6`/`IPV4V6` | A |
| PFCP PDI | `crates/pfcp/src/lib.rs:785-887` (`:822`) | v6 UE IP / prefix in PDI; carry prefix to UPF | B |
| UPF classifier | `crates/pfcp/src/lib.rs:151-166` | v6 branch in `transport_key` (proto@6, addrs@8/24, ext-hdr walk) | B |
| UPF session table | `crates/pfcp/src/lib.rs:301-740` | v6/dual `UpfState`/`Session` keys (route/buffer/flush) | B |
| N6 datapath | `crates/n6/src/lib.rs:27-104`, `tun.rs:28` | `ipv6_addrs` parser; v6 TUN address; v6 route/spoof/downlink | B |
| **RA injector** | `nf/nf-upf/src/main.rs`, `crates/n6` (new) | build ICMPv6 RA (Prefix Info, A-flag); inject on DL-up; answer RS | C |
| GTP-U | `crates/gtpu/*` | **none** (inner opaque) | — |
| Config/env | `nf/nf-smf/src/main.rs`, `nf/nf-upf/src/main.rs` | v6 prefix pool, N6 v6 addr, per-DNN DNS | A/B |
| BDD | `bdd/src/{datapath,ran,netns}.rs` | ICMPv6 echo builder; v6 SLAAC scripted UE; v6 netns | B/C |

## 6. Phased plan (slices)

Each phase is a landable PR with tests, tagged **LANDED** here as it completes (house pattern, cf. [128](128-gnb-ocudu-feasibility.md)).

**Phase A — signalling scaffold (control-plane only). Size M. LANDED.**
NAS PDU Session Type IE (read+emit) + IID / IID‖v4 PDU Address encoding; SMF /64+IID allocation and type negotiation (#50/#51 downgrades); AMF threads the requested type; NGAP N2 type; subscriber `allowedSessionTypes`. **No datapath.** *Exit:* a scripted UE (`bdd/src/ran.rs`) requests IPv6 and IPv4v6 and the Accept carries a correct PDU Address IE (len-9 IID / len-13 IID‖v4) + selected type; a downgrade scenario asserts cause #50/#51. Mirrors the control-plane-first slices 120/122/123.
  - **Landed (branch `feat/131-ipv6-pdu-sessions`):** `nas` — `PduSessionType`/`PduAddress`, `pdu_session_establishment_request_typed`, `requested_pdu_session_type`, IID/IID‖v4 accept encoding + `pdu_address_from_establishment_accept`/`ue_ipv6_iid_from_establishment_accept`/`accept_5gsm_cause`, sm_cause #50/#51. `nf-smf` — a /64+IID allocator (`2001:db8:a::/48`, one /64 per session, IID `::n`), `negotiate_pdu_type` (free5gc `IsAllowedPDUSessionType` shape) + `parse_pdu_session_types`, `pduSessionType` in the create request, `selectedPduSessionType`/`ueIpv6Prefix`/`ueIpv6Iid`/`cause5gsm` + optional `ueIpv4Addr` in the response; a pure-IPv6 session still allocates a v4 for the (unchanged) N4 downlink PDR — Phase A plumbing. `nf-amf` — parses the requested type from the SM container, threads it to the SMF, builds the accept from a `PduAddress` + cause, sets the N2 `PduSessionType`. `ngap` — `PduSessionType` param on the N2 setup transfer (resume/handover default to IPv4, a Phase B item). `nf-udr` demo subscriber gains `allowedSessionTypes:[IPV4,IPV6]` on `internet` + an IPv4-only `ims` DNN for the downgrade test. **Tests:** nas 37, ngap 24, nf-smf 12 (incl. the negotiation matrix + type parsing), nf-amf 51; **full `cargo test -p bdd` = 4 features / 25 scenarios / 277 steps GREEN** (netns datapath + standalone-gNB tiers via passwordless sudo), with the 3 new scripted scenarios — IPv6, IPv4v6, and the IPv4v6→IPv4 downgrade with cause #50, all vs the live core; workspace `--exclude bdd` 44 bins green; clippy no net-new (the accept/`pdu_session_resource_setup_request` too-many-args sites pre-existed). Added an opt-in `BDD_TAG=<feature-tag>` filter to the cucumber runner for loopback-only local runs. NEXT: Phase B (v6 datapath).

**Phase B — v6 user plane. Size L. LANDED.**
`crates/n6` v6 parser + v6 TUN address + v6 route/spoof/downlink; PFCP v6 PDI; UPF v6 `transport_key` + v6 session table. **No RA yet** — the scripted UE is *told* its `prefix::IID` out-of-band. *Exit:* a v6 ICMPv6 echo round-trips through the datapath (the IPv6 analog of [124](124-bdd-scripted-datapath.md)'s `scripted_datapath`), using the loopback-alias UPF topology from 124.
  - **Landed (branch `feat/131-ipv6-datapath`):** `pfcp` — a `UeAddr {v4, v6}` type (`From<Ipv4Addr>` keeps v4 call sites terse); `Session.ue_ipv6` (the /64 prefix); `establish`/`session_establishment_request` carry both families (one downlink PDR, `UeIpAddress::new(v4, v6)` — the /64 round-trips through the real PFCP marshal, verified); `route_downlink_v6`/`ue_ipv6_for_teid`/`admit_downlink_v6` route/police by /64 membership; the handler parses `ipv6_address` from the PDI. `n6` — `ipv6_addrs` (40-byte header), `uplink`/`downlink` dispatch on family (`Uplink::Spoofed` now `IpAddr`; `Downlink::NotIpv4`→`Unsupported`); v6 uplink spoof = src ∈ /64, v6 downlink route = dst ∈ /64 (v6 CM-IDLE buffering deferred). `n6::tun::open` adds a v6 address via iproute2 (`ip -6 addr add … nodad`, the `tun` crate is v4-only). `nf-upf` — N6 TUN gains gateway `2001:db8::1/32` covering the pool. `nf-smf` — **dropped the Phase-A v4-for-v6 hack** (a pure-IPv6 session now allocates NO v4; `SmContext.ue_ip` is `Option`), and **widened the v6 pool to `2001:db8::/32` with the full `u32` counter as the /64 index** — fixing the Phase-A `u16` truncation a commit security-review flagged (stale-identity-mapping: two sessions could collide on a /64 after 65536). **BDD** — `datapath.rs` ICMPv6 echo (pseudo-header checksum) + `ping_through_datapath_v6`; a `scripted_datapath` scenario moves a REAL ICMPv6 echo UE→gateway→reply through N3→N6→N3 over IPv6 (the UE reconstructs `2001:db8:<idx>::<iid>` from the accept's IID + the deterministic pool). **Tests:** pfcp 20 (+v6 routing), n6 11 (+v6 parse/uplink/downlink), datapath 4 (+ICMPv6); workspace `--exclude bdd` 44 bins green; **full `cargo test -p bdd` = 4 features / 26 scenarios / 291 steps GREEN** (v6 datapath echo via sudo); clippy no net-new. NEXT: Phase C (UPF ICMPv6 RA/SLAAC).

**Phase C — RA / SLAAC. Size M. LANDED.**
UPF builds an ICMPv6 Router Advertisement (Prefix Information /64, A-flag; source = a well-known link-local), injects it unsolicited when the DL FAR installs, and answers Router Solicitations. Scripted UE performs real SLAAC (forms `prefix::IID` from the RA, no out-of-band prefix). *Exit:* scripted UE derives its address purely from the RA and then pings; a Router Solicitation is answered.
  - **Landed (branch `feat/131-ipv6-slaac`):** `n6` — `router_advertisement(prefix, len, dst)` (RFC 4861 RA: Prefix Information option, **L|A flags** for on-link + autonomous SLAAC, M=O=0, hop limit 255, ICMPv6 pseudo-header checksum), `is_router_solicitation`, `ra_prefix` (parse the /64 from an RA), `Uplink::RouterSolicitation` (an RS bypasses the /64 spoof check and is answered, not forwarded). `pfcp` — `UpfState.pending_ra` queued by `set_downlink` when a v6 session's downlink installs (also on resume), drained by `take_pending_ra`; `ra_target_for_teid` resolves an RS on an uplink TEID to `(prefix, gNB-TEID, gNB-IP)`. `nf-upf` — the N4 handler sends the **unsolicited** RA over N3 on DL-up (alongside flush/end-markers); the N3 handler answers a **solicited** RS with an RA. `bdd` — `slaac_and_ping_v6`: the UE sends a Router Solicitation, reads the /64 from the RA answer with its **own** parser (`ra_prefix_of`, independent of the UPF's builder), forms `prefix ‖ IID` from the RA prefix alone, and pings; a `scripted_datapath` scenario proves it e2e. The unsolicited RA is unit-tested (builder + queue) and shares the send path with the e2e-tested solicited path. **Tests:** n6 14 (+RA roundtrip/RS-detect/RS-answered), pfcp 20 (RA queue + RS target); workspace `--exclude bdd` 44 bins green; **full `cargo test -p bdd` = 4 features / 27 scenarios / 305 steps GREEN** (real SLAAC via sudo); clippy no net-new. NEXT: Phase D (PCO-DNS + IPv4v6 dual-stack).

**Phase D — PCO-DNS + IPv4v6 + interop. Size M. LANDED.**
PCO IPv6-DNS request/response (container 0x0003); full IPv4v6 dual-stack (both families live simultaneously); optional RDNSS in RA. If free-ran-ue supports IPv6, add an `@sim` interop scenario; otherwise the scripted tier is the proof (free5gc can't be a datapath oracle here — §2). *Exit:* an IPv4v6 session moves both v4 and v6 traffic; the Accept returns an IPv6 DNS server.
  - **Landed (branch `feat/131-ipv6-pco-dualstack`):** `nas` — the first PCO code in the stack: `pdu_session_establishment_request_with_dns` (adds an ePCO with a **DNS Server IPv6 Address Request** container id 0x0003 after the type IE, so `requested_pdu_session_type` still parses); `pco_requests_ipv6_dns`; the accept builder gains a `dns_ipv6` param emitting an **ePCO** (IEI 0x7B TLV-E: config-protocol octet + container 0x0003 with the 16-byte server, before the DNN); `dns_ipv6_from_establishment_accept`. `nf-smf` — reads `dnnConfigurations[dnn].dns.ipv6` from sm-data, returns `dnsIpv6` in the create response. `nf-amf` — parses `pco_requests_ipv6_dns` from the container and returns the DNS in the accept only when requested + provided. `nf-udr` demo `internet` DNN gains `dns.ipv6: 2001:4860:4860::8888`. **IPv4v6 dual-stack**: no new datapath code — Phase B's `UeAddr{v4,v6}` PDR already carries both; a `scripted_datapath` scenario proves one session moves BOTH a v4 ICMP echo (to 10.45.0.1) and a v6 ICMPv6 echo (to 2001:db8::1). RDNSS-in-RA + `@sim` v6 interop skipped (free-ran-ue v6 support unconfirmed; scripted tier is the proof). **Tests:** nas 38 (+PCO round-trip); workspace `--exclude bdd` 44 bins green; **full `cargo test -p bdd` = 4 features / 29 scenarios / 334 steps GREEN** (PCO-DNS control-plane + IPv4v6 dual-stack datapath, via sudo); clippy no net-new. **design/131 COMPLETE — IPv6/IPv4v6 PDU sessions ship end-to-end: negotiation (A) → v6 datapath (B) → SLAAC (C) → PCO-DNS + dual-stack (D).**

## 7. Risks & open questions

- **Wide but shallow edit surface (A).** The type/address threading crosses NAS→AMF→SMF→NGAP→subscriber-db; low conceptual risk, many small edits. Land A behind the existing IPv4 default so nothing regresses (`defaultSessionType=IPV4` stays the default).
- **IID stability & privacy.** Use a per-session deterministic IID (never a real MAC; SLAAC privacy extensions are the UE's concern). Confirm the UE stack (scripted UE, later free-ran-ue) accepts a network-suggested IID vs. forming its own — 3GPP lets the UE use its own IID for additional addresses, so the datapath must route the whole /64, not just `prefix::IID`.
- **RA timing (C).** The unsolicited RA must fire only after the DL FAR (gNB TEID) is installed — i.e. on the PFCP **session modification** that carries the gNB F-TEID, not on establishment. Also handle the CM-IDLE→resume case (re-send/allow RS) so a resumed UE can re-SLAAC. Cross-check against the buffer-flush path ([126](126-bdd-scripted-buffer-flush.md)).
- **`transport_key` extension-header walking (B).** IPv6 puts L4 behind a Next-Header chain; the classifier must walk it (or, MVP, handle no-extension-header packets and log the rest). Bound the walk.
- **N6 dual-stack TUN.** One TUN with both a v4 and a v6 address for IPv4v6, or two TUNs? Prefer one TUN, two addresses (`tun.rs` gains a v6 addr). Verify the `tun` crate supports adding an inet6 address.
- **free-ran-ue IPv6 support unknown.** If the sim UE is IPv4-only, `@sim` interop for v6 is impossible and the scripted tier carries the proof (acceptable — it already exceeds `@sim`'s reach on CM-IDLE etc., [124](124-bdd-scripted-datapath.md)).
- **Scope discipline.** Ethernet PDU type, IPv6 P-CSCF/home-network-prefix PCO containers, and moving N1-accept construction into the SMF are **out of scope** — noted as follow-ups.

## 8. Sources

- **radian-rs:** `crates/nas/src/lib.rs` (accept/reader), `nf/nf-smf/src/pdu_session.rs` (pool/alloc/negotiation), `nf/nf-amf/src/main.rs` (N1 accept, container parse), `crates/ngap/src/lib.rs:1937`, `crates/pfcp/src/lib.rs` (PDI/`transport_key`/session table), `crates/n6/src/{lib,tun}.rs`, `crates/gtpu/*` (opaque), `crates/subscriber-db/src/lib.rs:813`, `nf/nf-udr/src/main.rs:140`, `bdd/src/{datapath,ran,netns}.rs`; `design/18-n6-forwarding.md`, `book/src/ch-03-03-n6-forwarding.md` (both flag dual-stack as future work).
- **free5gc (oracle for message shape / negotiation only):** `NFs/smf/internal/context/{sm_context.go (IsAllowedPDUSessionType, PDUAddressToNAS), gsm_build.go, ue_ip_pool.go, pco.go}`, `NFs/smf/internal/sbi/processor/gsm_handler.go`, `config/smfcfg.yaml` (dns.ipv6). Confirmed absent: IPv6 pool, real IID, RA/SLAAC/DHCPv6.
- **3GPP / IETF:** TS 24.501 §9.11.4.10 (PDU Address) / §9.11.4.11 (PDU Session Type) / PCO; TS 23.501 §5.8.2.2 (one /64 per PDU session, SLAAC); RFC 4861 (Neighbor Discovery / RA/RS), RFC 4862 (SLAAC), RFC 8106 (RDNSS).
- Cross-refs: [130-free5gc-functionality-gap.md](130-free5gc-functionality-gap.md) (P1 origin), [124-bdd-scripted-datapath.md](124-bdd-scripted-datapath.md) (datapath test topology), [126-bdd-scripted-buffer-flush.md](126-bdd-scripted-buffer-flush.md) (resume/DL-up timing).
