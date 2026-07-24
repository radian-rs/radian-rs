# free5gc vs. radian-rs — Functionality Gap Analysis

> Research date: 2026-07-23. Branch `docs/130-free5gc-gap`.
> Baseline compared: **free5gc** (Go, `~/free5gc`, NFs as git submodules under `NFs/`) — already radian-rs's standing wire-compat interop oracle via the `@sim` / free-ran-ue BDD tier.
> Companion to [01-asn1-rust-gap-analysis.md](01-asn1-rust-gap-analysis.md) (the codec-surface gap) and [128-gnb-ocudu-feasibility.md](128-gnb-ocudu-feasibility.md) / [129-rrc-codec-spike.md](129-rrc-codec-spike.md) (the RAN gap). This one covers the **core-network + access-breadth** gap.
> Verify 3GPP release numbers before committing to any slice; free5gc tracks Rel-15/16 with selective Rel-17.

## TL;DR

- radian-rs is **depth-first on one golden path**. The register → auth → PDU session → ping arc is deep and CI-covered end-to-end (both the free-ran-ue `@sim` tier and radian's own `@scripted` gNB/UE tier): full 5G-AKA with SQN resync + algorithm negotiation, the complete CM-IDLE arc (AN release → paging → DL buffering → Service Request resume → buffer flush → T3513 retx), **full N2 handover + Xn path-switch with NH/NCC and direct/indirect data forwarding**, multi-PDU-session per-flow QoS/GBR, session-AMBR policing, CHF charging, PCF AM+SM policy, and a **native Rust gNB** (RRC/PDCP/SDAP/F1AP with a CU/DU F1 split — [128](128-gnb-ocudu-feasibility.md)).
- free5gc is **breadth-first**. 14 NFs including **NSSF, NEF, N3IWF, TNGF, CHF, webconsole**; **ULCL + multi-UPF/I-UPF** user-plane topology; network slicing; **IPv6** PDU-session signalling (datapath stubbed — [131](131-ipv6-pdu-sessions.md) §2); **EAP-AKA'** + **SUCI ECIES profiles A/B**; NRPPa/positioning and MBS transport; multi-AMF with NAS reroute.
- **The gap is breadth, not core-path depth.** radian-rs matches or exceeds free5gc on the single-UE single-session control+user plane, and *leads* on SBI security (mTLS mesh + CRL + PKI, ES256/JWKS OAuth), encryption-at-rest, a userspace UPF (no out-of-tree `gtp5g` kernel module), and owning a RAN stack free5gc doesn't have. radian-rs *trails* on (a) whole NFs (NSSF/NEF/N3IWF/TNGF), (b) user-plane topology (ULCL/multi-UPF/N9), and (c) auth/cipher breadth (EAP-AKA', SUCI ECIES, SNOW3G/ZUC). *(The IPv6 gap listed here originally is **closed** — [131](131-ipv6-pdu-sessions.md) shipped the full stack and radian-rs now leads free5gc on it.)*
- **Verdict: radian-rs is a credible depth-complete single-path 5GC + gNB; free5gc's edge is horizontal coverage. Close the gaps in the order P1 (protocol robustness + IPv6) → P2 (slicing + multi-UPF/ULCL + NEF) → P3 (non-3GPP access + auth/cipher breadth) → P4 (ecosystem).**

Size legend: **S** ≈ days · **M** ≈ 1–2 weeks · **L** ≈ several weeks · **XL** ≈ multi-slice / months.
Severity: **Major** (blocks a whole class of scenarios) · **Moderate** (feature-parity gap on shared paths) · **Minor** (edge/robustness) · **▲ radian ahead**.

## Scope & method

Two trees were mapped NF-by-NF and layer-by-layer:

- **free5gc** — umbrella repo at `~/free5gc`; each NF is a git submodule under `NFs/<nf>/` (webconsole at repo root). Per-NF layout: `pkg/service`, `internal/context`, `internal/sbi/{consumer,processor}`, `internal/ngap|gmm|pfcp|ike`, `api_*.go` route files. Feature evidence: the `api_*.go` service surface, the NGAP/GMM/PFCP handlers, the `config/*.yaml` variants (`multiUPF/`, `multiAMF/`, `uerouting.yaml`), and the `test/*.go` + `test*.sh` E2E suite.
- **radian-rs** — Cargo workspace: 13 library crates (`crates/`), 9 NF binaries (`nf/`), a gNB (`ran/gnb`), the PKI tool (`tools/radian-pki`), and `bdd`. Feature evidence: the crate module structure, the `design/` corpus (01–129), and the BDD tiers.

free5gc is not an arbitrary baseline — it is the implementation radian-rs already validates its wire output against (designs 19/20/21/32/43/45/50/71/74/75/77/80/88/95/96/97 all cite it; the closed PFCP/GTP-U interop gaps 95/96/97 came from a free5gc "gap.txt"). This doc generalizes that per-gap habit into one catalog.

## 1. Network-Function inventory

| NF | free5gc | radian-rs | Gap |
|---|---|---|---|
| **AMF** | `NFs/amf` | `nf-amf` (+`crates/ngap`,`nas`) | shared — feature deltas in §2.1 |
| **SMF** | `NFs/smf` | `nf-smf` (+`crates/pfcp`) | shared — feature deltas in §2.2 |
| **UPF** | `NFs/upf` (go-upf, gtp5g) | `nf-upf` (+`gtpu`,`n6`) | shared — feature deltas in §2.3 |
| **AUSF** | `NFs/ausf` | `nf-ausf` (+`crates/aka`) | shared — §2.4 |
| **UDM** | `NFs/udm` | `nf-udm` | shared — §2.4 |
| **UDR** | `NFs/udr` (MongoDB) | `nf-udr` (redb) | shared — §2.5 (**radian ahead** on at-rest crypto) |
| **NRF** | `NFs/nrf` | `nf-nrf` | near-parity — §2.6 |
| **PCF** | `NFs/pcf` | `nf-pcf` | shared — §2.7 |
| **CHF** | `NFs/chf` | `nf-chf` | shared — §2.8 (free5gc adds Diameter Ro/Gy + CDR files) |
| **NSSF** | `NFs/nssf` | — | **Major, missing** — §3.1 |
| **NEF** | `NFs/nef` | — | **Major, missing** — §3.2 |
| **N3IWF** | `NFs/n3iwf` | — | **Major, missing** — §3.3 |
| **TNGF** | `NFs/tngf` | — | **Major, missing** — §3.4 |
| **webconsole** | `webconsole` | — | **Moderate, missing** — §3.5 |
| **gNB / RAN** | test emulator only (`test/ueRanEmulator`) | `ran/gnb` (RRC/PDCP/SDAP/F1AP, CU/DU) | **▲ radian ahead** — §5 |

Neither stack ships **SCP, SEPP, BSF, LMF, NWDAF, or SMSF** — so those are shared absences, not gaps *against free5gc*. free5gc has an experimental AMF **MCP** server (`amfcfg_mcp.yaml`); not a standards feature.

## 2. Per-NF feature-parity gaps (shared NFs)

### 2.1 AMF

| Feature | free5gc | radian-rs | Gap |
|---|---|---|---|
| NG Setup, Initial UE, UL/DL NAS transport | ✅ | ✅ | — |
| Initial/UE Context Setup·Modify·Release | ✅ | ✅ | — |
| Registration (initial/mobility/periodic), GUTI re-reg, Identity | ✅ | ✅ | — |
| 5G-AKA, Security Mode + algorithm negotiation, SQN resync | ✅ | ✅ | — |
| Service Request resume, Paging | ✅ | ✅ | — |
| NAS timers T3512/T3513/T3522/T3555/T3346/T3396 | partial | ✅ | **▲ radian ahead** (deeper timer/idle state machine) |
| **N2 handover** (Required/Request/Command/Notify/Cancel + fwd) | ✅ | ✅ | — |
| **Xn Path Switch** (+NH/NCC rotation) | ✅ | ✅ | — |
| **EAP-AKA'** authentication | ✅ | ❌ | **Moderate** — §6 |
| **NGReset / Overload Start·Stop / ErrorIndication** | ✅ | ✅ **CLOSED** ([132](132-n2-interface-management.md)) | — |
| **RAN Configuration Update** (+Ack) | ✅ | ✅ **CLOSED** ([132](132-n2-interface-management.md)) | — |
| **Multi-AMF + NAS Reroute** (`RerouteNASRequest`, `config/multiAMF`) | ✅ | ❌ | **Moderate** — no AMF-set / re-route |
| **NRPPa** transport (positioning) | ✅ (plumbed) | ❌ | **Minor** (no LMF either side) |
| **MBS** (`Namf_MBS_*`, multicast/broadcast) | ✅ (plumbed) | ❌ | **Minor** |
| Location Reporting / Trace (TraceStart, CellTrafficTrace) | ✅ | ❌ | **Minor** |

radian-rs is at or beyond free5gc on the mainline mobility + idle arcs; the AMF gaps are **auth breadth (EAP-AKA')**, **N2 interface-management robustness** (reset/overload/error-indication/RAN-config-update), and **multi-AMF**.

### 2.2 SMF

| Feature | free5gc | radian-rs | Gap |
|---|---|---|---|
| Nsmf_PDUSession Create/Update/Release/Modify | ✅ | ✅ | — |
| N4/PFCP association, session est/mod/del, reports | ✅ | ✅ | — |
| PCC/QoS/session/charging rule sourcing from PCF | ✅ | ✅ | — |
| GFBR admission, URR usage → CHF | ✅ | ✅ | — |
| DNN + S-NSSAI authorization (reject #27/#31/#70) | ✅ | ✅ | — |
| **ULCL / branching point / uplink classifier** | ✅ (`ulcl_procedure.go`, `bp_manager.go`) | ❌ | **Major** — §6 |
| **Multi-UPF / I-UPF + PSA chains / UP topology graph** | ✅ (`user_plane_information.go`, `upNodes/links`) | ❌ | **Major** — §6 |
| **IPv6 / IPv4v6 PDU session types** | ⚠ signalling only (`pco.go`, `gsm_build.go`) — negotiation + PCO-DNS but **no prefix/IID alloc, no SLAAC/RA** ([131](131-ipv6-pdu-sessions.md) §2) | ✅ **CLOSED** — negotiation, /64+IID, v6 datapath, SLAAC/RA, PCO-DNS, dual-stack ([131](131-ipv6-pdu-sessions.md)) | **▲ radian ahead** (free5gc's v6 datapath is stubbed) |
| Ethernet PDU session type | ✅ | ❌ | **Minor** |
| UE-IP pool | IPv4 only (the v6 pool is absent) | IPv4 + an IPv6 /64-per-session pool ([131](131-ipv6-pdu-sessions.md)) | **▲ radian ahead** |

The SMF's user plane is **single-UPF, single-N4-association, IPv4-only**. free5gc's ULCL + multi-UPF UP-topology graph (steered by `config/uerouting.yaml`) is the single largest core-network capability gap.

### 2.3 UPF

| Feature | free5gc | radian-rs | Gap |
|---|---|---|---|
| PFCP N4 agent (assoc/heartbeat/session/report) | ✅ | ✅ | — |
| GTP-U N3, uplink decap → DN, downlink encap | ✅ (gtp5g kernel) | ✅ (userspace TUN) | **▲ radian ahead** (no out-of-tree kernel module) — §6 |
| Session-AMBR policing, per-flow GBR, URR volume | ✅ | ✅ | — |
| CM-IDLE DL buffering + Downlink Data Report + flush | ✅ (netlink buffer) | ✅ (bounded in-process) | — |
| GTP-U End Marker, F-TEID CHOOSE, NetworkInstance=DNN | ✅ | ✅ | — |
| **N9 interface (UPF↔UPF chaining)** | ✅ | ❌ | **Major** — pairs with ULCL/multi-UPF |
| **IPv6 flow matching / SDF filters** | ⚠ v6 parser exists (`flowdesc.go`) but the gtp5g binding emits IPv4 attrs only — effectively v4 | ✅ v6 UE-IP PDI + /64 routing ([131](131-ipv6-pdu-sessions.md)); per-flow SDF still v4 | **Minor** (v6 SDF filters remain) |
| NAT for N6 | ✅ (config) | ❌ | **Minor** |

### 2.4 AUSF / UDM (authentication)

| Feature | free5gc | radian-rs | Gap |
|---|---|---|---|
| Nausf_UEAuthentication 5G-AKA (start/confirm/resync) | ✅ | ✅ | — |
| Nudm_UEAU auth-vector generation (Milenage), resync | ✅ | ✅ | — |
| Nudm_SDM (am/sm/smf-select data, subscriptions, notify) | ✅ | ✅ | — |
| Nudm_UECM (AMF/SMF register/deregister) | ✅ | ✅ | — |
| **EAP-AKA'** (`AKA_PRIME`) | ✅ | ❌ (5G-AKA only; a doc-comment in `nf-ausf/src/main.rs` mentions it but no EAP code exists) | **Moderate** — §6 |
| **SUCI deconcealment ECIES Profile A/B** | ✅ (`udm/pkg/suci`) | ❌ (null-scheme only; `sbi-core/src/nudm.rs` treats SUCI as cleartext SUPI) | **Moderate** — §6 |
| Nausf_SoRProtection / UPUProtection | ✅ | ❌ | **Minor** |
| Non-3GPP UECM registration | ✅ | ❌ (no non-3GPP access) | folds into §3.3/3.4 |

### 2.5 UDR

| Feature | free5gc | radian-rs | Gap |
|---|---|---|---|
| Nudr subscription/policy/context data | ✅ (MongoDB) | ✅ (redb) | — |
| Autonomous data-change → UDM notify | ✅ | ✅ | — |
| **Encryption at rest (AES-256-GCM, KEK/HSM seam, 0600)** | ❌ | ✅ | **▲ radian ahead** — §6 |
| **Influence data / PFD data** (AF/NEF traffic influence) | ✅ | ❌ | **Moderate** — required by NEF/ULCL (§3.2/§6) |

### 2.6 NRF

Near-parity: register/heartbeat/deregister/discover (filtered by S-NSSAI+DNN), heartbeat-TTL eviction, **OAuth2 token endpoint + JWKS**. radian-rs adds **ES256/P-256 asymmetric tokens with a JWKS endpoint** (§6). free5gc adds an `api_bootstrapping.go` endpoint (Minor). No SCP on either side, so no delegated discovery either way.

### 2.7 PCF

| Feature | free5gc | radian-rs | Gap |
|---|---|---|---|
| Npcf_SMPolicyControl (PCC rules, session rules, charging) | ✅ | ✅ (keyed partial-map model, QoS-flow binding) | — |
| Npcf_AMPolicyControl (+UpdateNotify push) | ✅ | ✅ | — |
| **Npcf_PolicyAuthorization** (AF app-session) | ✅ | ❌ | **Moderate** — needed for NEF/AF flows (§3.2) |
| **Npcf_BDTPolicyControl** (background data transfer) | ✅ | ❌ | **Minor** |
| **Npcf_UEPolicyControl** | ✅ | ❌ | **Minor** |

### 2.8 CHF

Both implement **Nchf_ConvergedCharging** (create/update/release) with CDR accumulation. free5gc additionally has **Diameter Credit-Control (Ro/Gy)** with dictionaries, **ABMF** (account balance), a **Rating Function**, and a **CGF** writing ASN.1 CDR files; plus **Nchf_SpendingLimitControl**. radian-rs CHF is Nchf-v3 + in-memory CDR only. Gap: **Moderate** (SpendingLimitControl + CDR-file/CGF export), the Diameter stack is **Minor/optional** for a greenfield core.

## 3. Whole-NF gaps (breadth)

### 3.1 NSSF — network slice selection · **Major** · **L**
free5gc: `Nnssf_NSSelection` (slice selection for registration + PDU session) and `Nnssf_NSSAIAvailability` (per-TA slice availability). radian-rs does slice checks **locally in the AMF** (allowed-NSSAI intersection, designs 32/33/102) — there is no `Nnssf`, no NSI selection, no AMF re-selection on slice-not-served. Needed for any multi-slice topology.

### 3.2 NEF — northbound exposure · **Major** · **L**
free5gc: **Traffic Influence** (`api_ti.go` → UDR influence data / PCF app-session → drives ULCL routing) and **PFD Management** (`api_pfd.go`). radian-rs has no northbound/AF surface. Depends on UDR influence data (§2.5) and PCF PolicyAuthorization (§2.7). Pairs with ULCL/NSSF to unlock `TestAFInfluenceOnTrafficRouting`-class scenarios.

### 3.3 N3IWF — untrusted non-3GPP access · **Major** · **XL**
free5gc: **IKEv2** (IKE_SA_INIT / IKE_AUTH with **EAP-5G** / CREATE_CHILD_SA / NAT-T), **xfrm IPsec** SA setup, N2/NGAP toward AMF as the non-3GPP node, **NWu** control (NAS over IPsec/TCP) + user plane, GRE + GTP-U toward UPF. radian-rs: none. Pulls in an IKEv2/IPsec/xfrm stack — a large, self-contained subsystem.

### 3.4 TNGF — trusted non-3GPP access · **Major** · **XL**
Like N3IWF plus a **RADIUS** server (EAP-5G over RADIUS) for trusted-access authentication, and the **NWt** interface. Shares most machinery with N3IWF; realistically a follow-on to it, not independent.

### 3.5 webconsole — provisioning WebUI · **Moderate** · **M**
free5gc: React frontend + Go backend writing subscriber provisioning (SUPI/keys/slices/DNN/policy) to MongoDB, plus a billing module. radian-rs provisions via `subscriber-db` traits / BDD fixtures — no operator UI. A thin admin API + UI over the existing `subscriber-db` and `nf-udr` store would close it; not on the signalling critical path.

## 4. Cross-cutting feature gaps

| Capability | free5gc | radian-rs | Sev · Size |
|---|---|---|---|
| **ULCL + multi-UPF / I-UPF / N9 chaining** | ✅ | ❌ | Major · **XL** |
| ~~**IPv6 / IPv4v6 PDU sessions** (control + datapath)~~ **CLOSED** | ⚠ signalling only, datapath stubbed ([131](131-ipv6-pdu-sessions.md) §2) | ✅ full stack ([131](131-ipv6-pdu-sessions.md)) | **▲ radian ahead** |
| **Network slicing** (NSSF + slice re-selection) | ✅ | partial (AMF-local) | Major · **L** |
| **Non-3GPP access** (N3IWF + TNGF) | ✅ | ❌ | Major · **XL** |
| **EAP-AKA'** | ✅ | ❌ | Moderate · **M** |
| **SUCI ECIES Profile A/B** | ✅ | ❌ null only | Moderate · **M** |
| **SNOW3G / ZUC** (NEA1/3, NIA1/3) | ✅ | ❌ NEA2/NIA2 only | Moderate · **M** |
| **AF traffic influence** (NEF→UDR/PCF→ULCL) | ✅ | ❌ | Moderate · **L** (needs NEF+ULCL) |
| **Multi-AMF + NAS reroute** | ✅ | ❌ | Moderate · **M** |
| ~~**N2 reset / overload / error-indication / RAN-config-update**~~ **CLOSED** | ✅ | ✅ ([132](132-n2-interface-management.md)) | — |
| **NRPPa / positioning**, **MBS** transport | ✅ plumbed | ❌ | Minor · **M** |

## 5. RAN-side — where the comparison inverts (▲ radian ahead)

free5gc ships **no gNB** — only a test UE/RAN emulator (`test/ueRanEmulator`, `test/nasTestpacket`, `test/ngapTestpacket`) that speaks NGAP/NAS well enough to drive the core. radian-rs has a **real Rust gNB** ([128](128-gnb-ocudu-feasibility.md)/[129](129-rrc-codec-spike.md)): RRC (TS 38.331, Hampi UPER codec), PDCP (TS 38.323, NEA2/NIA2), SDAP (TS 37.324), F1AP (TS 38.473, APER) with a **CU/DU F1 split** + F1-U / NR-U (TS 38.425), associating over real SCTP NGAP.

This is coverage free5gc simply doesn't have — but it is measured against a *different* oracle (srsRAN/OCUDU), so it is out of scope for a free5gc gap and tracked in [128](128-gnb-ocudu-feasibility.md). The **remaining RAN gaps there** (RLC/MAC/PHY/FAPI radio stack, E1AP CU-CP/CU-UP split, XnAP real Xn, real Uu) are gNB-roadmap items, not free5gc gaps.

## 6. Where radian-rs leads free5gc

| Capability | radian-rs | free5gc |
|---|---|---|
| **SBI mTLS mesh + CRL hot-reload + PKI tool** (`radian-pki`) | ✅ fail-closed, process-wide | HTTPS/TLS per-NF, no mesh, no CRL/PKI tool |
| **ES256/P-256 + JWKS OAuth2** | ✅ (also HS256) | OAuth2 via NRF (symmetric-style) |
| **Encryption at rest** for long-term credentials (AES-256-GCM, KEK/HSM seam) | ✅ | plaintext MongoDB |
| **Userspace UPF datapath** (TUN, no kernel module) | ✅ | requires out-of-tree **gtp5g** kernel module |
| **Native gNB stack** (RRC/PDCP/SDAP/F1AP + F1 split) | ✅ | test emulator only |
| **Deep timer / idle-mode state machine** (T3512/13/22/55/3346/3396, buffer-flush, T3513 retx) | ✅ | partial |
| **CI-runnable scripted gNB/UE e2e tier** (no external simulator) | ✅ | Go E2E needs full RAN/UE emulator + namespaces |
| **IPv6 / IPv4v6 PDU sessions** — working datapath, SLAAC/RA, PCO-DNS, dual-stack ([131](131-ipv6-pdu-sessions.md)) | ✅ full stack | signalling scaffold only: no prefix/IID alloc, no SLAAC/RA, v4-only datapath |

These are genuine radian-rs advantages — the gap is not one-directional. A greenfield core that leads on security posture and ships its own RAN is a different value proposition than free5gc's horizontal NF coverage.

## 7. Prioritized roadmap

Ordered by value-per-effort, respecting dependencies. Each is a candidate design-doc slice (`131+`).

**P1 — protocol robustness + IPv6 (core-parity, high value):**
1. ~~**N2 interface management** — NGReset/Overload/ErrorIndication/RAN-Config-Update (§2.1)~~ — **DONE**, shipped in [132](132-n2-interface-management.md): all four procedures, with the AMF releasing UE contexts on NG Reset and an OAM route driving Overload.
2. ~~**IPv6 / IPv4v6 PDU sessions** (§2.2/2.3/4)~~ — **DONE**, shipped in [131](131-ipv6-pdu-sessions.md) (PRs #115/#116/#117/#118): type negotiation + #50/#51 downgrades, /64+IID allocation, the v6 datapath, SLAAC via Router Advertisements, PCO IPv6-DNS, and IPv4v6 dual-stack. Because free5gc stubs its v6 datapath (§2 of 131), radian-rs now **leads** here.

**P2 — breadth that unlocks whole scenario classes:**
3. **NSSF + AMF slice re-selection** (§3.1). *L*. New `nf-nssf` + `Nnssf`; wires into existing AMF slice logic.
4. **ULCL + multi-UPF / N9** (§2.2/2.3/4). *XL*. UP-topology graph in SMF + N9 in UPF datapath — the largest core refactor; realistically its own multi-slice effort. Requires ≥2 UPFs first.
5. **NEF + AF traffic influence** (§3.2). *L*. New `nf-nef` + UDR influence data (§2.5) + PCF PolicyAuthorization (§2.7); most valuable once ULCL exists (steers it).

**P3 — access + auth breadth:**
6. **EAP-AKA' + SUCI ECIES Profile A/B** (§2.4/6). *M each*. AUSF/UDM + `crates/aka`; no new NF; improves auth compliance.
7. **SNOW3G / ZUC ciphers** (§4). *M*. `crates/aka`/`pdcp`/`nas` cipher backends; gated on crate maturity (noted as a risk in [128](128-gnb-ocudu-feasibility.md)).
8. **N3IWF then TNGF** (§3.3/3.4). *XL*. IKEv2/IPsec/xfrm subsystem; TNGF follows N3IWF (adds RADIUS). Largest single effort; do last unless non-3GPP is a product requirement.

**P4 — ecosystem:**
9. **webconsole-equivalent provisioning UI/API** (§3.5) over `subscriber-db`/`nf-udr`. *M*.
10. **CHF SpendingLimitControl + CDR/CGF export** (§2.8). *M*. (Diameter Ro/Gy optional.)

## 8. Risks & open questions

- **IPv6 is broad but shallow-per-file** — it threads through PDU-type/PCO in `nas`, IP allocation in `nf-smf`, and the N6 TUN + GTP-U flow matching in `n6`/`gtpu`. Low conceptual risk, wide edit surface; sequence it before ULCL so multi-UPF isn't built IPv4-only.
- **ULCL/multi-UPF is the pivot decision** — it's an XL UP-topology refactor and it presumes a second UPF exists. Question: is multi-UPF worth it before there's a real second-UPF deployment story, or is a single-UPF core the right long-lived scope? This gates P2.4/P2.5 and much of NEF's value.
- **Non-3GPP (N3IWF/TNGF) is a self-contained XL** pulling in IKEv2/IPsec/xfrm and (for TNGF) RADIUS — only worth starting if untrusted/trusted WLAN access is a product goal. Otherwise defer indefinitely.
- **SNOW3G/ZUC crate maturity** — the Rust ecosystem lacks a proven, audited implementation (same risk flagged for the gNB in [128](128-gnb-ocudu-feasibility.md)); AES-only (NEA2/NIA2) remains the safe default until a vetted crate exists.
- **Slicing without NSSF is already partially covered** by the AMF-local allowed-NSSAI logic (designs 32/33/102); confirm what genuinely *needs* a standalone NSSF (NSI selection, cross-TA availability) vs. what the AMF already does, so P2.3 isn't over-scoped.
- **free5gc release skew** — free5gc mixes Rel-15/16 with selective Rel-17; when validating a closed gap against it, pin the free5gc commit (same discipline as the RRC release-skew note in [129](129-rrc-codec-spike.md)).

## Sources

- **radian-rs:** `Cargo.toml` (workspace members); `nf/nf-amf/src/{main,auth,pdu_session}.rs`; `nf/nf-smf/src/pdu_session.rs`; `nf/nf-upf/src/main.rs`; `crates/{n6,gtpu,pfcp,ngap,nas,aka,sbi-core,subscriber-db}/src/`; `crates/sbi-core/src/nudm.rs` (SUCI out-of-scope note); `ran/gnb/src/{lib,f1,du,uu}.rs`; `design/` corpus (01, 32/33/102, 61, 65, 74/75, 78, 95/96/97, 116–129).
- **free5gc:** `~/free5gc/.gitmodules`; `NFs/amf/internal/{ngap/handler.go,gmm/handler.go}`; `NFs/smf/internal/sbi/processor/{pdu_session,ulcl_procedure}.go` + `internal/context/{user_plane_information,bp_manager}.go`; `NFs/upf/internal/forwarder/gtp5g.go`; `NFs/{ausf,udm,nssf,nef,pcf,chf,n3iwf,tngf}/internal/sbi/api_*.go`; `config/{uerouting.yaml,multiUPF/,multiAMF/}`; `test/*.go`, `test*.sh`.
- **3GPP:** TS 23.501 / 23.502 (architecture/procedures); TS 24.501 (5GMM/5GSM); TS 29.244 (PFCP); TS 29.281 (GTP-U); TS 29.500-series (SBI); TS 33.501 (security, SUCI, EAP-AKA'); TS 38.413 (NGAP); TS 38.331 / 38.473 / 38.425 (RRC / F1AP / NR-U).
- Cross-refs: [01-asn1-rust-gap-analysis.md](01-asn1-rust-gap-analysis.md), [128-gnb-ocudu-feasibility.md](128-gnb-ocudu-feasibility.md), [129-rrc-codec-spike.md](129-rrc-codec-spike.md).
