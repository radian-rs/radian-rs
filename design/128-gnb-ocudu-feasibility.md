# gNodeB in Rust — OCUDU Study, Feasibility Gap, and Phased Plan

> Research date: 2026-07-12, on branch `feat/design-gnb-feasibility`.
> Companion to [01-asn1-rust-gap-analysis.md](01-asn1-rust-gap-analysis.md) (the ASN.1
> ecosystem study — this doc extends it to the RAN side it deliberately deferred) and
> [116-bdd-ue-gnb-test-plan.md](116-bdd-ue-gnb-test-plan.md) (the scripted gNB/UE tier
> this doc proposes to grow into a real network element).
> Reference implementation studied: **OCUDU** at `~/ocudu` (local checkout).

## TL;DR

We want gNodeB functionality in radian-rs, in Rust, using OCUDU as the reference.
The investigation splits the problem cleanly in three:

1. **The gNB-CU (control + user plane above RLC) is feasible in Rust now.** radian-rs
   already owns most of the N2/N3 surface (NGAP codec with the full gNB procedure set,
   NAS, GTP-U, SCTP, a working scripted mini-gNB in `bdd/`). The genuinely new work is
   RRC (a UPER codec problem — the one gap design/01 flagged as "project-sized"),
   PDCP/SDAP (~compact), and a real gNB state machine. Order: weeks-to-months, not years.
2. **The DU-high (MAC/RLC/scheduler) is feasible but big.** ~59k LOC of spec-dense C++
   in OCUDU (scheduler alone 43k). No DSP, maps well to Rust. Order: many months for a
   minimal single-cell subset.
3. **The PHY (L1) should not be reimplemented in Rust now.** 63k LOC of hand-vectorized
   DSP (LDPC 11k with AVX2/AVX512/NEON backends, PUSCH receive chain, hard real-time
   pacing). No Rust precedent exists anywhere. OCUDU's own architecture gives us the
   escape hatch: the **FAPI (split 6)** and **F1 (split CU/DU)** seams let a Rust CU or
   DU-high interoperate with OCUDU's C++ lower layers — real UEs without porting DSP.

**Recommended strategy: the interop ladder.** Build the Rust gNB top-down along OCUDU's
own split seams, validating each rung against the live radian core (scripted tier, CI)
and against OCUDU itself (interop tier, real UEs):
CU-over-fake-Uu → +RRC/PDCP → **Rust CU ↔ OCUDU DU over F1** → Rust DU-high ↔ OCUDU
du_low over FAPI → (PHY: attach, don't port).

---

## 1. What OCUDU is

OCUDU is the Linux Foundation-governed continuation of the **srsRAN Project** (SRS's 5G
gNB; namespaces renamed `srsran`→`ocudu`, `srslog`→`ocudulog`, `srsvec`→`ocuduvec`).
C++17/CMake, BSD-3-Clause Open MPI variant (permissive — architectural reference and
porting are fine with attribution). It is a complete, commercial-grade O-RAN gNB:
full L1/L2/L3, split 7.2 fronthaul, E2/RIC, positioning, NTN.

Scale (measured, `.cpp+.h`):

| Bucket | LOC | Notes |
|---|---|---|
| `lib/` hand-written (excl. asn1) | ~137k | the actual RAN stack |
| `apps/` (composition, units, services) | ~46k | thin mains + reusable "application units" |
| `lib/asn1` **generated** ASN.1 codecs | ~754k (≈1.0M with headers) | RRC ~320k, F1AP ~201k, XnAP ~145k, NGAP ~144k, E1AP ~74k, NRPPa ~54k, E2AP/E2SM ~63k |

### 1.1 Apps and functional splits

Binaries are thin shells over composable units (`apps/units/{o_cu_cp,o_cu_up,flexible_o_du}`),
wired either with in-process connectors (monolithic) or real SCTP/UDP gateways (split):

| Binary | Role | Terminates |
|---|---|---|
| `gnb` | monolithic (CU-CP+CU-UP+DU in-process) | N2, N3, Xn, E2, radio/fronthaul |
| `ocu` | CU (CU-CP+CU-UP, E1 in-process) | N2, N3, F1-C, F1-U, Xn, E2 |
| `ocucp` / `ocuup` | split CU-CP / CU-UP | N2+F1-C+E1+Xn / N3+F1-U+E1 |
| `odu` | DU (DU-high + DU-low + RU) | F1-C, F1-U, E2, radio |
| `odu_low` | split-6 PHY-only DU-low | FAPI (network), radio |

Splits supported: **F1** (CU↔DU), **E1** (CU-CP↔CU-UP), **split 6** (FAPI between
DU-high and DU-low, with a plugin loader — the designed hook for third-party L1s),
**split 7.2** (Open Fronthaul/eCPRI to an O-RU), **split 8** (raw IQ to an SDR).
FAPI (SCF P5/P7) is the MAC↔PHY boundary in *every* deployment, in-process or not.

```
 CU-CP ──NGAP/SCTP── AMF          CU-CP ──E1── CU-UP ──GTP-U── UPF (N3)
   │ RRC lives HERE                  │
   F1-C (SCTP)                     F1-U (GTP-U + NR-U flow control)
   │                                 │
 DU-high (MAC + RLC + scheduler + F1AP-DU)
   │ FAPI P5/P7  ← the seam a Rust DU-high can attach at (split 6)
 DU-low (upper PHY: LDPC/polar, PxSCH chains)
   │
 RU ∈ { ru_sdr (UHD/ZMQ/Sidekiq), ru_ofh (7.2/eCPRI), ru_dummy (no HW) }
```

### 1.2 Component inventory (hand-written LOC, what each does)

| Component | LOC | Content | Rust-port relevance |
|---|---|---|---|
| `phy` | 63.5k | upper PHY 50.6k (LDPC **11k**, PUSCH chain ~7.5k incl. channel estimator + MMSE equalizer, polar 1.6k, all with AVX2/AVX512/NEON backends), lower PHY 5.1k (OFDM, FFTW, real-time TX pacing) | **do not port now** (§4.5) |
| `scheduler` | 42.7k | pluggable MAC scheduler: SSB/SIB/RA/paging/PRACH/CSI-RS common scheduling, per-UE HARQ state machines, PUCCH/SRS/UCI resource math, TDD, link adaptation, RAN slicing, QoS policy | biggest *behavioral* surface; minimal subset first |
| `du` | 24.2k | DU-manager (UE lifecycle, RAN resource mgmt), du_high/du_low assembly, test mode | port with MAC |
| `cu_cp` | 23.9k | UE/DU/CU-UP managers, mobility (incl. conditional HO), measurements, security mgr, UP resource mgr, coroutine "routines" per procedure | the Rust CU's blueprint |
| `ofh` | 14.8k | O-RAN 7.2 C/U/S-plane, eCPRI, BFP compression (SIMD), timing windows | out of scope (attach) |
| `f1ap` | 14.5k | CU + DU sides, full UE-context + positioning procedure sets | needed for the interop ladder |
| `ran` | 13.4k | NR constants/math: PRACH tables, PDCCH candidates, band/ARFCN, TDD patterns | port-as-needed (pure functions, easy) |
| `e2` | 10.6k | RIC agent, KPM/RC/CCC service models | defer |
| `ngap` | 9.1k | NG Setup/Reset, ICS, PDU sessions, HO prep/resource-alloc, path switch, paging, PWS, NRPPa transport | **already have** the codec + most builders |
| `mac` | 9.1k | RACH→TC-RNTI, DL/UL PDU assembly/parse, BSR/PHR, HARQ buffer pools | port for DU-high |
| `e1ap` | 8.4k | bearer-context setup/mod/release, both sides | defer until CU-UP splits out |
| `radio` | 8.1k | UHD (B2xx/X3x0/N3xx...), **ZMQ virtual radio**, Sidekiq | attach/FFI only |
| `fapi_adaptor` | 7.4k | MAC↔FAPI↔PHY translators (+ zero-copy fastpath) | the split-6 seam |
| `rlc` | 7.3k | AM (segmentation/ARQ/status), UM, TM; lock-free SDU queues | clean Rust fit |
| `rrc` | 6.7k | **only 5 UE procedures** (setup, reestablishment, resume, reconfiguration, capability); HO/measurements ride RRCReconfiguration built by CU-CP | small — the codec is the real cost |
| `pdcp` | 4.3k | TX/RX entities, 12/18-bit SN, reorder/discard, ciphering+integrity, crypto offload | compact, port |
| `cu_up` | 4.6k | PDU-session manager: QoS-flow→DRB→PDCP→SDAP→F1-U assembly, TEID pools | port (small) |
| `xnap` | 3.6k | Xn setup + HO prep + SN status transfer | defer |
| `gtpu` | 2.9k | G-PDU/echo/error-ind/end-marker, ext headers, NG-U + NR-U tunnel flavors, TEID pool, demux | have minimal version; extend |
| `security` | 2.4k | KDF chain (K_gNB→K_RRC/K_UP, K_NG-RAN* for HO), NEA1-3/NIA1-3 engines (SNOW-3G/AES/ZUC) | RustCrypto covers AES; SNOW-3G/ZUC need care |
| `f1u`/`nru`/`psup`/`sdap` | ~3.1k | F1-U bearers + NR-U flow control (TS 38.425), PDU Session UP protocol (TS 38.415: QFI/RQI/PPI), SDAP QFI↔DRB (300 LOC) | small, port |

### 1.3 Execution model (what "carrier-grade" costs)

All threads owned by a central `worker_manager`; per-layer executor mappers; RT
priorities + CPU-affinity pinning (isolated cores for PHY/cell workers); epoll I/O
broker; **systematically allocation-free datapath** (bounded `static_vector`,
SPSC/MPMC rings, segment-pooled `byte_buffer`, pre-allocated HARQ soft-buffer and
resource-grid pools); timers driven by the PHY slot tick. External deps: yaml-cpp,
mbedTLS, lksctp (all required); FFTW/MKL, UHD, ZMQ, DPDK, libnuma, librohc (optional).

For a Rust port this maps naturally to: tokio for control plane (CU — OCUDU's own
CU is coroutine-per-procedure, i.e. exactly our `async` model), but the DU datapath
below RLC wants dedicated pinned threads + bounded lock-free queues, **not** tokio.

### 1.4 Running without radio hardware (the key enabler for us)

Three first-class hardware-free modes exist, all relevant to a CI-testable Rust gNB:

- **`ru_dummy`** (`lib/ru/dummy`): a Radio Unit that fabricates the slot timeline and
  consumes/produces resource grids with no hardware — the full CU+DU+scheduler+upper-PHY
  stack runs against a synthetic clock. The model for a Rust "simulated PHY" tier.
- **ZMQ virtual radio** (`lib/radio/zmq`): IQ over ZMQ sockets, pairs with srsUE — full
  split-8 chain, no hardware, real (software) UE.
- **Test mode** (`configs/testmode.yml`): synthetic RRC-connected UEs + MAC traffic,
  no core, no UE.

---

## 2. What radian-rs already has (measured)

The scripted BDD tier (designs 116–127) quietly built most of a gNB's N2/N3 side:

| Asset | Where / size | State |
|---|---|---|
| **NGAP codec + builders/parsers** | `crates/ngap` (2.9k LOC over `oxirush-ngap` 0.3.1 APER + `asn1-codecs` for transfer-IEs) | NG Setup, Initial UE Msg, UL/DL NAS, ICS, UE Context Release/Modify, PDU Session Setup/Modify/Release, Paging, **full HO set** (Path Switch, HO Required/Request/Command/Notify/Cancel) — both directions, shared by AMF and tests |
| **NAS 5GMM/5GSM** | `crates/nas` (2.3k over `oxirush-nas` + `oxirush-security`) | complete for our core's surface, incl. working NIA/NEA security context (protect/unprotect, COUNT tracking) — a gNB relays NAS transparently, and the co-located test UE needs exactly this |
| **UE-side 5G-AKA** | `crates/aka` (MILENAGE, RES*, AUTS resync, K_AUSF→K_SEAF→K_AMF→**K_gNB**) | working vs live core |
| **GTP-U** | `crates/gtpu` (162 LOC) | G-PDU encap/decap, echo, end marker. **No extension headers** |
| **SCTP** | `sctp-rs` 0.3.1 pattern, both sides (AMF listener `nf-amf`, client `bdd/src/ran.rs`) | proven, PPID 60; one-to-one only, no multi-homing |
| **Scripted mini-gNB + UE** | `bdd/src/ran.rs` (~360 LOC) + `datapath.rs` (194) + 1.1k of step code | drives vs the live core: registration (all outcome variants), PDU session, CM-IDLE resume, paging + T3513, buffer flush, **real ICMP through N3/N6** |
| Interop harness | free-ran-ue (`@sim` tier) | external Go gNB/UE ↔ radian core, wire-level cross-check |

Gaps on the existing surface (before any new layer):

- **No standalone gNB**: the mini-gNB lives inside the `bdd` test crate; gNB and UE are
  fused into one SCTP endpoint by design ("Tier B plays gNB *and* UE", design/117).
- **No RAN-side state machine**: `crates/ngap` is deliberately stateless codecs; a gNB
  needs association management, RAN-UE-NGAP-ID allocation, per-UE contexts, procedure
  sequencing (the AMF's per-association task model is a template, but AMF-shaped).
- **GTP-U lacks the PDU Session Container extension header** (TS 38.415 PSUP) — no
  QFI/RQI on N3. A compliant gNB must mark uplink G-PDUs with QFI. Also missing:
  error indication, NR-U (TS 38.425) for F1-U.
- **Nothing below NGAP/NAS exists**: no RRC, PDCP, SDAP, RLC, MAC, PHY — as designed.
- Datapath is userspace `UdpSocket` + TUN — fine for the test tier, not a performance
  datapath (no AF_PACKET/XDP/io_uring). Acceptable for every phase proposed here.

---

## 3. Gap analysis by layer

| Layer | OCUDU (hand-written) | radian-rs today | Gap to a working Rust equivalent | Risk |
|---|---|---|---|---|
| NGAP (N2) | 9.1k + 144k gen | **~80% present** | RAN-side state machine + a handful of unbuilt IEs as needed | low |
| GTP-U/N3 + PSUP | 2.9k + 0.1k | minimal codec | PSUP ext header (QFI/RQI), echo wiring, TEID pool, demux | low |
| NAS relay | (transparent) | full stack | none | — |
| **RRC** | 6.7k + **320k gen (UPER)** | none | **the codec is the gap** (§3.1); the 5 procedures themselves are ~1k of logic | medium |
| PDCP + security | 4.3k + 2.4k | NAS-level security only | PDCP entities (SN, reorder, discard), K_RRC/K_UP derivation, NEA2/NIA2 first (RustCrypto `aes`/`ctr`/`cmac`); SNOW-3G/ZUC later (thin/unmaintained crates — audit before trusting) | low-med |
| SDAP | 0.3k | none | trivial (QFI↔DRB header) | low |
| F1AP + F1-U/NR-U | 14.5k + 201k gen + 2.7k | none | APER codec (same generator problem as RRC, aligned variant) + CU-side procedures + NR-U flow control | medium |
| E1AP | 8.4k + 74k gen | none | only needed when CU-CP/CU-UP split; monolithic CU defers it entirely (internal Rust API instead) | deferable |
| RLC | 7.3k | none | AM is the meat (segmentation/ARQ/status); clean sequential Rust, lock-free queues | medium |
| MAC | 9.1k | none | PDU assembly/parse, RACH, BSR/PHR, HARQ buffer mgmt | medium |
| Scheduler | 42.7k | none | even a minimal single-cell, RR, no-CA, no-slicing subset is the largest single work item outside PHY; spec-dense (HARQ, PUCCH/CSI/SRS resource math, TDD) | high (effort) |
| **PHY** | 63.5k, SIMD, hard-RT | none | LDPC/polar at spec throughput, PUSCH receive chain, sample-accurate pacing; **no Rust precedent anywhere** (§3.2) | very high |
| OFH 7.2 / radio | 14.8k / 8.1k | none | out of scope: attach via OCUDU RU/ZMQ, or UHD FFI much later | avoid |
| E2 / NRPPa / Xn / NTN | ~22k | none | orthogonal features; defer | — |

### 3.1 The ASN.1 gap, revisited (extends design/01)

Design/01 concluded: core = NGAP only, done via `oxirush-ngap`; "the RAN side is where
ASN.1 cost would explode." That bill now comes due, with one important refinement —
**volume ≠ difficulty**. OCUDU's 1M generated lines are the *output* of a generator fed
3GPP `.asn` modules (not in the OCUDU tree; sourced from 3GPP). What we actually need:

- **RRC (TS 38.331, UPER)** — the big one (~320k generated C++ equivalent). Options:
  1. **Hampi (`asn1-codecs`)** — 3GPP-first, already in our tree for transfer-IEs,
     documents RRC codegen support. First candidate.
  2. **rasn + rasn-compiler** — most active ecosystem, but known rough edges on the
     gnarliest 3GPP modules (design/01); RRC is the gnarliest.
  3. **Hand-rolled minimal subset** — what our messages actually need (RRCSetup,
     SecurityModeCommand, RRCReconfiguration with a fixed shape, UL/DL-DCCH containers)
     is a tiny fraction of 38.331. This is the `crates/ngap` philosophy (build only
     the IEs we use) applied to UPER. Viable fallback; risk is silent divergence, so
     it must be validated against golden PDUs (pcaps from OCUDU/srsUE runs — OCUDU's
     generated codec is our oracle: encode ours, decode theirs, byte-compare).
  Decision by **spike**, not debate: run Hampi and rasn-compiler over 38.331 rel-17,
  measure what compiles, encode/decode golden PDUs (Phase 1a below).
- **F1AP (APER)** — same story, smaller module; needed at the interop-ladder rung, not
  before. E1AP/XnAP/E2AP: deferred with their features.
- **UE capabilities** (`ue_cap.cpp` is 54k of OCUDU's RRC codec alone): treat
  UECapabilityInformation as an opaque octet string for as long as possible (the CU
  mostly forwards it to the AMF anyway).

### 3.2 The PHY, frankly

The upper PHY is hand-vectorized DSP with four instruction-set backends and a hard
real-time envelope (slot-level deadlines, ≤1 ms TX buffering, O-RAN timing windows).
Nothing in the Rust ecosystem approaches this (our search found only control-plane
PoCs — alsoran, discontinued, lives on in QCore — and UDP-simulated-radio simulators
like UERANSIM-style tools). `std::arch`/`portable_simd` + `rustfft` make it *possible*,
but it is person-years of numerically-fiddly, correctness-critical work with a weak
payoff while OCUDU's L1 is attachable at FAPI. **Verdict: not now, likely not ever as
a port; revisit only as a research project once everything above it is real.**

---

## 4. Strategy

Three options considered:

- **A. Pure-Rust full stack, bottom-up** — rejected. Front-loads the two highest-risk
  items (PHY, scheduler) before anything is testable end-to-end; contradicts the
  repo's slice culture (every slice lands testable against the live core).
- **B. FFI-wrap OCUDU components in-process** (link `lib/phy` etc. into a Rust binary) —
  rejected as the *primary* strategy: drags the whole CMake/C++ dependency surface into
  our build, couples us to internal C++ ABIs that OCUDU doesn't stabilize, and defeats
  the "keep using Rust" premise. (Process-level attachment at standardized seams gives
  the same capability without the coupling.)
- **C. Top-down along OCUDU's own split seams ("interop ladder")** — **chosen.** Every
  rung is a working, CI-testable system; OCUDU processes are test peers, not build
  dependencies; the seams (F1, FAPI) are 3GPP/O-RAN/SCF-standardized, exactly the
  boundaries OCUDU itself uses between its binaries.

The ladder, bottom rung first:

```
Rung 1  radian-gnb (monolithic, fake Uu):   scripted-UE ─UDP "Uu"─ [gNB: NGAP+GTPU+PSUP] ─ radian core
Rung 2  + real RRC/PDCP/SDAP over fake Uu:  UE RRC ↔ gNB RRC (UPER on the wire), K_gNB→K_RRC keys
Rung 3  Rust CU ↔ OCUDU odu over F1:        real MAC/PHY under us; srsUE via ZMQ ⇒ REAL UE, no DSP written
Rung 4  Rust DU-high ↔ OCUDU odu_low FAPI:  our MAC/RLC/scheduler drive their PHY (split-6 seam)
Rung 5  (optional, far) Rust PHY research:  ru_dummy-analog simulated timeline first, ZMQ IQ later
```

Rungs 1–2 need only the radian core as peer (pure `cargo test -p bdd`, CI-runnable).
Rung 3 is where a real UE (srsUE over ZMQ, eventually COTS via B210) enters — the
whole point of basing this on OCUDU.

---

## 5. Phased plan (slices)

Sizes: S ≈ days, M ≈ 1–2 weeks, L ≈ weeks, XL ≈ months. Each phase lands as one or
more PR-sized slices with BDD coverage, per repo convention.

### Phase 0 — `radian-gnb`: promote the scripted gNB to a network element (M) — **LANDED**
Delivered on branch `feat/gnb-p0-standalone`: `ran/gnb` is a live binary+library
(`GnbConfig` from `RADIAN_GNB_*`, an `UuTransport` trait with a `UdpUu` fake-Uu adapter,
per-UE context + RAN-UE-NGAP-ID/DL-TEID allocators, an N2/N3/Uu `select!` loop with
NG-Setup reconnect). `crates/gtpu` grew a `psup` module (TS 38.415) and extension-header
walking so uplink G-PDUs carry the QFI. A new `@gnb` BDD tier drives the standalone binary
through full 5G-AKA registration, a PDU session with a real ICMP datapath echo, and
idle/paging — all green alongside the retained `@scripted` tier. What follows is the
original plan the slice implemented.

New workspace members: `ran/gnb` (binary crate; `ran/` tree keeps RAN elements apart
from core `nf/`) and the state it needs. Content:
- Extract/adapt `bdd/src/ran.rs` + `datapath.rs` guts into `ran/gnb`: SCTP association
  manager (connect/NG Setup/reconnect), per-UE context store, RAN-UE-NGAP-ID allocation,
  NGAP dispatch loop (reusing `crates/ngap` builders/parsers unchanged).
- **UE-facing seam from day one**: a small "Uu adapter" trait — the same gNB core serves
  (a) an in-process scripted UE (BDD) and (b) a UDP fake-Uu socket (standalone runs).
  NAS rides opaque, exactly like a real gNB.
- GTP-U N3 datapath: uplink encap **with PSUP PDU Session Container (QFI)** / downlink
  decap; echo; TEID pool. Extend `crates/gtpu` with TS 29.281 extension headers +
  a new tiny `psup` module (TS 38.415) — OCUDU's `lib/psup` is 133 LOC; ours will be similar.
- BDD: a `@gnb` tier running the *same* scenarios as `@scripted` but through the
  standalone binary (registration, PDU session, idle/paging, datapath echo). The
  scripted tier stays — it tests the core; the new tier tests the gNB.
- Explicit non-goals: no RRC yet (fake Uu carries NAS directly), single AMF, no HO.

### Phase 1 — RRC foundation (L) — **LANDED**
Delivered across four PRs: **1a** the codec spike (PR #104 → design/129, Hampi chosen);
**1b** `crates/rrc` (PR #105, the TS 38.331 UPER codec + builders, golden RRCReconfiguration
byte-identical); **1c** `crates/pdcp` + `aka::rrc_keys` (PR #106, SRB PDCP integrity/
ciphering, NEA2/NIA2 reused from `oxirush-security`); and the **integration** (this branch):
the Uu now carries real RRC over PDCP — SRB0 for RRCSetupRequest/Setup, SRB1 (PDCP) for
NAS transport in UL/DL-InformationTransfer, and the **AS security-mode procedure** flipping
on PDCP integrity then ciphering with keys derived from the K_gNB the AMF hands the gNB.
The `@gnb` BDD tier now asserts the full RRC flow (connection setup → NAS auth → NAS
security → AS security → registration accept → PDU session + datapath → idle/RRCRelease →
paging) end to end against the live core (22 scenarios green). What follows is the original
plan the phase implemented.

- **1a. Codec spike (S/M, throwaway)**: Hampi vs rasn-compiler vs minimal-hand-rolled
  over TS 38.331 (rel pinned to what OCUDU targets). Exit criterion: round-trip the
  golden PDUs captured from an OCUDU `gnb` + srsUE ZMQ run (their codec = oracle).
  Decision recorded as design/129.
- **1b. `crates/rrc`** with the chosen approach, covering: RRCSetupRequest/Setup/
  SetupComplete, SecurityModeCommand/Complete, RRCReconfiguration/Complete,
  RRCRelease, UL/DL-InformationTransfer (NAS), UECapability as opaque. UPER on the wire.
- **1c. `crates/pdcp` + security**: PDCP entities for SRB1/2 (12-bit SN, integrity
  mandatory), K_gNB→K_RRC-int/enc derivation (extend `crates/aka`'s KDF — same
  TS 33.220 HMAC-SHA256 pattern), NEA2/NIA2 engines via RustCrypto (matching what the
  core already negotiates). DRB/18-bit SN + reordering lands in Phase 2.
- gNB: RRC state machine per UE (the OCUDU `rrc_ue` procedures, ~1k of logic), SRB0/1/2
  over the fake Uu; scripted UE grows the UE side (it already owns K_gNB).
- BDD: registration now flows UE-RRC→gNB-RRC→NGAP with real ciphered/integrity-protected
  SRBs; assert against golden traces.

### Phase 2 — user plane completion over fake Uu (M)
- `crates/sdap` (QFI↔DRB, ~300 LOC), PDCP DRB entities (18-bit SN, reorder/discard),
  DRB establishment driven by PDU Session Resource Setup (QoS flow → DRB mapping — the
  OCUDU `cu_up` PDU-session-manager logic, small).
- Datapath echo BDD through the full chain: TUN-side ICMP → N3 G-PDU+QFI → PDCP(DRB,
  ciphered) → fake Uu → UE decap, and back.
- This completes a **UERANSIM-class gNB** — but wire-correct above RLC and validated
  against our own core in CI.

### Phase 3 — F1: Rust CU ↔ OCUDU DU (L/XL, the interop rung)
- `crates/f1ap` (APER, same codec decision as RRC): F1 Setup, Initial UL RRC Transfer,
  DL/UL RRC Transfer, UE Context Setup/Modification/Release, Paging — the subset OCUDU's
  `odu` exercises against a CU.
- F1-U: extend gtpu with the NR-U container (TS 38.425 DL user data / delivery status —
  OCUDU's `lib/nru` is 425 LOC) + `f1u` bearer glue.
- Restructure `ran/gnb` as CU-shaped (it already is: RRC/PDCP/SDAP live CU-side; the
  fake-Uu adapter is replaced by an F1 adapter — same seam as Phase 0 designed in).
- Interop target: `radian-gnb --f1` ↔ OCUDU `odu` (ru_dummy first, then ZMQ + srsUE):
  **a real UE registers on the radian core through a Rust CU.** Manual/nightly tier
  (needs the OCUDU checkout), mirroring the free-ran-ue `@sim` pattern.
- E1 explicitly skipped: monolithic CU (CU-CP+CU-UP in-process behind a Rust trait);
  split + `crates/e1ap` only if/when a deployment needs it.

### Phase 4 — DU-high in Rust ↔ OCUDU du_low over FAPI (XL)
- `crates/fapi` (SCF P5/P7 message structs — header-only in OCUDU, ~small), transport
  per OCUDU's split-6 plugin conventions.
- Minimal `crates/rlc` (TM+UM first, AM after), `crates/mac` (RACH/TC-RNTI, PDU
  assembly/parse, BSR), minimal scheduler (single cell, RR, no CA/slicing) — accept
  OCUDU's `lib/ran` tables as the porting source (pure functions, property-testable).
- This rung is where the tokio-free pinned-thread datapath architecture gets built
  (bounded queues, pre-allocated pools — OCUDU's patterns, §1.3).
- Honest framing: this phase alone rivals the entire core in effort; it is the
  "become a real DU vendor" step and should be re-scoped when we get there.

### Phase 5 — PHY (not planned)
Revisit only after Phase 4 is real. Even then: `ru_dummy`-analog synthetic timeline
for CI, ZMQ IQ for interop, hardware via attachment. A Rust LDPC/PUSCH chain is a
standalone research project, not a slice.

### Crate map (target state through Phase 3)

```
crates/ngap   (exists)      crates/rrc   (P1)      ran/gnb        (P0, binary)
crates/nas    (exists)      crates/pdcp  (P1)      bdd @gnb tier  (P0)
crates/gtpu   (+ext P0)     crates/sdap  (P2)
crates/aka    (+KDF P1)     crates/f1ap  (P3)      [P4: fapi, rlc, mac, sched]
```

## 6. Risks and open questions

1. **RRC codec generator quality** — the load-bearing unknown; that's why Phase 1a is a
   spike with a hard exit criterion (golden-PDU round-trip), and hand-rolled-subset is
   held as the fallback. Mitigation: OCUDU's codec as oracle + pcap corpus.
2. **3GPP release skew** — pin the ASN.1 release OCUDU targets before generating;
   record in the codec crate. (Same discipline design/01 prescribed for NGAP.)
3. **Fake-Uu ≠ Uu** — Rungs 1–2 prove message/state correctness, not radio behavior;
   RLC/MAC timing interactions stay untested until Rung 3+. Accepted: that's what the
   OCUDU-interop tiers are for.
4. **oxirush-ngap coverage ceiling** — the gNB may need IEs the AMF never did (e.g.
   full ServedGUAMI handling, RRC-inactive assistance). Same builder-per-need approach;
   watch for the point where generated-complete (rasn/hampi NGAP) beats hand-extension.
5. **SNOW-3G/ZUC in Rust** — thin/unmaintained crates; ship NEA2/NIA2-only first
   (matches the core's negotiation today), audit or port SNOW-3G/ZUC when interop
   demands them (srsUE/COTS UEs all support AES).
6. **Scheduler scope creep (Phase 4)** — 43k LOC upstream; guard with an explicit
   "minimal viable cell" definition when the phase is scoped.
7. **License hygiene** — OCUDU is BSD-3-Clause-Open-MPI: porting with attribution is
   fine; keep ported-logic provenance notes in crate READMEs.

## 7. Sources

- OCUDU checkout `~/ocudu` (README, `apps/`, `lib/`, `configs/`; LOC measured 2026-07-12).
- radian-rs: `crates/{ngap,nas,gtpu,aka}`, `bdd/src/ran.rs`, designs 01/02/116–127.
- [alsoran](https://github.com/nplrkn/alsoran) — discontinued Rust gNB-CU PoC (lives on
  in QCore); the only known prior art for Rust RAN control plane.
- [srsRAN Project](https://github.com/srsran/srsRAN_Project) — OCUDU's lineage;
  docs at docs.srsran.com describe the same split architecture.
- [UERANSIM](https://github.com/aligungr/UERANSIM) — the "simulated Uu" precedent
  (radio over UDP, no PHY).
- Specs: TS 38.331 (RRC), 38.413 (NGAP), 38.473 (F1AP), 38.463 (E1AP), 38.415 (PSUP),
  38.425 (NR-U), 38.323 (PDCP), 37.324 (SDAP), 38.322 (RLC), 38.321 (MAC), 33.501
  (security), SCF FAPI (P5/P7), O-RAN WG4 CUS (7.2 fronthaul).
