# BDD Expansion Test Plan — 56 UE/gNB-driven Scenarios

> Written 2026-07-09 on branch `feat/bdd-test-plan`. This is a **plan**, not an
> implementation slice: 115 design slices have shipped but the BDD suite still holds only
> 2 features / 5 scenarios (`n6_datapath`, `datapath_e2e`), and a long tail of procedures
> was pinned "not sim-drivable" (free-ran-ue cannot go CM-IDLE, re-register, or run a
> two-gNB handover). This doc catalogs **56 new scenarios** across 7 feature files, the
> harness tier each runs on, and the infrastructure enablers, so they can be implemented
> in bounded slices.

## Two harness tiers

| Tier | Who plays the UE/gNB | What it proves | Runs where |
|---|---|---|---|
| **A — `@sim`** (exists) | free-ran-ue (Go, free5gc libs) in netns | True wire interop (oxirush ↔ free5gc codecs) | Only with `FREE_RAN_UE_BIN` |
| **B — `@scripted`** (new) | The test process, via radian's own crates | The real deployed stack end-to-end: real SCTP :38412, real NFs as processes, real N4/N3/SBI — everything the in-process nf-amf integration tests *don't* cross | Always (sudo + netns only — **CI-runnable**, no external binary) |

Tier B is the big unlock. A `bdd/src/ran.rs` module scripts a gNB + UE:

- **SCTP client** to the AMF via `sctp-rs` 0.3 (the same crate nf-amf serves with).
- **NGAP** via the `ngap` crate — both directions of most procedures are already public
  builders/parsers (the nf-amf integration tests drive them as the gNB); gaps filled as found.
- **NAS security** via `nas::NasSecurityContext::{protect, unprotect}` (public).
- **USIM** via the `aka` crate (Milenage f-functions, RES\*, `compute_auts`, key chain) +
  the demo subscriber's known K/OPc — a real 5G-AKA run, UE-side.
- **GTP-U** via the `gtpu` crate (the `n6_datapath` feature already plays gNB at this layer).
- The UPF runs in a namespace exactly as `n6_datapath` does; the core runs on the host.

Honest boundary: Tier B tests radian against **its own codecs** — a wire-encoding bug
symmetric in builder+parser is invisible to it. That is what Tier A is for; the two tiers
are complementary, and every arc keeps at least its existing Tier-A live-smoke pin.

## Infrastructure enablers (build once, Phase 1)

1. `bdd/src/ran.rs` — `ScriptedGnb` (SCTP assoc, NG Setup w/ configurable gNB-id + TA
   list, send/expect NGAP, N3 GTP-U socket) and `ScriptedUe` (USIM state, NAS security
   context, registration/SR/dereg drivers, IE-level assertions on received NAS).
2. **Log capture**: spawn each NF with stdout→`/tmp/<tag>_<nf>.log`; step
   `the <NF> log should contain "<text>"` with `wait_until` polling (Tier-A scenarios
   assert core-side effects this way; Tier-B scenarios mostly assert on the wire).
3. **SBI poke steps**: reuse `sbi-core` clients from the bdd crate — `I PUT the UDR
   am-policy-data …`, `I POST the PCF policy update for "<supi>"`, `I DELETE the
   subscriber`, `I POST the SMF release for session <psi>` (drives designs 38/48/69/91).
4. **Fixtures**: `ue_nea1.yaml` (NEA1/NIA1-only), `ue_wrong_key.yaml`,
   `ue_unsubscribed_snssai.yaml` (sst=2), a second-subscriber provisioning step (UDR PUT).
5. **Timer envs**: `RADIAN_AMF_T3555_SECS` / `…_T3513_SECS` / `…_IMPLICIT_DEREG_SECS` /
   `…_TNGRELOCPREP/OVERALL_SECS` already exist; add an env for **T3522** (currently a
   fixed 6s const — a 5-send scenario would otherwise take ~30s).
6. Every new feature file ends with the mandated `Scenario: Teardown topology` asserting
   `the test environment should be clean` (not counted in the 56).

## The catalog

Priorities: **P1** = closes a "not sim-drivable"/"not exercised e2e" boundary; **P2** =
new negative/robustness coverage; **P3** = nice-to-have breadth. *(verify sim)* = depends
on an unconfirmed free-ran-ue capability — check first, demote to Tier B if absent.

### A. `sim_registration.feature` (@sim — Tier A, 6 scenarios)

| # | Scenario | Designs | Key assertion | Pri |
|---|---|---|---|---|
| A1 | NEA1/NIA1-only UE registers and pings | 62 | negotiation picks NEA1/NIA1 (AMF log) + ping | P2 |
| A2 | Wrong-K UE never registers | 5-7 | ueTun0 never appears; AMF releases the UE | P2 |
| A3 | Unsubscribed S-NSSAI (sst=2) session rejected | 31 | registration OK, no tunnel; SMF 403 SNSSAI_DENIED in log | P2 |
| A4 | A second provisioned subscriber registers alongside the first | 10, 26 | both UEs ping concurrently | P3 |
| A5 | UE restart re-registers (stale SQN → AUTS resync) | 61 | 2nd registration succeeds after resync (AUSF/UDR log) *(verify sim)* | P1 |
| A6 | Core without a UPF: registration OK, session rejected | 29 | ueTun0 absent; 5GSM reject in AMF log | P2 |

### B. `sim_traffic.feature` (@sim — Tier A, 4 scenarios)

| # | Scenario | Designs | Key assertion | Pri |
|---|---|---|---|---|
| B1 | Session-AMBR polices a UDP blast | 49 | received bytes at N6 ≪ sent; RateLimited drops in UPF log | P2 |
| B2 | GBR port-range traffic classified to its flow | 51 | per-flow QER hits (UPF log) vs off-range traffic on the session bucket | P2 |
| B3 | Usage threshold fires mid-session | 59 | CHF receives an *update* before release (CHF log) | P2 |
| B4 | CDR volume on session release matches traffic sent | 59 | CHF CDR volume == bytes pushed (±ICMP overhead) | P1 |

### C. `sim_policy_push.feature` (@sim + SBI pokes — Tier A, 9 scenarios)

| # | Scenario | Designs | Key assertion | Pri |
|---|---|---|---|---|
| C1 | UE-AMBR UpdateNotify → CUC; UE keeps pinging | 69, 107 | PCF 200 + push; AMF "ConfigurationUpdateCommand"; ping OK | P1 |
| C2 | servAreaRes-only change rides the MRL to the RAN | 71, 72 | AMF sends DL-NAS+MRL; UE unaffected | P1 |
| C3 | RFSP change → UEContextModificationRequest | 70 | AMF log (sim ignores proc 40 — no breakage) | P3 |
| C4 | UDR-autonomous am-data change → CUC w/ new NSSAI | 100-102 | UDM notify → AMF CUC; UE processes it + pings | P1 |
| C5 | Narrowed allowed NSSAI releases the running session | 103 | N2 release; subsequent ping fails | P1 |
| C6 | SM policy sessRules AMBR change re-rates the live QER | 48, 49, 113 | SMF refresh → Update QER (UPF log); ping OK | P1 |
| C7 | Partial SM update touches ONE keyed map only | 108, 112-115 | untouched maps intact (SMF log shows merged decision) | P2 |
| C8 | UDR subscriber DELETE → network-initiated dereg | 38 | AMF Deregistration Request; UE tears down *(verify sim answers w/ Accept)* | P1 |
| C9 | Network-initiated PDU release → UE loses the tunnel | 91 | SMF-triggered N2 release; ping stops | P1 |

### D. `scripted_registration.feature` (@scripted — Tier B, 10 scenarios)

| # | Scenario | Designs | Key assertion | Pri |
|---|---|---|---|---|
| D1 | Scripted UE full 5G-AKA registration | 3-7, 19 | every message field-asserted: Auth Req → RES\* → SMC → ICS | P1 |
| D2 | ICS carries K_gNB + NSSAI + RFSP + MRL + UE-AMBR | 77, 67-71 | gNB-side field equality incl. `kgnb(kamf, ul_count)` | P1 |
| D3 | GUTI re-registration re-authenticates | 60 | fresh 5G-AKA on GUTI hit; same SUPI resumed | P1 |
| D4 | Unknown GUTI → Identity Request → SUCI → registers | 60 | Identity Request received; flow completes | P1 |
| D5 | Stale-SQN UE sends AUTS → resync → success | 61 | Auth Failure(synch) → new challenge verifies w/ adopted SQN | P1 |
| D6 | Wrong RES\* aborts: UE Context Release | 6, 35 | release command w/ NAS cause on the wire | P2 |
| D7 | No subscribed slice → Reject #62 + T3346 + release | 34-36 | cause #62, rejected-NSSAI IE, GprsTimer2 value, release cmd | P2 |
| D8 | Requested-NSSAI intersection + rejected-NSSAI IE | 33 | allowed = ∩ in accept; rejected IE cause correct | P2 |
| D9 | Registration area = gNB TA list ∪ UE TAI in the accept | 74, 75 | TAI-list IE octets vs NG Setup TAs | P2 |
| D10 | Unsubscribed DNN → 5GSM reject #27 + T3396 IE | 29, 30 | cause + GprsTimer3 == 600s read UE-side | P2 |

### E. `scripted_idle.feature` (@scripted — Tier B, 11 scenarios)

| # | Scenario | Designs | Key assertion | Pri |
|---|---|---|---|---|
| E1 | AN release → CM-IDLE, UP deactivated, context retained | 63 | release cmd; UPF FAR=BUFF (log); SMF session persists | P1 |
| E2 | Service Request resume: ICS(ServiceAccept) + inline sessions + echo | 64, 78, 88 | one ICS w/ Cxt-Req list; GTP-U echo round-trips after | P1 |
| E3 | Downlink data buffers + pages; SR flushes the buffer | 65 | Paging w/ right TAI at the gNB; buffered pkt arrives on the NEW tunnel | P1 |
| E4 | T3513: unanswered page retransmits ≤3 then stays retained | 74 | exactly `max_sends` pagings; context still resumable | P1 |
| E5 | Registration-area paging selects only serving-TA gNBs | 74, 75 | gNB-in-area paged, out-of-area gNB silent (two scripted gNBs) | P1 |
| E6 | Mobility registration update: new area + new GUTI | 76, 86 | accept carries re-assigned TAI list + fresh 5G-GUTI; old TMSI dead | P1 |
| E7 | Periodic registration refreshes without re-auth | 85 | lightweight accept, area unchanged, eviction deadline reset | P1 |
| E8 | Uplink Data Status reactivates flagged sessions inline | 87 | UDS PSI → N2 setup inline; unflagged stays deactivated | P1 |
| E9 | PDU Session Status reconciliation both ways | 90 | UE claims a dropped session → accept's bitmap clears it | P1 |
| E10 | T3512 expiry → implicit dereg evicts the retained UE | 66 | (shrunk env) UPF session freed, GUTI gone, next SR → full re-auth | P1 |
| E11 | AM-policy change while idle: 202 + page, applied on resume | 73 | pending held; resume emits ICS → UECtxMod → CUC in order | P1 |

### F. `scripted_handover.feature` (@scripted — Tier B, two gNBs, 8 scenarios)

| # | Scenario | Designs | Key assertion | Pri |
|---|---|---|---|---|
| F1 | Xn path switch: NH/NCC rotate + downlink re-points + source released | 79, 80 | Ack{NCC=1, NH₁}; echo arrives at gNB2's N3; gNB1 gets release(successful-handover) | P1 |
| F2 | End marker on the old path at switch | 97, 98 | gNB1's N3 socket receives GTP-U type 254 | P1 |
| F3 | N2 handover happy path across two associations | 81 | Required→Request(NCC/NH, UL F-TEID)→Ack→Command→Notify; DL re-pointed; source released | P1 |
| F4 | N2 handover with direct forwarding | 82 | Command carries the target's fwd F-TEIDs verbatim | P2 |
| F5 | Indirect forwarding datapath end-to-end | 84 | pkt sent to the UPF ingress F-TEID **emerges at the target gNB** (closes design/84's unexercised boundary) | P1 |
| F6 | Target rejects → HandoverPreparationFailure at source | 83 | target's cause relayed; pending entry gone | P2 |
| F7 | Cancel after Ack → target's prepared context released | 83 | CancelAck + release(HANDOVER_CANCELLED) at target | P2 |
| F8 | TNGRELOCprep expiry → prep-failure, no leak | 83 | (shrunk env) failure at source; HANDOVERS empty | P2 |

### G. `scripted_lifecycle.feature` (@scripted — Tier B, 8 scenarios)

| # | Scenario | Designs | Key assertion | Pri |
|---|---|---|---|---|
| G1 | UE-initiated deregistration tears everything down | 37 | PFCP delete (UPF log), UECM purge, release cmd; GUTI survives | P1 |
| G2 | Switch-off dereg: no Deregistration Accept | 37 | no accept on the wire; teardown identical | P2 |
| G3 | T3522: unanswered network dereg → 5 sends → abort | 39 | (env) exact retransmit count + spacing; contexts dropped after | P1 |
| G4 | T3555: unacked CUC retransmits; late ack stops it | 109, 110 | (env) resend count; ack after 3rd → no 4th | P1 |
| G5 | T3555 exhaustion → implicit dereg escalation | 111 | give-up releases sessions + purges UECM/GUTI | P1 |
| G6 | Network PDU release finalises on the UE's N1 Complete | 91, 92 | SMF N4 delete only AFTER the scripted UE's Complete | P1 |
| G7 | Multi-session release in one SMF request | 94 | N release cmds, each finalising independently | P2 |
| G8 | CM-IDLE session release + next-SR reconciliation | 93 | no N2; retained session gone; SR accept's PDU status reflects it | P1 |

**Total: 56 scenarios** (6+4+9+10+11+8+8) — 34×P1, 17×P2, 5×P3.

## Representative Gherkin (shape, not final wording)

```gherkin
@serial @scripted @scripted_idle
Feature: CM-IDLE lifecycle against the live core
  Scenario: Downlink data pages the UE and the buffer flushes on resume
    Given a clean test environment
    And the radian core is running with a namespaced UPF
    And a scripted gNB "gnb1" serving TAC "000001" has completed NG Setup
    And a scripted UE has registered and established a PDU session
    When the gNB releases the UE context (AN release)
    And a downlink UDP packet is sent to the UE address on N6
    Then the gNB receives a Paging message for the UE's 5G-S-TMSI in TAC "000001"
    When the UE resumes with a Service Request
    Then the AMF re-establishes the context with an InitialContextSetupRequest
    And the buffered downlink packet arrives on the new N3 tunnel

  Scenario: Teardown topology
    ...
```

## Phasing (one slice ≈ one PR, matching the project cadence)

1. **116a** — enablers: `bdd/src/ran.rs` (ScriptedGnb/ScriptedUe minimum: NG Setup +
   full registration), log capture, T3522 env. Delivers **D1** as the proof.
2. **116b** — `scripted_registration.feature` (D2-D10).
3. **116c** — `scripted_idle.feature` (E1-E11; E5 introduces the second gNB).
4. **116d** — `scripted_handover.feature` (F1-F8).
5. **116e** — `scripted_lifecycle.feature` (G1-G8).
6. **116f** — Tier-A additions: `sim_registration` + `sim_traffic` (A1-A6, B1-B4;
   confirm the *(verify sim)* items first).
7. **116g** — `sim_policy_push.feature` (C1-C9; needs the SBI poke steps).

Suite cost: all scripted timers env-shrunk to ≤1s; target < 3 min for the whole
`@scripted` set so it can gate CI. `@sim` stays opt-in via `FREE_RAN_UE_BIN`.

## Boundaries

- Tier B shares codecs with the system under test — it can never replace Tier A's
  wire-compat role, only extend procedural coverage.
- No RRC/Uu modelling: the "UE" and "gNB" are one scripted endpoint (free-ran-ue splits
  them; here the distinction is internal to `ran.rs`).
- Inter-AMF (N14) handover, multi-UPF, and roaming have no core-side implementation yet —
  out of scope.
