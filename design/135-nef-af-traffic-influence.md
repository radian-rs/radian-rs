# NEF + AF traffic influence — northbound exposure that drives ULCL

> Research date: 2026-07-24. Executes design/130's **P2-5 NEF + AF traffic influence** — the last open P2 item, unblocked now that ULCL exists (design/134).
> free5gc is the interop oracle: NEF at `NFs/nef/`, the AF flow `Nnef_TrafficInfluence` (TS 29.522) → `Npcf_PolicyAuthorization` (TS 29.514) → SMF ULCL (TS 23.501 §5.6.7 AF influence on routing).
> 3GPP: TS 29.522 (Nnef_TrafficInfluence), TS 29.514 (Npcf_PolicyAuthorization), TS 23.501 §5.6.7 / §5.6.4 (AF influence → UL classifier), TS 29.512 (SM policy decision, TrafficControlData/RouteToLocation).
> **Status:** Phases 1 + 2a LANDED — a thin NEF (`nf-nef`, port 8009) turns an AF `Nnef_TrafficInfluence` request into a live ULCL insertion (Phase 1, `@nef` e2e), and AF influence can now ride **through the SM policy** (`traffContDecs` → the SMF's refresh reconciles a live breakout, Phase 2a). Remaining: Phase 2b (the AF → NEF → PCF front + PCF→SMF notify) and Phase 3 (group/any-UE via UDR).

## TL;DR

- An **AF traffic-influence** request says "route traffic for *this app*, for *this UE on this DNN*, to *this edge (DNAI)*." That is exactly a local-breakout / uplink-classifier insertion — which design/134 Phase 3e already implements as a live-session operation. The missing piece is the **northbound front door**: a NEF that speaks `Nnef_TrafficInfluence` to the AF and drives the SMF's existing ULCL trigger.
- **The endpoint of the chain already exists.** design/134 Phase 3e's `insert_breakout`/`remove_breakout` splice a breakout onto a live session given `(supi, prefix, target UPF)`. A NEF is the production trigger the OAM stand-in was standing in for.
- free5gc's full path is AF → NEF → {PCF single-UE | UDR group/any-UE} → SMF. The PCF only reshapes `trafficRoutes` into an SM-policy `TrafficControlData.routeToLocs`, and the SMF resolves the **DNAI → UPF** through its userplane config's `dnaiList`. radian's SMF trigger already consumes the *resolved* `(prefix, target UPF)`, so for a first slice **the PCF hop collapses**: AF → NEF → SMF directly, mirroring free5gc's single-UE branch minus the policy-authorization machinery.
- **Decision: land a thin NEF first (Phase 1).** `nf-nef` (port 8009) speaks the two essential `Nnef_TrafficInfluence` endpoints (create + delete a subscription), translates a `TrafficInfluSub` into the SMF's breakout trigger, and tracks subscriptions so a delete removes the breakout. To keep the NEF thin and faithful, **DNAI→UPF resolution stays in the topology** (the SMF resolves it, as free5gc does) — so the topology's `UpNode` gains a `dnai`, and the SMF's trigger learns to take a DNAI and to identify the session by `(supi, dnn)`. The PCF-mediated path and group/any-UE-via-UDR are later phases.

## 1. The AF influence flow (free5gc, measured)

| Hop | free5gc | What it does |
|---|---|---|
| AF → NEF | `POST /3gpp-traffic-influence/v1/{afId}/subscriptions` (`NFs/nef/internal/sbi/api_ti.go`) | AF submits a `TrafficInfluSub` |
| NEF fork | `processor/ti.go:38` | single-UE (`gpsi`/`ipv4Addr`) → PCF `Npcf_PolicyAuthorization`; group/`anyUeInd` → UDR influence data |
| PCF | `policyauthorization.go:1696 provisioningOfTrafficRoutingInfo` | builds a `PccRule` + `TrafficControlData`, sets `tcData.routeToLocs = trafficRoutes` (carries the DNAI) |
| SMF | `sm_context.go:640 CreatePccRuleDataPath` | reads `tcData.RouteToLocs[0].Dnai` → `UPFSelectionParams{Dnai}` → selects PSA2 path → `AddPDUSessionAnchorAndULCL` |
| DNAI→UPF | `snssai.go:39 ContainsDNAI`, config `dnnUpfInfoList[].dnaiList` | the UPF whose `dnaiList` contains the DNAI is the breakout anchor |

**`TrafficInfluSub` (TS 29.522) — the fields that matter:** `dnn`, `snssai`, a UE identity (`gpsi`/`ipv4Addr`/`externalGroupId`/`anyUeInd`), `trafficFilters[].flowDescriptions` (IPFilterRule strings — the destination in `"permit out ip from A to B"` is the breakout prefix), and `trafficRoutes[].dnai` (a `RouteToLocation`; the DNAI is the breakout target). The rest (`afServiceId`, `afTransId`, `tempValidities`, …) is metadata.

## 2. What radian has, and the gap

- **The trigger** — design/134 Phase 3e: `oam_breakout`/`insert_breakout`/`remove_breakout` (`nf-smf/src/pdu_session.rs`) splice a breakout onto a live session given `BreakoutReq{ supi, pdu_session_id, prefix, via }` (`via` = a UP-topology node name). Proven end-to-end (`@ulcl_mid_session`).
- **The topology** — `Topology{ up_nodes, links, routes }` (`nf-smf/src/topology.rs`): named UP nodes with `n4`/`dnns`, and per-DNN breakout `routes{ dnn, prefix, via }`. **No DNAI attribute** — `Route.via` is already a node name.
- **The PCF** — `sbi_core::npcf::SmPolicyDecision` carries session AMBR + per-flow QoS only; **no `TrafficControlData`, no `routeToLocs`, no DNAI**. It cannot express "route to an edge" today. So the PCF-mediated path needs the policy model extended first — a bigger effort, deferred.
- **The gaps for a NEF:** (a) a NEF NF and its `Nnef_TrafficInfluence` service; (b) DNAI→UPF-node resolution (belongs in the topology, per free5gc); (c) flow-description → prefix; (d) the SMF identifying a session by `(supi, dnn)` — an AF targets a DN, not a `pduSessionId`, and the SMF has no SUPI→sessions index.

## 3. Design decisions

**D1 — AF → NEF → SMF direct; the PCF hop collapses (for now).** free5gc's PCF only reshapes `trafficRoutes → tcData.routeToLocs` and forwards `(dnn, snssai, dnai, filter)`; radian's SMF trigger already consumes the resolved `(prefix, target UPF)`. So a faithful minimal slice skips the PCF and the policy-model surgery it would need. *Rejected for now:* the PCF-mediated path — it is the "correct" single-UE route (AF→NEF→PCF→SMF) and the only way AF influence composes with QoS policy, but it requires inventing `TrafficControlData`/`RouteToLocation`/DNAI in `SmPolicyDecision` and teaching `apply`/`diff`/`refresh_sm_policy` about them (design/48/49's machinery). Phase 2.

**D2 — DNAI→UPF stays in the topology, resolved by the SMF.** free5gc resolves a DNAI to a UPF through the userplane config (`dnnUpfInfoList[].dnaiList`), *not* in the NEF — the NEF never learns the UP topology. radian mirrors this: `UpNode` gains an optional `dnai`, and the SMF's breakout trigger accepts a `dnai` and resolves it to a node (`Topology::node_for_dnai`). The NEF passes the DNAI through untouched, staying a thin translator. *Rejected:* a `dnai→node` table in the NEF — it would leak UP-topology knowledge into the exposure layer, which free5gc is careful not to do.

**D3 — The SMF identifies the AF-targeted session by `(supi, dnn)`.** An AF request targets a UE + DNN, not a `pduSessionId` (which it cannot know). The breakout trigger's `BreakoutReq` gains an optional `dnn`: given `supi + dnn`, the SMF finds the (single) matching live session. `pdu_session_id` stays supported (the Phase 3e OAM tests/BDD use it), so the change is additive. A UE with multiple sessions on one DNN is out of scope for the first slice (documented).

**D4 — Flow-description → prefix by targeted extraction, not a full IPFilterRule parser.** The AF's `flowDescriptions[0]` is an IPFilterRule (`"permit out ip from <src> to <dst>"`); the **destination** is the breakout prefix (free5gc's `EstablishULCL` derives the SDF filter's match from the route destination the same way). The NEF extracts the `to <cidr>` token — a small, targeted parse. A full IPFilterRule engine stays a known simplification (radian's pfcp already uses its own flow-description format, design/134 §D4). A subscription may also carry the prefix directly for callers that prefer it.

**D5 — The NEF tracks subscriptions so a delete undoes the insert.** `Nnef_TrafficInfluence` is CRUD: the create returns a `{subId}` (and a `Location` header), the delete addresses it. The NEF keeps a `subId → (supi, dnn)` map so `DELETE …/{subId}` calls the SMF trigger with `remove:true`. State is in-memory (the NEF is otherwise stateless), matching how radian's other NFs hold soft state.

## 4. Phases

**Phase 1 — a thin NEF driving the SMF's ULCL trigger. Size M. LANDED.**
`nf-nef` (port 8009, copied from the `nf-nssf` skeleton) + `sbi_core::nnef` (the `TrafficInfluSub` subset + `POST /3gpp-traffic-influence/v1/{afId}/subscriptions` create and `DELETE …/{subId}`). The NEF discovers the SMF via the NRF (or an explicit `RADIAN_NEF_SMF` base) and POSTs the breakout trigger; it tracks each subscription (`subId → (supi, dnn)`) so a delete withdraws the breakout.
  - **SMF-side enablers:** `Topology.UpNode.dnai` + `Topology::node_for_dnai` (the DNAI→node map free5gc keeps in the userplane config); `BreakoutReq` gained `dnai` (resolved to a node via the topology when `via` is absent) and `dnn` (a session identified by `supi + dnn`, since an AF targets a DN, not a `pduSessionId`) — both additive, so the Phase 3e OAM path is unchanged.
  - **NEF translation:** `supi`/`gpsi` → the UE; the destination CIDR of the first IPFilterRule `flowDescription` (`… to <cidr>`) → the steer prefix (or a direct `prefix`); `trafficRoutes[0].dnai` → passed through for the SMF to resolve. The NEF never learns the UP topology.
  - **Tests:** `sbi-core::nnef` — flow-description prefix extraction + the create/delete translating against a mock SMF; `nf-smf::af_traffic_influence_through_the_nef_splices_a_breakout` — a real NEF → real SMF → **three** in-process UPFs, the AF naming a **DNAI** and targeting by **SUPI+DNN**, asserting the DNAI-named edge anchors the breakout and a delete withdraws it. **BDD** `nef_traffic_influence.feature` (`@nef`): a real `nf-nef` process front-doors the live datapath — the UE reaches the edge DN `10.99.0.1` (unreachable a moment earlier) after an AF traffic-influence `POST`. Full `cargo test -p bdd` = **43 scenarios / 464 steps GREEN** (41/444 + this feature's 2/20); sbi-core 51 + nf-smf 28 unit tests; clippy clean.

**Phase 2a — AF influence carried through the SM policy. Size M. LANDED.**
The policy model now expresses a route-to-DNAI, and the SMF turns it into a live breakout — so AF influence rides in the *same* decision as QoS (`Npcf_SMPolicyControl`), not a side channel. `SmPolicyDecision` gained `traffic_control_data` (`traffContDecs`, TS 29.512 §5.6.2.10): a `TrafficControlData{ route_to_locs: [RouteToLocation{dnai}], traffic_prefix }` — the DNAI is the anchor, `traffic_prefix` the CIDR the classifier matches (radian's per-flow filter is port-based, so the steered prefix rides on the tc decision rather than a linked PCC rule's `flowInfo` — a known simplification, §D4). `diff`/`apply` carry it as a fifth keyed partial map; `influence_route()` reads the effective `(prefix, DNAI)`.
  - **The SMF's `refresh_sm_policy` grew a reconcile arm.** After merging the policy delta, it compares the decision's `influence_route()` to the session's live breakout state (`chain.breakout_seid`): a route now present with none active → `insert_breakout` (resolving the DNAI via the topology); a route now absent with one active → `remove_breakout`. Skipped for a session whose DNN owns a **static** topology route (config-owned; policy must not disturb it). This reuses the Phase 3e insert/remove machinery unchanged — the refresh is just a new trigger for it.
  - **Tests:** `sbi-core::npcf` — the `traffContDecs` diff/apply + `influence_route`; `nf-smf::sm_policy_traffic_control_drives_a_breakout_on_refresh` — a UDR-backed PCF over three in-process UPFs: a mid-session policy-data change adds a route→DNAI, a refresh splices the breakout in, and withdrawing it tears the breakout down. sbi-core 52 + nf-smf 29; full bdd unchanged (the arm only fires on an influenced policy, which no other tier provisions).

**Phase 2b — the AF → NEF → PCF front. Size M. (remaining)**
Wire the Phase-1 NEF's **single-UE** requests through the PCF instead of straight to the SMF: `Npcf_PolicyAuthorization` on the PCF (`AppSessionContext`, `POST /npcf-policyauthorization/v1/app-sessions`) folds the AF's route into the matching SM policy's decision, and the PCF **notifies the SMF** (an `Npcf_SMPolicyControl` update notify to a URI the SMF registers at policy create) so the 2a reconcile arm fires. This makes the full AF → NEF → PCF → SMF chain the production path; the Phase-1 NEF→SMF-direct route stays as the deployment-without-PCF fallback.

**Phase 3 — group / any-UE via UDR influence data. Size M. (deferred)**
`externalGroupId`/`anyUeInd` requests are stored as UDR *application influence data* and applied to **new** sessions at establishment (not spliced live) — the SMF consults influence data during `resolve_path`. Plus DNAI-change subscription/notification.

## 5. Risks & open questions

- **The PCF bypass is a simplification, not the target.** Phase 1's AF→NEF→SMF direct path mirrors free5gc's single-UE branch *after* the PCF has reshaped it, minus policy authorization — so AF influence does not yet compose with PCF QoS decisions. Phase 2 closes this; Phase 1 is honest about being a front door onto the OAM-equivalent trigger.
- **`(supi, dnn)` assumes one session per DNN.** A UE with two sessions on the same DNN is ambiguous; the first slice takes the first match and documents it. A real GPSI→sessions resolution lives at the UDM/UECM (`smf-registrations`), out of scope here.
- **No authorization of the AF.** A real NEF authenticates the AF and checks it is entitled to influence the target DNN/UE (OAuth + `afServiceId` allow-list). The first slice trusts the caller, as the OAM endpoint does; NEF-side OAuth is a follow-on (radian already has the SBI OAuth machinery, design/46).
- **GPSI vs SUPI.** The AF uses a GPSI (e.g. an MSISDN); radian's trigger uses the SUPI. The first slice accepts a `supi` (or a `gpsi` that *is* the SUPI); a real GPSI→SUPI map is UDM territory.

## 6. Sources

- free5gc: `NFs/nef/internal/sbi/api_ti.go`, `NFs/nef/internal/sbi/processor/ti.go`, `NFs/pcf/internal/sbi/processor/policyauthorization.go` (`provisioningOfTrafficRoutingInfo`), `NFs/smf/internal/context/sm_context.go` (`CreatePccRuleDataPath`), `NFs/smf/internal/context/snssai.go` (`ContainsDNAI`), `NFs/smf/internal/sbi/processor/ulcl_procedure.go`, `ci-test/config/ULCL/smfCfg.yaml` (`dnaiList: [mec]`), `ci-test/test/json/ti-data.json`.
- radian: `nf/nf-nssf/src/main.rs` + `crates/sbi-core/src/nnssf.rs` (new-NF template, design/133), `nf/nf-smf/src/pdu_session.rs` (`oam_breakout`/`insert_breakout`, `BreakoutReq`), `nf/nf-smf/src/topology.rs` (`Topology`/`UpNode`/`Route`), `crates/sbi-core/src/nnrf.rs` (`discover`), `crates/sbi-core/src/npcf.rs` (`SmPolicyDecision` — no route/DNAI today).
- TS 29.522, TS 29.514, TS 23.501 §5.6.7 / §5.6.4, TS 29.512. Gap origin: [130](130-free5gc-functionality-gap.md) §2.5 / roadmap P2-5. Trigger reused: [134](134-ulcl-multi-upf.md) Phase 3e.
