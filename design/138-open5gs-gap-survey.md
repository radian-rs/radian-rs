# open5gs 2.8.0 vs radian-rs — Gap Survey (2026-08)

> Survey date: 2026-08-07. Baseline: **open5gs v2.8.0**, `~/open5gs` @
> `8f25f3bea` (2026-08-07, current `main`) — C/meson, ships a **complete 4G EPC
> alongside the 5GC** (17 NF binaries: amf ausf bsf nrf nssf pcf scp sepp smf
> udm udr upf + mme hss pcrf sgwc sgwu). Method: six parallel per-area code
> surveys (AMF; SMF; UPF; AUSF/UDM/UDR; PCF/NSSF/BSF/NRF/SCP/SEPP; EPC+infra),
> each instructed to verify radian claims in code and to flag
> **open5gs-vs-free5gc deltas** so this composes with
> [137](137-free5gc-422-gap-survey.md) instead of repeating it.
> New work items continue 137's catalog as **G31–G42** (§7); §5 recalibrates
> existing G-items where the second oracle changes the verdict.

## TL;DR

- **open5gs is a different kind of oracle than free5gc.** free5gc's edge was
  5GC service-surface breadth (many routes, some stubs). open5gs's edge is
  **production hardening + deployment reality**: a real transaction layer and
  fuzz-hardened TLV parsing on N4, Error Indication with interop-bug war
  stories, SCTP multihoming + per-UE streams, TS 28.552-named Prometheus
  metrics, 20 Debian packages + 17 systemd units, and whole domains free5gc
  never had — **4G EPC, roaming (HR/LBO + SEPP + inter-PLMN NRF + vNSSF),
  SCP, VoLTE/CSFB/SMS**.
- **open5gs is also missing a lot radian has.** No CHF, no NEF, **no OAuth2
  anywhere** (no token endpoint, no Bearer handling — SBI authz ranking:
  free5gc > radian > open5gs), no EAP-AKA' (501, like radian), no
  N3IWF/TNGF, no ULCL/multi-UPF/N9, **no QER rate enforcement** (parses
  MBR/GBR, uses neither), no SDM change-notify (stores the callback, never
  calls it), no registration-time NSSF path, no serving-network authz, no RAN.
  radian's ▲-list *grows* against this oracle (§6).
- **Strongest confirmations:** downlink **QFI marking (G11)** is now missing
  against *all three* references — the one gap every oracle agrees on.
  **SUCI ECIES A/B (G2)** hardens to table stakes (both oracles implement it;
  open5gs's shape — one shared library call + a flat `hnet:` key list — is the
  cheap one to copy). **PFCP liveness (G4)**, **IPAM (G6)**, **NRF status
  subscriptions (G28)**, **BSF (G20)** all get second independent witnesses.
- **Strongest softenings:** **EAP-AKA' (G3)** is free5gc-only pressure
  (open5gs 501s it). Much of 137's NGAP-breadth list (PWS, NRPPa, Trace,
  Location Reporting, RerouteNAS, AMFStatusIndication, NASNonDelivery,
  PDUSessionResourceNotify/ModifyIndication) turns out to be **stub-surface in
  free5gc and absent in open5gs** — downgraded to "nobody implements" (§5).
  The must-have NGAP robustness core narrows to: emit ErrorIndication, RAN
  Status Transfer relay, InitialContextSetupFailure, SCTP COMM_LOST teardown,
  T3550/T3560/T3570, Service Reject + 5GMM Status, richer 5GMM causes.
- **New gap classes free5gc never posed:** the 4G EPC (G31), roaming as a
  cross-NF slice (G32), SCP indirect communication (G33), SCTP robustness
  (G35), codec fuzzing (G36), and a handful of production-datapath UPF
  features (G37).

Severity/size legend as in [137](137-free5gc-422-gap-survey.md).

## 1. What open5gs is (and is not)

| Domain | open5gs 2.8.0 | radian |
|---|---|---|
| 5GC NFs | amf ausf bsf nrf nssf pcf scp sepp smf udm udr upf (**no CHF, no NEF**) | 11 NFs incl. CHF + NEF (**no BSF/SCP/SEPP**) |
| 4G EPC | mme hss pcrf sgwc sgwu + SMF=PGW-C, UPF=PGW-U dual role (~66k LOC) | none |
| RAN | none (tests use an in-process UE/gNB/eNB driver) | native gNB + CU/DU F1 split |
| Store | MongoDB (`lib/dbi`), shared by HSS/UDR/PCRF/PCF; K **plaintext** | redb, AES-256-GCM at rest, ARPF boundary |
| SBI security | TLS/mTLS (`verify_client`), **zero OAuth2** | mTLS + CRL + ES256/JWKS OAuth (enforced at 1 NF) |
| UPF datapath | **userspace TUN/TAP**, single-thread epoll — same family as radian | userspace TUN |
| Charging | Diameter **Gy** (EPC only); no Nchf | Nchf ConvergedCharging (accumulator) |
| Interworking | EPS↔5GS via **combined SMF/UPF node** — grep confirms **no N26** in `src/mme` | none |

open5gs's userspace UPF **validates radian's datapath architecture choice**
— free5gc's gtp5g kernel module is the outlier, not the norm. Its scaling
moves (hash lookups, 32-packet drain budget per wakeup, no threads) are the
cheap ones radian should copy (G19/G37).

## 2. Per-NF gaps (radian missing vs open5gs; free5gc-shared items only named)

### 2.1 AMF (`src/amf`, ~33k lines)

Parity holds on the whole golden path (NG setup, registration/5G-AKA/SMC,
service request, paging+T3513, N2 HO + path switch, dereg, CUC, NGReset incl.
partial, RANConfigUpdate). Gaps, deduplicated against 137:

- **Second-witness confirmations** (details in 137 §3.1 / G7–G9): T3550/T3560/
  T3570 absent; Service Reject + 5GMM Status absent; `InitialContextSetupFailure`
  + `UEContextModificationFailure` unhandled; RAN Status Transfer absent;
  ErrorIndication never emitted — open5gs emits from **9 call sites**
  (`ngap-path.c:271,297`, `nsmf-handler.c` ×6, `gmm-sm.c:1944` …) and radian's
  `crates/ngap` `error_indication()` builder is **dead code** (only its own
  unit tests call it).
- **New vs open5gs only:**
  - `UERadioCapabilityInfoIndication` stored + **replayed** into
    InitialContextSetupRequest / HandoverRequest (`ngap-build.c:892,1426`) —
    free5gc's handlers here are stubs, so open5gs is the oracle for what to
    *do* with the capability.
  - `AMFConfigurationUpdate` (AMF→RAN) + `ngap_send_amf_configuration_update_all()`
    fan-out when served PLMNs change at runtime; runtime PLMN OAM API
    (`namf-oam.c`, 849 lines: GET/POST/DELETE `/namf-oam/v1/plmns`).
  - **PLMN access control with configurable per-PLMN reject causes**
    (`gmm_cause_from_access_control`, `gmm-handler.c:1896`) + RAT restriction —
    the concrete shape for **G12** (free5gc has only a TAI-list check).
  - `nas_5gs_send_gmm_reject_from_sbi()` — maps SBI HTTP failures onto proper
    5GMM causes; ~20 distinct 5GMM causes emitted vs radian's #62 + 4.
  - **IMEISV via SecurityModeCommand** (request flag + digit-swap decode) —
    radian has no PEI anywhere.
  - Registration Accept IE breadth: T3502, 5GS network feature support
    (IMS-VoPS), PDU session status, reactivation result, real TAI list
    (list0/1/2); CUC payload breadth (network name, time zone, DST).
  - **NAS message container** unwrapping (ciphered initial NAS,
    `gmm-handler.c:1763`) — security-relevant.
  - `AMF_TIMER_NG_HOLDING` grace window; **per-UE SCTP stream assignment**
    (spread over `sac_outbound_streams` to avoid head-of-line blocking);
  - **SCTP COMM_LOST/SHUTDOWN → gNB + UE teardown** (`amf-sm.c:874`); radian
    logs the notification and does nothing (`main.rs:768`).
  - **Home-routed roaming**: `plmn_id_in_vplmn` → roaming indication →
    **V-SMF + H-SMF discovery** with target/requester-plmn-list (free5gc
    hardcodes NON_ROAMING) → G32.
- **radian ▲ vs open5gs:** OverloadStart/Stop (open5gs has **zero** occurrences),
  CBL pacing, handover guard timers, `/oam/v1/*`, PCF-vs-subscribed AMBR model,
  in-tree e2e tests. Implicit-dereg / mobile-reachable timers: **parity** with
  open5gs (137 marked this ▲ vs free5gc — still true there; annotate).

### 2.2 SMF (`src/smf`, ~41k lines — also the PGW-C)

- **G16 confirmed from the second direction**: open5gs's SMF encodes/decodes
  N1 5GSM (`gsm-build.c` incl. real per-flow NAS QoS rules + packet filters)
  and N2 transfer IEs (`ngap-build.c` with 5QI/ARP/GBR/AMBR/SecurityIndication)
  itself, carried as **multipart by contentId**. Both oracles put the codecs in
  the SMF; radian's JSON-over-Nsmf is a private dialect.
- **Second witnesses** for G4 (heartbeat + `restoration_required` →
  `pfcp_restoration()` teardown; xact layer with retransmit + dedup; both-
  direction association), G6 (per-DNN subnet pools with ranges + `alloc/free`,
  static IPs, framed routes; radian never frees), G10 (PCO/ePCO: IPCP, DNS
  v4/v6, P-CSCF, MTU, PAP/CHAP; SSC modes decoded/validated/echoed; PTI
  stamped into every 5GSM header; 13 distinct 5GSM causes), G14 (vol/time/event
  quotas + `quota_holding_time` + validity timers).
- **New vs open5gs only:** 13-state per-session FSM (`gsm-sm.c`) + PFCP node
  FSM — radian sequences nothing; **home-routed roaming resources**
  (`/pdu-sessions`, `/vsmf-pdu-sessions`, create/update/release in both HSMF
  and VSMF roles) → G32; session **restoration indication** (PFCPSEReq flag +
  TEID swap); SLAAC **RA sent by the SMF** (via a CP-function FAR — note
  radian sends RA from the UPF: a valid alternative, but another reason a
  radian UPF can't sit under an open5gs SMF); `/pdu-info` OAM dump; metrics.
- **The whole EPC side is open5gs-only**: GTPv2-C S5/S8 + GTPv1-C Gn, Gx/Gy/S6b
  Diameter, EPS bearers/TFT/EBI → G31. **Note: open5gs has no Nchf** — its
  online charging is Gy — so radian's CHF scores only against free5gc.
- **radian ▲ vs open5gs:** ULCL + multi-UPF/N9 + mid-session breakout + UP
  topology graph (open5gs: zero ULCL), AF-influence reconciliation, GFBR
  admission, Nchf charging, `/refresh-policy`, SM-policy **inbound** update
  route (open5gs SM policy is create/delete only — no mid-session SMF-initiated
  modification at all), SUPI-masked logs.

### 2.3 UPF (`src/upf` + `lib/pfcp`)

- **Second witnesses** for the whole G4/G18 block, now with sharper anchors:
  pinned recovery timestamp (`lib/pfcp/context.c:51`), Node-ID validation +
  restoration purge, xact dedup ("Request Duplicated. Retransmit!"),
  `ogs_pfcp_send_error_message` with Cause + **Offending IE** on 10 response
  types, ~40 mandatory-IE checks — and HEAD itself is a PFCP F-TEID bounds fix:
  open5gs actively fuzz-hardens the N4 boundary. Rust closes the memory-safety
  *class* but not the **protocol answer**: radian replies to malformed input
  with silence.
- **Precedence actually evaluated** (sorted PDR list + lowest-precedence
  fallback PDR); **real IPFilterRule** via vendored ipfw2 with BID/direction
  swap; **QFI marked on downlink, on buffered flush, and on End Markers**
  (`lib/pfcp/handler.c:255`, `path.c:471`) → G11 now contradicted by nobody.
- **GTP-U Error Indication both directions** with the TS 23.527 §4.3.2
  suppression window and a hard-won `teid_matched` drop rule (comment cites a
  live-voice-bearer teardown bug) — radian has neither direction; 137 §5
  listed this as a both-sides non-gap **against free5gc**; against open5gs it
  is a real gap → fold into G37.
- **New vs open5gs only (→ G37):** FramedRoute/FramedIPv6Route PDI + binary
  trie longest-prefix routing; **UE↔UE hairpin** without a TUN round-trip;
  ARP/ND proxy + TAP mode; multiple DNN → multiple TUN devices with per-subnet
  config; UPF-side UE-IP pools; User Plane IP Resource Information / TEID
  ranges / multi-N3; rx **drain budget** batching; hash/trie lookups (radian:
  O(n) scans under one global mutex, twice per packet); IPv6 multicast.
- **radian ▲ vs open5gs:** **QER MBR/GBR actually enforced** — open5gs parses
  and re-encodes `qer->mbr/gbr` and **never polices**; GateStatus mandatory
  but unenforced. Combined with free5gc (kernel-offloaded), radian's token
  buckets lead **both** references. Also ▲: RA/SLAAC from the UPF (standalone
  v6), unconditional uplink anti-spoofing, per-flow URR attribution
  (Σ rating-groups == total; open5gs counts each packet against *every* URR on
  the PDR), graceful no-CAP_NET_ADMIN degradation, clock-injected rootless
  tests, NR-U/F1-U support in the gtpu crate.

### 2.4 AUSF / UDM / UDR (+`lib/dbi`)

- **G2 hardens + gets its implementation shape**: SUCI null + **Profile A
  (X25519) + Profile B (P-256)** live in one shared call
  (`ogs_supi_from_supi_or_suci`, `lib/sbi/conv.c:110-227`; crypto in
  `lib/crypt/{curve25519-donna,ecc}.c`; test vectors
  `tests/crypt/ecies-test.c`), keyed by a flat YAML `hnet: [{id, scheme,
  key}]` list. radian can land this as one function in `crates/aka` (or a
  `suci` crate) + home-net keys in subscriber-db — no UDM restructuring.
- **G3 softens**: open5gs hard-501s any `authType != 5G_AKA`
  (`ausf/nudm-handler.c:72-82`); its EAP-AKA lives only on the 4G SWx path.
  EAP-AKA' = free5gc-only pressure. (Still fix the `nf-ausf/src/main.rs:2`
  doc-comment.)
- **Serving-network authorization missing in open5gs too** — "beat both
  oracles" item, ~10 lines, folded in G12.
- **New vs open5gs only:** `DELETE /ue-authentications/{ctx}` (auth removal →
  authRemovalInd chain); `{supi}/auth-events` as a real resource; SDM `nssai`
  dataset + aggregate `GET /{supi}?dataset-names=` + `fields=` projection;
  UECM **GET + PATCH** (imeisv/purgeFlag writeback); NRF profile advertising
  all three UDM services with `allowedNfTypes` (radian: `nudm-ueau` only —
  the **S-sized fix** flagged in G25); subscriber schema breadth (MSISDN→GPSI,
  ODB, access-restriction, subscriber-status, RAU/TAU timer, per-session
  static UE/SMF IPs, framed routes, pcc_rule templates); `open5gs-dbctl` CLI —
  the **cheap shape for G23** (a CLI over `RedbStore::provision_hex`
  in-process preserves the ARPF boundary; open5gs proves UI+CLI-direct-to-store
  is a viable provisioning model without a Nudr CRUD API).
- Wire-compat note (add to the §2-style table): radian's SQN resync is a
  bespoke `POST …/auth-events/resync` endpoint; **both oracles** carry
  `resynchronizationInfo` inside the generate-auth-data body. Also deliberate-
  design note: radian burns an SQN per AV; open5gs increments only on auth
  **confirmation** (abandoned auths don't burn SQNs) — worth an explicit
  decision either way.
- **radian ▲ vs open5gs (all verified):** encryption-at-rest + KEK/HSM seam
  (open5gs: K as plaintext hex in Mongo, `lib/dbi/subscription.c:88`, and the
  UDR serializes K/OPc into the Nudr HTTP response); ARPF boundary (K never on
  the wire); **working data-change-notify chain** (open5gs stores the SDM
  callback and never invokes it — no notify builder exists); UDR
  application-data/influenceData; UECM stale sweep; SSRF guard; `oauth::protect`
  on the UDR; UE-side AKA + full key hierarchy.

### 2.5 PCF / NSSF / BSF / NRF / SCP / SEPP

- **BSF (G20) second witness** — full op set (POST/GET-by-UE-IP/GET-by-id/
  PATCH/DELETE), and the half radian is really missing: **the PCF registers a
  binding on every SM-policy create/delete** (`src/pcf/nbsf-build.c`), which
  is what lets an AF find the serving PCF (`tests/af/nbsf-build.c` shows the
  chain).
- **PCF MediaComponent / AF-QoS (G24) gets a runnable oracle**: medComponents
  → qosReference → configured `qos_profile[]` → PCC rule binding, exercised by
  `tests/vonr/{af,qos-flow,video,session}-test.c` with a real AF client.
  free5gc's PCF had the models; open5gs has the tests.
- **NRF**: status subscriptions + NFStatusNotify fan-out (**every** open5gs NF
  mounts `nf-status-notify` — second witness for G28); real JSON-Patch profile
  update over `/nfStatus`,`/load`,`/plmnList` (radian PATCH discards the body);
  `GET /nf-instances/{id}`; discovery params incl. `service-names`, `tai`,
  `guami`, plmn-lists, `limit`, `hnrf-uri` + **inter-PLMN forwarding via SEPP**
  (→ G32); profile `priority/capacity/load/allowedNfTypes/plmnList` +
  per-NF info blocks.
- **NSSF**: implements **only** `slice-info-request-for-pdu-session` (400s the
  registration path!) — the exact complement of radian's registration-only
  path; returns `NsiInformation{nrfId, nsiId}` (per-slice NRF — G17 confirmed
  against a working implementation); **vNSSF→hNSSF roaming relay** (→ G32).
  Neither implements NSSAIAvailability (radian's PUT/GET surface is ▲).
  Registration-time NSSF: radian + free5gc are **ahead** of open5gs.
- **SCP (G33, whole NF)** — Model C/D indirect communication: `3gpp-Sbi-
  Target-apiRoot`, `3gpp-Sbi-Discovery-*` params, delegated NRF discovery,
  next-hop SCP chaining, SEPP hand-off. `src/scp/sbi-path.c` ≈ 45 KB.
- **SEPP (part of G32, whole NF)** — N32-c exchange-capability handshake
  (TLS/PRINS negotiation), N32-f forwarding keyed on Target-apiRoot →
  PLMN-from-FQDN → peer SEPP; vPLMN/hPLMN FQDN split helpers.
- **OAuth2: open5gs has none at all** — no token endpoint, no Bearer handling;
  the generated AccessToken models are unreferenced. SBI authz ranking:
  **free5gc > radian > open5gs**. G1 stays P0 but is honestly "match free5gc,
  beat open5gs"; open5gs's compensation is exactly radian's fallback (mTLS),
  minus the CRL.
- **radian ▲ vs open5gs:** CHF (verified absent: not in `src/meson.build`),
  NEF (zero non-generated hits), ES256/JWKS+HS256 OAuth, CRL-aware mTLS,
  SM-policy inbound `/update` with typed Keep/Clear/Set deltas, AM-policy
  `/update`+`/delete` subresources, NSSAIAvailability surface.
- **Don't copy:** open5gs PCF reads PCC rules straight from MongoDB, bypassing
  the UDR (`src/pcf/context.c:1029`); radian's UDR-sourced model is cleaner.

## 3. EPC, roaming, and ecosystem (whole-domain gaps)

- **4G EPC (G31, Critical/XL):** MME (S1AP 26 procedures, NAS-EPS, S6a, S11,
  **SGsAP → CSFB + SMS-over-SGs**, Gn/S3 SGSN handover, **SBc-AP/PWS**, NAPTR
  DNS gateway selection), HSS (S6a + **Cx** IMS-HSS + **SWx**), PCRF (Gx +
  **Rx** with ASR — the VoLTE anchor), SGW-C/U (S11, S5/S8, PFCP **Sxa**).
  Interworking is **combined-node**, not N26 — the cheaper architecture if
  ever attempted. Codec assets radian lacks structurally: S1AP (680 asn1c
  files), NAS-EPS, GTPv1/v2-C, Diameter (freeDiameter fork + 8 dictionaries).
- **VoLTE/VoNR (feeds G24/G31):** open5gs ships no IMS but everything an
  external Kamailio needs: Rx/Cx on the EPC side, PCF N5 + BSF on the 5G side,
  P-CSCF address in PCO, `lib/ipfw` IPFilterRule compilation — tested by
  `tests/volte` (6) + `tests/vonr` (5) with in-tree Rx/Cx/AF simulators.
  radian's N5 route exists but is routing-influence-only and untested by any
  AF-QoS scenario.
- **Non-3GPP:** open5gs has **no N3IWF/TNGF either** — its non-3GPP is the 4G
  ePDG anchor (SWx/S6b/S2b, `tests/non3gpp/epdg-test.c`). G30 stays
  free5gc-anchored; three-way, untrusted-WLAN-for-5G is a differentiator no
  one here ships.
- **Test ecosystem:** 16 meson suites incl. handover, slice, CSFB, VoLTE/VoNR,
  AMF-transfer, DNS, **8 libFuzzer harnesses with seed corpora** (NAS-EPS,
  NAS-5GS, NGAP, S1AP, PFCP, GTP, SBI ×2) → G36 is the cheapest new item:
  radian's codec crates are prime `cargo-fuzz` targets. Only external test
  dependency is MongoDB — no root/netns (radian's BDD needs sudo netns; its
  `@gnb` tier is a capability open5gs structurally cannot have).
- **Packaging (G29 gets its target shape):** 20 Debian packages, 17 systemd
  units + networkd TUN provisioning, multi-distro Docker + compose (mongodb +
  webui), Vagrant, logrotate/newsyslog, `make-certs.sh`/`gen-hnkey.sh`,
  release-upload automation.
- **Observability (G26 gets concrete):** `lib/metrics` with swappable
  prometheus/void backends; 7 NFs instrument; AMF counters carry **TS 28.552
  names** (`fivegs_amffunction_rm_reginitreq/succ`, …, a registration-time
  histogram, per-(plmn,snssai) registered-subscriber gauge, per-cause failure
  counters) — copy these names. Logging: 6 levels × 35 per-domain runtime-
  settable log domains + file sink + logrotate; radian has a global
  `RUST_LOG` filter only.
- **Config (G5 second witness):** 20 per-NF YAML templates + 10 scenario
  configs, uniform grammar (logger/sbi server+client/transport servers/metrics/
  NF domain), `address|dev` + `advertise`, TAC ranges (`tac: [6-10]`), CLI
  overrides (`-c/-e/-m/-k`). radian: 69 `RADIAN_*` env vars read inline.

## 4. Wire-compatibility additions (extends 137 §2)

| Interface | Deviation (radian vs both oracles) |
|---|---|
| Nudm_UEAU resync | radian: bespoke `POST …/auth-events/resync`; spec + both oracles: `resynchronizationInfo` inside generate-auth-data |
| UPF/SMF role split | open5gs allocates UE IPs **in the UPF** (per-DNN `session:` subnets) and sends RA **from the SMF**; radian: IP in SMF (free5gc-like), RA from UPF (like neither). Blocks mixing radian's UPF under an open5gs SMF independent of rule-format issues |
| NSSF | open5gs NSSelection is `GET` + query at v2 (second witness); also the *paths* are disjoint: open5gs = PDU-session only, radian = registration only |
| N1N2MessageTransfer | open5gs decodes the full `N1N2MessageTransferReqData` + multipart by contentId, honours `skipInd`, returns `cause=ATTEMPTING_TO_REACH_UE`, stores `n1n2FailureTxfNotifURI`; radian's route takes no body (pages only) — second witness |

## 5. Recalibrations of the 137 catalog

| Item | Change |
|---|---|
| **G1** OAuth enforcement | Stays **P0**, reframed: free5gc > radian > open5gs; open5gs ships zero OAuth. It's "finish what only free5gc does", and radian's mTLS+CRL already beats open5gs's transport-only posture |
| **G2** SUCI | **Hardens** — both oracles implement ECIES A+B. Copy open5gs's shape: one library call + `hnet:` key list; land in `crates/aka`/new `suci` crate + subscriber-db keys |
| **G3** EAP-AKA' | **Softens** — open5gs 501s it; free5gc-only. Keep, lower urgency; fix the misleading doc-comment now |
| **G8/G9** NGAP/SBI breadth | **Narrows** — PWS, NRPPa, Trace, Location Reporting, RerouteNAS (as NGAP), AMFStatusIndication, NASNonDelivery, PDUSessionResourceNotify/ModifyIndication: free5gc = stub surface, open5gs = absent → reclassify "nobody implements". Must-have core: ErrorIndication emission (dead builder!), RAN Status Transfer, ICS Failure, SCTP teardown, Service Reject/5GMM Status, cause breadth |
| **G11** QFI marking | **Hardens** — all three references mark downlink (open5gs also on flush + End Markers). Unanimous; do first |
| **G12** admission checks | Gets its shape: open5gs `access_control` per-PLMN reject causes + RAT restriction. SNN authz stays (both oracles lack it — beat-both item) |
| **G4/G6/G14/G28/G20** | Second witnesses; unchanged, confidence up |
| **G23** provisioning | Cheaper shape available: `open5gs-dbctl`-style CLI over `provision_hex` in-process (keeps ARPF boundary), UI later |
| **G26** metrics | Use TS 28.552 counter names from open5gs `src/amf/metrics.c` |
| **G30** non-3GPP | Three-way absence confirmed (open5gs's "non3gpp" = 4G ePDG anchor) |
| 137 §6 ▲-list | Implicit-dereg: ▲ vs free5gc, **parity** vs open5gs. Add new ▲s: QER policing (vs both), SDM change-notify (vs open5gs), OverloadStart/Stop (vs open5gs), SM-policy inbound update (vs open5gs), CHF + NEF (vs open5gs) |
| 137 §5 non-gaps | GTP-U Error Indication **moves off** the non-gap list (open5gs implements both directions + suppression window) → G37. EPS-interworking/N26, SMS-over-NAS, PWS-5G, SoR/UPU, UDM EventExposure: three-way confirmed non-gaps |

## 6. Where radian leads open5gs (verified)

CHF · NEF · OAuth2 (ES256/JWKS + HS256 + enforcement middleware) · CRL-aware
mTLS · encryption-at-rest + ARPF boundary (open5gs: plaintext K in Mongo,
served over HTTP) · working UDR→UDM→subscriber change-notify · ULCL /
multi-UPF / N9 / mid-session breakout / UP topology graph · AF traffic
influence end-to-end · GFBR admission · **QER rate enforcement** · UPF
RA/SLAAC + anti-spoofing + per-flow URR attribution · SM-policy inbound update
+ typed policy deltas · NSSF registration path + NSSAIAvailability ·
OverloadStart/Stop + CBL · handover guard timers · native gNB/CU-DU ·
rootless clock-injected tests. (And vs free5gc, 137 §6 stands.)

## 7. New work items G31–G42 (continue 137 §8's catalog)

| ID | Item | Sev | Size | Pri | Notes |
|---|---|---|---|---|---|
| **G31** | **4G/EPC core** — MME/HSS/PCRF/SGW-C/U + SMF/UPF dual role; S1AP, NAS-EPS, GTPv1/v2-C, Diameter S6a/Gx/Gy; combined-node interworking (not N26) | Critical (domain) | **XL×n** | P4 | Only if 4G/VoLTE/CSFB is a product goal; VoLTE (Rx/Cx) and CSFB/SMS-over-SGs and ePDG (SWx/S6b/S2b) all hang off it |
| **G32** | **Roaming slice** — HR-roaming (V-SMF/H-SMF discovery + `/vsmf-pdu-sessions`), SEPP (N32-c/f), inter-PLMN NRF discovery (`hnrf-uri`, plmn-lists), vNSSF→hNSSF relay, LBO indication | Major | **XL** | P3 | New gap class free5gc never posed; radian has zero VPLMN/HPLMN awareness |
| **G33** | **SCP** — indirect communication Model C/D, delegated discovery, `3gpp-Sbi-*` header machinery, next-hop chaining | Moderate | L | P3 | Deployment-topology feature; also unlocks the 3gpp-Sbi header plumbing G32 reuses |
| **G34** | **VoNR/AF-QoS conformance** — drive G24 (MediaComponent→PCC binding) against open5gs's `tests/vonr` + `tests/af` as the oracle; IPFilterRule parser shared with G18 | Moderate | M (after G24) | P2 | First runnable AF-QoS oracle; pairs with a BDD `@vonr` tier |
| **G35** | **SCTP robustness** — multihoming (bindx over address list), INITMSG/RTO/HB tuning, per-UE stream assignment, COMM_LOST→teardown, NG holding timer | Moderate | M | **P1** | Gap vs both oracles (free5gc multihomes too); the COMM_LOST teardown half is S and should ride with G8 |
| **G36** | **Codec fuzzing** — `cargo-fuzz` harnesses + corpora for `crates/{ngap,nas,pfcp,gtpu}` (+`rrc,f1ap`), seeded from open5gs's `tests/fuzzing` corpora | Moderate | **S** | **P1** | Cheapest new item; open5gs's HEAD is literally a TLV bounds fix — this is where interop bugs live |
| **G37** | **UPF production-datapath pack** — GTP-U Error Indication (both directions + TS 23.527 suppression), framed routes + LPM, hairpin, ARP/ND proxy + TAP, multi-DNN TUNs, restoration indication/TEID swap, rx batching; fold into/behind G18/G19 | Moderate | L | P2 | Error-Indication + batching + hash lookups are the high-value S/M prefix |
| **G38** | **AMF NAS polish** — IMEISV/PEI acquisition, Registration Accept IE breadth (T3502, NW feature support, PDU session status, real TAI lists), CUC payload breadth, reject-from-SBI cause mapping, NAS message container | Moderate | M | P2 | Complements G7/G10/G12 |
| **G39** | **UE radio capability** — store from UERadioCapabilityInfoIndication, replay in ICS/HandoverRequest | Minor | S | P2 | open5gs is the working oracle; free5gc's is stubbed |
| **G40** | **Provisioning CLI** (G23 phase 1) — `radian-dbctl` over `provision_hex`/Nudr, ARPF-preserving; webui-equivalent later | Moderate | **S–M** | **P1** | Re-scoped from G23 using open5gs's dbctl shape |
| **G41** | **Runtime NF reconfiguration** — NRF JSON-Patch profile update (load/status/plmn), AMF served-PLMN OAM + AMFConfigurationUpdate fan-out | Minor–Mod | M | P3 | open5gs-only capability |
| **G42** | **Log/metrics ops surface** — per-domain runtime log levels, file sink + rotation hooks, TS 28.552 counter names (with G26) | Minor | S | P2 | |

**Updated first wave** (merging 137's, by value-per-effort):
**G1 → G11 → G36 → G40 → G6 → G4 → G7(+G35's teardown half) → G2 → G5**;
then the §7-of-137 pivot decision (G16/G18) — now sharpened: *both* oracles
agree on where the codecs live, so if foreign-NF interop is ever a goal, the
answer is known; if not, G34/G32/G33 are the breadth items worth weighing
against RAN-side work.

### First-wave status (updated 2026-08-11) — **complete**

Every first-wave item has landed. Where a design doc is cited, that is the
implementing slice.

| Item | Status | Landed as |
|---|---|---|
| **G11** QFI marking | ✅ done | [139](139-upf-downlink-qfi.md) — downlink + buffered flush |
| **G36** codec fuzzing | ✅ done | [145](145-codec-fuzzing.md) — cargo-fuzz harnesses + seed corpora |
| **G40** provisioning CLI | ✅ done | [144](144-subscriber-provisioning-cli.md) — `radian-dbctl` |
| **G6** IPAM | ✅ done | [140](140-smf-ipam-pool.md) — releasable UE address pool |
| **G4** PFCP liveness | ✅ done | [141](141-pfcp-liveness.md) — heartbeat both directions |
| **G7** NAS timers | ✅ done | [142](142-amf-nas-retransmission.md) — T3550/T3560/T3570 |
| **G35** teardown half | ✅ done | [146](146-sctp-teardown.md) — SCTP COMM_LOST/SHUTDOWN → gNB teardown |
| **G2** SUCI ECIES A/B | ✅ done | [143](143-suci-deconcealment.md) — deconcealment at the UDM |
| **G5** per-NF config | ✅ done | [147](147-per-nf-config.md) foundation + SMF; [148](148-config-upf-ausf.md) UPF/AUSF |
| **G1** OAuth enforcement | ✅ done | mechanism + UDM/UDR ([137-security-audit](137-security-audit.md) F2–F4); **enforced across all six remaining producers** ([149](149-oauth-enforcement-rollout.md)) + **consumer-side token attachment on every edge** ([150](150-oauth-consumer-tokens.md)) |

G1 is now proven end-to-end across processes: a `@sbi_security` BDD run brings the
whole mesh up with `RADIAN_SBI_SECRET` on and completes registration + a PDU
session with every producer enforcing and every consumer attaching tokens
([152](152-sbi-security-bdd.md)). The authorization model is complete — **both
audience and scope** are enforced ([154](154-oauth-per-scope-authz.md)), proven
through that same BDD. Remaining G1 nicety: an asymmetric (ES256/JWKS) variant of
the secured BDD run. **Next after the wave**: the §7-of-137 pivot decision above
(G16/G18 codec-home vs G34/G32/G33 breadth vs RAN-side work).

## Sources

- open5gs v2.8.0 @ `8f25f3bea`: `src/{amf,smf,upf,ausf,udm,udr,pcf,nssf,bsf,
  nrf,scp,sepp,mme,hss,pcrf,sgwc,sgwu}`, `lib/{pfcp,sbi,nas,ngap,sctp,crypt,
  dbi,metrics,ipfw,tun,gtp}`, `configs/`, `tests/`, `webui/`, `debian/`,
  `misc/db/open5gs-dbctl`.
- radian anchors as cited; calibration base [137](137-free5gc-422-gap-survey.md)
  (its radian-side claims re-verified in code by each surveyor; all held).
- Six survey transcripts, 2026-08-07. Line numbers valid at survey date.
