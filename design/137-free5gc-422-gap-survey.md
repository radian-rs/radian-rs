# free5gc 4.2.2 vs radian-rs — Gap Survey (2026-08)

> Survey date: 2026-08-07. Baseline: **free5gc 4.2.2 monorepo** at
> `~/free5gc-4.2.2` (NFs vendored in-tree, not submodules — a pinned, stable
> oracle, unlike the moving `~/free5gc` used by [130](130-free5gc-functionality-gap.md)).
> Method: six parallel per-area code surveys (AMF; SMF; UPF; AUSF/UDM/UDR;
> PCF/CHF/NSSF/NEF/NRF; infra + missing NFs), each enumerating the Go feature
> surface from its handlers/routes and checking the radian counterpart.
> Successor to [130](130-free5gc-functionality-gap.md) (2026-07-23): confirms
> its verdict, corrects one error, and goes one level deeper (per-IE, per-route,
> per-timer). Work items are numbered **G1–G30** (§8) for picking.

## TL;DR

- The [130](130-free5gc-functionality-gap.md) verdict stands: **radian-rs is
  depth-first on one golden path and matches or exceeds free5gc there**
  (registration/5G-AKA/PDU session/QoS/charging/CM-IDLE/handover/ULCL/IPv6 +
  a native gNB). The deltas below are breadth, robustness, and wire fidelity.
- **Correction to 130:** it claimed "neither stack ships BSF". free5gc 4.2.2
  **does ship a BSF** (`NFs/bsf`, built by the Makefile, `run.sh -bsf`):
  `Nbsf_Management` pcfBindings (UE-IP+DNN+S-NSSAI → serving PCF). New gap.
- **New theme this survey surfaces — wire compatibility.** Several radian NFs
  speak co-designed internal dialects rather than the 3GPP wire format: the
  SMF's N1/N2 content crosses Nsmf as pre-decoded JSON, the UPF pattern-matches
  hardcoded rule IDs + a proprietary SDF syntax, NSSF NSSelection is
  POST-with-body not GET-with-query, NRF discovery invents scalar
  `snssai-sst`/`sd` params. radian NFs interoperate with **each other**; most
  could not serve or be served by a free5gc peer NF one-for-one (§5).
- **New theme — security enforcement vs security plumbing.** radian leads on
  the plumbing (mTLS mesh, CRL, ES256/JWKS, encryption at rest) but the
  enforcement is hollow: `oauth::protect` is applied by **exactly one NF**
  (nf-udr), and the NRF token endpoint checks neither scope nor certificates.
  free5gc wraps every service group of every NF in a scope check (§6.1).
- **Sharpest single operational gap:** there is **no way to provision a
  subscriber** — no UDR `authentication-subscription` route, no webconsole, no
  CLI. Only `RADIAN_UDR_PROVISION_DEMO=1` or an in-process call (§3.4).

Severity: **Major** (blocks a scenario class) · **Moderate** (parity gap on a
shared path) · **Minor** (edge/robustness) · **▲ radian ahead**.
Size: **S** ≈ days · **M** ≈ 1–2 wk · **L** ≈ several wk · **XL** ≈ multi-slice.

## 1. Status of design/130's ledger (what this survey changes)

| 130 said | This survey finds |
|---|---|
| "Neither ships BSF" | **Wrong** — free5gc 4.2.2 ships `NFs/bsf` (G20) |
| NSSF closed ([133](133-nssf-slicing.md)) | Closed for the *radian-internal* shape; not TS 29.531 wire-compatible (POST vs GET), no PDU-session path, no NsiInformation/roaming (G17) |
| ULCL/multi-UPF mostly closed ([134](134-ulcl-multi-upf.md)) | Confirmed; residue = topology config (Phase 3), 1 branch/session, ≤2-hop chains |
| IPv6 ▲ radian ahead ([131](131-ipv6-pdu-sessions.md)) | Confirmed — gtp5g is IPv4-only, free5gc's v6 is signalling-scaffold |
| N2 interface mgmt closed ([132](132-n2-interface-management.md)) | Confirmed for Reset/Overload/ErrorIndication(rx)/RANConfigUpdate; ~20 further NGAP procedures still unhandled, and radian never *emits* ErrorIndication (G8) |
| SBI security ▲ radian ahead | Split verdict: plumbing ▲, enforcement is the sharpest security gap (G1) |
| OAuth/SUCI/EAP-AKA' gaps | Confirmed, now with exact anchors (§3.4, G2/G3) |

## 2. Wire-compatibility deviations (radian ↔ radian only)

These are not missing features — they are **interfaces where radian works
end-to-end against itself but could not swap a peer NF with free5gc's**. Fixing
any of them is a compat/conformance slice, not new capability.

| Interface | Deviation | Anchor |
|---|---|---|
| Nsmf (AMF↔SMF) | N1 SM (NAS-SM) and N2 SM (NGAP transfer IEs) are **never encoded/decoded by the SMF** — pre-decoded JSON fields (`gnbN3Teid` hex etc.); no multipart, no `n2SmInfoType` dispatch. The AMF does all codec work. A UE-initiated **PDU Session Modification Request is misrouted into CreateSMContext** (only Release Complete is recognized in the SM container) | `nf-smf/src/pdu_session.rs:9` (header note), `nf-amf/src/main.rs:3382` |
| N4 (SMF↔UPF) | UPF matches **hardcoded rule IDs** (`UPLINK_FAR_ID=1`, `DOWNLINK_PDR_ID=2`, `PER_FLOW_PDR_BASE=100`, `ULCL_PDR_BASE=400`…) — anything else is silently ignored; SDF filter is proprietary `proto=17;ports=..;dst=..`, **not IPFilterRule** (`permit out ip from any to assigned` is rejected). free5gc's SMF cannot drive radian's UPF, nor vice versa | `crates/pfcp/src/lib.rs:74-101,162-168,202` |
| Nnssf | NSSelection is **POST with JSON body**, spec is GET+query; availability keyed by bare TAC, spec keys by TAI (PLMN+TAC); fail-open on unknown TAC where Go rejects | `crates/sbi-core/src/nnssf.rs:193,99,149` |
| Nnrf-disc | Scalar `snssai-sst`/`snssai-sd` instead of the `snssais` JSON-array param; 5 of ~36 query params | `crates/sbi-core/src/nnrf.rs:389-403` |
| OAuth2 | HS256/ES256 vs Go's RS512; `aud` = NF **type** not target instance ID; no `scope` echoed in response; errors as ProblemDetails not RFC 6749 bodies | `crates/sbi-core/src/oauth.rs:285-316` |
| Namf-comm | Three bespoke **SUPI-keyed** routes, not TS 29.518 `ue-contexts/{ueContextId}`; `/n1-n2-messages` takes **no body** (pages only — cannot carry an N1/N2 container from an SMF) | `nf-amf/src/main.rs:1140` |

## 3. Per-NF gaps

### 3.1 AMF (deep mainline; thin periphery)

Go: `NFs/amf/internal/{ngap,gmm,sbi}` ≈ 28k lines. Rust: `nf-amf` ≈ 4.2k prod
lines. Parity on: NGSetup/InitialUE/NAS transport, full registration + 5G-AKA +
resync + SMC, service request, paging+T3513, N2 handover + Xn path switch
(NH/NCC), dereg both directions, CUC, NGReset/Overload/RANConfigUpdate.

Gaps:
- **NGAP procedures with no handler and no codec support** (fall through the
  `_ => unhandled` arm; zero hits in `crates/ngap`): `UplinkRANStatusTransfer`/
  `DownlinkRANStatusTransfer` (**PDCP SN lost across N2 handover — the one that
  bites**), `NASNonDeliveryIndication`, `InitialContextSetupFailure`,
  `UEContextModificationFailure`, `PDUSessionResourceNotify`,
  `PDUSessionResourceModifyIndication`, `RRCInactiveTransitionReport`,
  `UplinkRANConfigurationTransfer` (SON), NRPPa transport (4 directions),
  Location Reporting (3), UE Radio Capability (3 — so Paging lacks
  `UERadioCapabilityForPaging`), Trace (4), `AMFConfigurationUpdate`,
  `AMFStatusIndication`, `RerouteNASRequest`, `UETNLABindingReleaseRequest`.
  Also: ErrorIndication is parsed (`main.rs:1780`) but **never sent** — Go
  emits one for every malformed/unknown-UE message. → **G8/G9**
- **NAS-MM**: no EAP-AKA' (G3); no Service Reject (failed resume is silently
  dropped, context re-retained, `main.rs:2036`); no 5GMM Status; no
  Notification/T3565; no LADN; no DRX negotiation; Identity Request SUCI-only;
  reject causes limited to #62 + session #26/27/31/70 — no #15 TA-not-allowed /
  #11 PLMN-not-allowed / #7 / #22 congestion (no supportTaiList /
  plmnSupportList exists to check against). → **G10/G12**
- **Missing NAS retransmission timers: T3550 (Registration Accept), T3560
  (Auth Req / SMC), T3570 (Identity Req)** — a lost downlink stalls the
  registration permanently. Rust has T3512/T3513/T3522/T3555 only. → **G7**
- **SBI producer surface**: no Namf_EventExposure (11 event types), Namf_MT,
  Namf_Location, Namf_OAM, AMFStatusChange subscriptions, CreateUEContext /
  UEContextTransfer / RegistrationStatusUpdate / AssignEbiData; N1N2Transfer
  reduced to body-less paging. → **G9/G13**
- **No inter-AMF anything**: no AMF set, GUAMI routing, context transfer, NAS
  reroute (`config/multiAMF` scenarios unrunnable). → **G13**
- **Infra**: hardcoded single PLMN=999/70, TAC, GUAMI, algorithm order
  (`main.rs:45-128`); no SCTP multihoming or notification handling (assoc loss
  is logged, RAN never cleaned up, `main.rs:768`); no per-UE NGAP worker
  scheduler (Go: `ngap/scheduler.go`). → **G5/G26**

▲ radian ahead: indirect data forwarding actually implemented (Go:
`handler.go:351 // Todo: remove indirect tunnel`), TNGRELOCprep/overall guard
timers (absent in Go — a stalled Go handover leaks the target context), CBL
admission pacing ([136](136-come-back-later.md)), implicit-dereg sweep
([66](66-t3512-implicit-dereg.md)), PCF-vs-subscribed UE-AMBR precedence model,
pending AM policy across CM-IDLE, ~35 in-tree e2e tests.

### 3.2 SMF

Parity on: Create/Update/Release SM context, PFCP est/mod/del, DLDR→paging,
VOLTH usage→CHF, PCF SM policy incl. PCF-initiated update, GBR flows→QER/SDF
PDR/URR, session AMBR, DNN/S-NSSAI authorization, type negotiation with #50/#51,
2-hop chains + ULCL branch + indirect forwarding, End Marker on re-point.

Gaps:
- ~~**No PFCP heartbeat loop / RecoveryTimeStamp restart detection**~~
  **liveness CLOSED** ([141](141-pfcp-liveness.md)): the SMF heartbeats every UPF
  (`run_heartbeats`), and on a newer recovery timestamp re-associates and drops
  the stranded sessions (freeing IP/GFBR/UECM) — the *silent-stranding* bug is
  fixed. *Remaining:* PFCP retransmission/dedup transaction layer; SMF still
  client-only on 8805 (single 2s timeout). → **G4** (liveness done)
- **IPAM**: ~~monotonic `AtomicU32`, addresses never released~~ **leak CLOSED**
  ([140](140-smf-ipam-pool.md)): a bounded lazy-reuse `U32Pool` (v4 + v6) with an
  RAII `IpLease` freeing addresses on every failure path; exhaustion → 503/#26.
  *Remaining:* per-(S-NSSAI,DNN,UPF) pools, static pools, per-subscriber static
  IP from UDM, overlap checks (Go: `ue_ip_pool.go` + `lazyReusePool`). → **G6** (leak done)
- **No granted-quota loop**: no VolumeQuota/Volqu, no `updateGrantedQuota` —
  **online charging cannot be enforced at the UPF**; triggers limited to
  VOLTH+FINAL (no ADDITION_OF_UPF / USER_LOCATION_CHANGE / QUOTA_EXHAUSTED /
  validity-time / start-of-SDF). → **G14**
- No BAR; no rule-state model (RULE_INITIAL/UPDATE/REMOVE) or generic
  Remove/Update ops; no URR measurement period / time threshold / quota.
- No SSC modes (Go pins mode 1 in the accept), no Ethernet PDU type, no
  UP security IEs, no ARP/5QI/priority modelling, no NAS QoS-rule/packet-filter
  construction, no PCO/ePCO (DNS/P-CSCF/MTU requests unanswered — DNS pushed
  unconditionally). → **G10/G16**
- No SMContextStatusNotify to AMF; no charging-notification callback (CHF can't
  revoke quota); no UpPathChg event notification to NEF/AF; no OAM
  (`ue-pdu-session-info`, `user-plane-info`) or runtime UPI topology API. → **G15/G22**
- No `uerouting.yaml` equivalent (SUPI-group paths, specificPath, routeProfile,
  PFD-per-app); ULCL: **1 branch/session** (`pdu_session.rs:1687`), chains ≤
  2 hops, no PSA2/ULCL *selection* algorithm (config/DNAI names the anchor);
  no NR-DC dual tunnel. → **G21/G24**
- AMF interaction discovers "first AMF from NRF" not the serving AMF
  (`pdu_session.rs:2257` "single-AMF demo"); paging POST body is `json!({})`.

▲ radian ahead: GFBR admission budget (503→#26), `/refresh-policy` +
`/oam/v1/breakout` mid-session ULCL API (Go's ULCL is setup-time-only),
policy-vs-direct breakout ownership, DNAI→UP-node resolution, SUPI-masked logs,
~2.4k lines of in-proc integration tests.

### 3.3 UPF

Parity on: association-accept + heartbeat-reply, est/mod/del, UE-IP PDI +
CHOOSE F-TEID, downlink FAR/OHC, BUFF/DROP + DLDR + flush, VOLTH URR + TERMR
final, AMBR/MFBR token buckets, Echo reply, End Marker, ULCL/N9.

Gaps (control plane — Go is far more spec-faithful):
- **No association state** (sessions accepted with no association; no purge on
  re-association; no NodeID validation); ~~recovery timestamp regenerated per
  message~~ **pinned at startup now** ([141](141-pfcp-liveness.md) — the UPF no
  longer looks permanently restarting); **no transaction layer** — no
  retransmission of UPF-initiated reports, no request dedup (**a retransmitted
  Establishment allocates a second session+TEID**); no error causes — malformed
  input gets **no PFCP response at all** (`main.rs:214`). → **G4** (recovery-ts pinned; assoc-state/tx-layer/causes remain)
- No BAR (fixed 64-pkt buffer; no notification delay / suggested count); OHR
  ignored (unconditional decap); **GateStatus unenforced**; GBR is ceiling-only;
  precedence written but never evaluated (branch order = PDR id); RemoveFar/
  RemoveUrr/UpdatePdr/QueryUrr unread; no PERIO/duration/quota measurement, no
  packet counts (flags hardcoded TOVOL|ULVOL|DLVOL), fake URSEQN, no
  StartTime/EndTime, no reports in Modification Response. → **G18**
- ~~**Downlink G-PDUs carry no QFI/PDU Session Container**~~ **CLOSED**
  ([139](139-upf-downlink-qfi.md)): `n6::downlink` (v4+v6), the buffered flush,
  and SLAAC RAs now stamp the QFI (matched GBR flow's, else `DEFAULT_QFI`) — the
  one gap all three references agreed on. → ~~**G11**~~ done
- No ICMP/PMTUD generation (TUN MTU 1400 only); no forwarding-policy /
  NetworkInstance routing / per-DNN route install; single N3 socket.
- Datapath scaling: **O(n) linear scans per packet under one global
  `Mutex<UpfState>`** both directions (`lib.rs:707-1114`, `main.rs:292,362`);
  TEID/SEID never reclaimed. gtp5g: 131072-bucket kernel hash. → **G19**

▲ radian ahead: userspace TUN (no out-of-tree kernel module, degrades
gracefully), full IPv6 UP + RA/SLAAC + RS answering, uplink anti-spoofing
(neither Go nor gtp5g), per-flow URR attribution (sum(rating groups) == total),
explicit N9/Egress model, clock-injected rootless tests.

### 3.4 AUSF / UDM / UDR

Parity on: 5G-AKA start/confirm + HXRES*/K_SEAF, Milenage AV generation, SQN
atomic increment + AUTS resync, SDM am/sm/smf-select + subscribe/notify fan-out,
UECM AMF/SMF register/dereg, UDR provisioned-data + policy-data + influenceData,
data-change notify UDR→UDM→subscribers, NRF registration.

Gaps:
- **No SUCI deconcealment at all** — no ECIES Profile A (X25519) or B (P-256),
  **not even the null-scheme parse**: `nudm.rs:388` treats supiOrSuci as the
  SUPI. A privacy-enabled UE cannot authenticate. (Null-scheme live-UE interop
  was [19](19-suci-deconcealment-live-ue.md) — AMF-side; the UDM side is the
  gap.) No `SuciProfile` config, no home-network key store. → **G2**
- **No EAP-AKA'**: zero EAP code; `nf-ausf/src/main.rs:2` doc-comment *claims*
  it — fix the comment or the gap. Go has the full RFC 5448 flow. → **G3**
- **No serving-network authorization** in AUSF — any caller names any SNN and
  gets a K_SEAF bound to it (Go: `IsServingNetworkAuthorized` → 403). Security
  relevant. → **G1-adjacent, folded into G12**
- **No subscriber provisioning surface**: UDR exposes **no
  `authentication-subscription` route**; only `RADIAN_UDR_PROVISION_DEMO=1` or
  in-process `provision_hex`. No webconsole, no CLI. → **G20/G23**
- UDM: 3 of ~20 SDM datasets (missing nssai, trace-data, ue-context-in-*,
  shared-data, aggregate `GET /{supi}`, …); UECM PUT/DELETE-only (no GET, no
  PATCH, no non-3GPP); no ParameterProvision; no EventExposure (real in Go);
  no ConfirmAuth/auth-event persistence; no GPSI↔SUPI translation (nnef.rs:278
  *equates* them); **NRF profile advertises `nudm-ueau` only**
  (`nf-udm/src/main.rs:66`) — SDM/UECM not discoverable by service name. → **G25**
- UDR: no exposure-data class, no ue-policy-set/bdt/pfds/authentication-status/
  identity-data/ODB; no generic subs-to-notify (one hardcoded am-data trigger →
  one fixed UDM, `resourceId` always `"am-data"`, `nudm.rs:235`); policy data
  stored under an **empty PLMN key** (not roaming-partitioned); SDM
  subscriptions in-memory (lost on UDM restart), `monitoredResourceUris`
  ignored. → **G25**

Non-gaps: SoR/UPU are **501 stubs in Go too**; TUAK absent both sides.

▲ radian ahead: redb + AES-256-GCM at rest + KEK/HSM seam (free5gc: plaintext
Mongo); ARPF trait boundary — K never crosses a trait or the wire (Go's UDM
pulls plaintext K over Nudr); UECM stale-registration sweep vs live NRF; SSRF
guard on callback URIs; UE-side AKA + full key hierarchy in `crates/aka`.

### 3.5 PCF / CHF / NSSF / NEF / NRF

**PCF** — parity: SM policy CRUD + partial-delta update, AM policy + update
notify, UDR-sourced policy, PolicyAuthorization create/delete (routing only).
Gaps: **no MediaComponent/AF-QoS** (app-sessions carry routing influence only —
AF-requested QoS unreachable, G24); no GET on sm-policies/am-policies; no
PATCH/events-subscription/pcscf-restoration on app-sessions; no GBR budget pool
(`RemainGbrDL/UL`); no usage monitoring (`UmDecs`); no `AuthorizedDefaultQos`
in session rules; no sponsored connectivity; no BDT (Go real); UEPolicyControl
absent (Go 501 — nominal); no BSF binding registration (G20); UDR influence
intake is **poll-per-create, not push** (no `/nudr-notify` callbacks); no
termination-request notifications; no SuppFeat. ▲ ahead: typed
`Keep/Clear/Set` partial-delta merge (`policy.rs`), ServAreaRes actually
populated (Go TODO), flow→rating-group resolution.

**CHF** — parity: the three ConvergedCharging ops + per-rating-group volume
accumulation. Gaps: **it is a usage accumulator, not a charging function** —
no quota/reservation state machine (MultipleUnitInformation, GrantedServiceUnit,
FinalUnitIndication…), no rating, no ABMF/balance, no **ASN.1 CDR encoding or
CDR files** (JSON in a HashMap), no CGF/FTP export, no recharge endpoints, no
ChargingNotify push. (Diameter Ro/Gy: optional for greenfield.)
SpendingLimit/OfflineOnly: Go 501 — nominal. → **G14/G27**

**NSSF** — parity: registration-time selection + per-TA availability PUT.
Gaps: wire shape (§2); **no PDU-session selection path**; no NsiInformation
(per-slice NRF/NSI id); no CandidateAmfList/TargetAmfSet outputs; no roaming
(home-plmn-id, mappingOfNssai); no ConfiguredNssai/default-configured; flat
rejectedNssai (no InPlmn/InTa split); no availability subscriptions/JSON-Patch;
no consumer-type/PLMN validation. → **G17**

**NEF** — parity: traffic-influence create/delete with the **same routing
split as Go** (single-UE→PCF app-session; group/anyUE→UDR influence data).
Gaps: no GET/PUT/PATCH on subscriptions; no UE-by-IP identification (common AF
case); **both PFD-management surfaces absent** (northbound 3gpp-pfd-management
+ southbound Nnef_PFDManagement with SMF fan-out); no `/nnef-callback` SMF
intake (never learns DNAI changes); no AF notifications back
(notificationDestination/notifCorreId); no RFC 7807 errors; influence doc is a
hand-rolled blob, not `TrafficInfluData`. ▲ ahead: PCF-less direct-to-SMF mode
(`RADIAN_NEF_PCF=none`). → **G22**

**NRF** — parity: register/deregister/heartbeat-TTL/list/discover/token.
Gaps: **no NF-status subscriptions or notifications at all** — nothing in
radian learns of NF churn except polling (Go: REGISTERED/DEREGISTERED/
PROFILE_CHANGED push); no `GET /nf-instances/{id}`; **no profile update after
registration** (PATCH is bound to heartbeat, body discarded — load/capacity/
services frozen at boot); 5 of ~36 discovery params, no complexQuery, no
`limit`/UriList form; profile has no priority/capacity/load/locality/
allowedPlmns/allowedNfTypes (**no load-balancing or authorization-by-profile
possible**) and only `smf_info` (no upf/amf/udm/…Info blocks); in-memory only
(not restartable, no HA); no `/bootstrapping`. Token endpoint: **G1**. → **G28**

## 4. Cross-cutting

### 4.1 SBI authorization is effectively advisory (worst security gap)

Two halves, both required:
1. **Issuance** (`nnrf.rs:314-340`, `oauth.rs:285-316`): no scope validation
   against the producer's `nfServices` (scope copied verbatim into claims — no
   `invalid_scope` path exists), no X.509 chain / URI-SAN / nfType-vs-profile
   checks (Go verifies the consumer's cert against the root CA, DNSName=nfType,
   SAN opaque-id=nfInstanceId), `aud` = NF type ⇒ a token minted for "UDR" is
   valid at any UDR forever-scoped to nothing.
2. **Enforcement**: `grep -rn "oauth::protect"` → **`nf-udr/src/main.rs:99`
   only**. AMF, SMF, AUSF, UDM, PCF, CHF, NSSF, NEF, NRF serve unauthenticated
   even with `RADIAN_SBI_SECRET`/`RADIAN_SBI_OAUTH` set. free5gc:
   `util_oauth.NewRouterAuthorizationCheck(serviceName)` on every service group
   of every NF, validating token scope against the invoked service.
mTLS partially compensates (peer must hold a core-CA cert) — but any enrolled
NF can then call anything: no least-privilege between NFs. → **G1**

### 4.2 Configuration

**Zero config files in the repo** (only 3 BDD fixture YAMLs for free-ran-ue).
Every NF reads env vars inline in `main.rs`; no schema/validation, no logger
config, no CLI flags (`clap` only in radian-pki). free5gc: 20 YAML files with
per-NF `pkg/factory` validated schemas, `multiAMF/`, `multiUPF/`,
`uerouting.yaml`. Config-driven UP topology is also [134](134-ulcl-multi-upf.md)
Phase 3. → **G5**

### 4.3 Observability & deployment

No Prometheus/metrics endpoint anywhere (free5gc: per-NF metrics servers); no
OAM read surfaces beyond `/oam/v1/{overload,cbl,breakout}`; no runtime
UE-context inspection. No Makefile/run.sh/force_kill.sh, no CI workflow, no
container story, no log/pid management (free5gc: all of these + pcap capture
flags). radian needs no gtp5g kernel module — its heaviest deploy dependency
is `sudo ip netns` for BDD. → **G26/G29**

### 4.4 Test-scenario coverage vs free5gc's suite

free5gc scenarios with no radian BDD equivalent: EAP-AKA', multi-AMF +
NAS reroute, duplicate registration, non-3GPP (N3IWF/TNGF), dual connectivity
(TestDC/DynamicDC/XnDCHandover), AF-influence is covered (`@nef`) but
TestULCLAndMultiUPF-style multi-branch topologies are not (1 branch/session).
▲ radian's suite is CI-runnable without an external emulator; free5gc's needs
root + namespaces + its UE emulator.

## 5. Non-gaps (absent or stubbed on BOTH sides)

SoR/UPU protection (Go 501) · Nchf_SpendingLimitControl + OfflineOnlyCharging
(Go 501) · Npcf_UEPolicyControl (Go 501) · Nsmf EventExposure subscription CRUD
(Go 501) · SMF RetrieveSmContext / SendMoData / HR-roaming V-SMF (Go 501) ·
PWS (Go stubs) · TUAK (both Milenage-only) · reflective QoS · EPS interworking
/ N26 · GTP-U Error Indication · PFCP PFD-mgmt / Node Report / Session-Set-
Deletion / Assoc Update (Go logs "not supported") · outgoing GTP-U Echo ·
Framed Routes · SCP/SEPP/LMF/NWDAF/SMSF (BSF is **not** on this list — see G20).

## 6. Where radian-rs leads (unchanged or strengthened since 130)

mTLS mesh + CRL hot-reload + radian-pki · encryption-at-rest + ARPF boundary
(K never on the wire; free5gc: plaintext Mongo, K crosses Nudr) · full IPv6 UP
with SLAAC/RA (gtp5g v4-only) · userspace UPF + uplink anti-spoofing · native
gNB with CU/DU F1 split · indirect data forwarding + handover guard timers
(Go: TODO comment) · CBL admission pacing · implicit-dereg sweep · UECM
stale-registration eviction · GFBR admission · mid-session ULCL API · typed
policy partial-delta · deeper NAS timer machine (T3512/13/22/55) · CI-runnable
BDD tiers · in-proc e2e test volume.

## 7. Risks & open questions

- **Wire-compat vs greenfield tension (the pivot question of this survey).**
  Closing §2 means adopting 3GPP wire shapes on Nsmf (multipart N1/N2), N4
  (generic rule tables + IPFilterRule), Nnssf (GET), Nnrf (param set) — real
  refactors whose payoff is *mix-and-match interop with foreign NFs*. If
  radian's product is a vertically-integrated core+RAN, G30 (interop tiers
  against free5gc peers) may matter more as a *conformance oracle* than as a
  deployment mode. Decide before sinking L-sized effort into G16/G18.
- **G1 first.** Every new SBI route added before enforcement exists widens the
  unauthenticated surface. Small, self-contained, already-designed
  ([46](46-sbi-oauth.md)/[55](55-sbi-asymmetric-oauth.md) plumbing exists).
- **IPAM release semantics** interact with CM-IDLE retained contexts and ULCL
  second anchors — releasing on the wrong path re-allocates a live address.
- **SUCI Profile A/B** needs the home-network private key in the UDM's store —
  touches subscriber-db schema + radian-pki provisioning, not just crypto.
- **free5gc 4.2.2 is now the pinned oracle** — cite it (not `~/free5gc`
  HEAD) in future gap-closure designs.

## 8. Work-item catalog (pick from here)

P0 = do before adding surface · P1 = robustness/parity on shared paths ·
P2 = unlocks scenario classes · P3 = breadth/ecosystem.

| ID | Item | Sev | Size | Pri | Notes |
|---|---|---|---|---|---|
| **G1** | **Enforce OAuth across all NFs + real token issuance** — `oauth::protect` (or successor) on every service group; scope validated against producer services at the NRF; cert/nfType checks; instance-scoped `aud` | Major (security) | M | **P0** | §4.1; builds on [46](46-sbi-oauth.md)/[55](55-sbi-asymmetric-oauth.md) |
| **G2** | **SUCI deconcealment** — null-scheme parse + ECIES Profile A/B in UDM; home-net key in subscriber-db; `SuciProfile` config | Major | M | **P1** | §3.4; blocks any privacy-enabled UE |
| **G3** | **EAP-AKA'** — AUSF eap-session routes + RFC 5448 PRF; UDM `EAP_AKA_PRIME` AV type; AMF EAP relay; fix the misleading doc-comment now | Moderate | M | P1 | 130's P3-6 confirmed |
| **G4** | **PFCP liveness both sides** — SMF heartbeat loop + RecoveryTimeStamp restart detection + re-association + retransmission; UPF association state + pinned recovery timestamp + tx/rx transactions + error causes | Major (robustness) | M | **partial** | §3.2/3.3; **liveness + restart recovery DONE** ([141](141-pfcp-liveness.md)): heartbeat loop, pinned recovery-ts, drop-stranded-sessions. Remaining: UPF assoc-state, tx/dedup layer, error causes |
| **G5** | **Config files** — per-NF YAML (serde) replacing inline env reads; PLMN/TAC/GUAMI/tai-list/algorithm order/timers; keep env as override | Moderate | M | **P1** | §4.2; prerequisite-ish for G13/G21/G24 |
| **G6** | **IPAM** — allocate/release pools per (S-NSSAI,DNN,UPF), static pools, per-subscriber static IP from UDM | Major (leak) | S–M | **partial** | §3.2; **leak DONE** ([140](140-smf-ipam-pool.md)): bounded lazy-reuse pool + RAII release. Remaining: per-DNN/static pools, static IP from UDM |
| **G7** | **AMF NAS retransmission timers T3550/T3560/T3570** (+ Service Reject on failed resume) | Moderate | S | **P1** | lost downlink = permanently stalled registration |
| **G8** | **NGAP robustness pack** — emit ErrorIndication; handle InitialContextSetupFailure, NASNonDeliveryIndication, RAN Status Transfer relay (lossless HO), UEContextModificationFailure | Moderate | M | P1 | §3.1 |
| **G9** | AMF standard SBI: TS 29.518 ue-contexts resource model + real N1N2MessageTransfer (N1/N2 containers) + Namf_EventExposure | Moderate | L | P2 | prerequisite for G13; overlaps G16 |
| **G10** | NAS-SM fidelity: route UL 5GSM by request type (fix Modification→Create misroute), PCO/ePCO answers, SSC mode IE, richer 5GMM/5GSM causes | Moderate | M | P1 | §3.2 |
| ~~**G11**~~ | ~~**UPF downlink QFI marking**~~ — **DONE** ([139](139-upf-downlink-qfi.md)): `n6::downlink` v4+v6 + buffered flush + SLAAC RAs stamp the QFI (matched GBR flow's, else `DEFAULT_QFI`); N9-chain final hop deferred | Moderate | **S** | ✓ | closed the one gap all three references agreed on |
| **G12** | Admission checks: supportTaiList/plmnSupportList (#15/#11), AUSF serving-network authorization | Moderate | S | P1 | config from G5 |
| **G13** | Multi-AMF: AMF set, GUAMI routing, UEContextTransfer/RegistrationStatusUpdate, RerouteNASRequest | Moderate | L | P2 | 130's P-item confirmed; needs G9 |
| **G14** | Online charging: CHF quota grant (MultipleUnitInformation/FUI) + SMF VolumeQuota loop + UPF VOLQU + charging-notify callback | Moderate | M–L | P2 | §3.2/3.5 |
| **G15** | SMContextStatusNotify + UpPathChg event notification (SMF→AMF, SMF→NEF/AF) | Minor–Mod | S | P2 | completes the NEF story ([135](135-nef-af-traffic-influence.md)) |
| **G16** | **Nsmf wire fidelity** — multipart N1/N2 containers, SMF-side NAS-SM + N2 transfer-IE codecs, n2SmInfoType/hoState | Moderate (interop) | **L** | P2 | §2; decide via §7 pivot question first |
| **G17** | NSSF conformance: GET+query wire shape, PDU-session path, NsiInformation, TAI keying, rejected-in-PLMN/TA split | Moderate | M | P2 | §3.5 |
| **G18** | **N4 generic rule engine** — real PDR/FAR/QER/URR tables, precedence evaluation, IPFilterRule SDF parser, GateStatus, BAR, OHR honoured | Major (interop) | **L** | P2 | §2/§3.3; the other half of the pivot question |
| **G19** | UPF datapath scaling: TEID/UE-IP hash indexes, drop the global mutex (sharded or lock-free), TEID/SEID reclaim | Moderate | M | P2 | O(n)+Mutex per packet today |
| **G20** | **BSF** — new `nf-bsf` (Nbsf_Management pcfBindings) + PCF binding registration + SMF/NEF binding query | Moderate | M | P2 | the 130 correction; unlocks AF→PCF lookup |
| **G21** | UP topology Phase 3 — config-driven graph (G5 format), >2-hop chains, >1 ULCL branch, PSA/ULCL selection | Moderate | L | P2 | [134](134-ulcl-multi-upf.md) Phase 3 |
| **G22** | NEF completeness: subscription GET/PUT/PATCH, UE-by-IP, PFD management (north+south + SMF fan-out), AF notifications, RFC 7807 | Moderate | M–L | P2 | §3.5 |
| **G23** | **Subscriber provisioning API** — UDR authentication-subscription CRUD (+ minimal admin UI or CLI over it) | Moderate (ops) | M | **P2** | §3.4; 130's P4-9, now sharper: *no* path exists |
| **G24** | PCF depth: MediaComponent/AF-QoS in PolicyAuthorization, GBR budget pool, usage monitoring, UDR push callbacks, AuthorizedDefaultQos | Moderate | L | P2 | needed for AF-QoS scenarios |
| **G25** | UDM/UDR breadth: nssai + ue-context-in-* SDM datasets, UECM GET/PATCH, EventExposure, GPSI↔SUPI identity-data, generic subs-to-notify, PLMN-partitioned policy data, advertise nudm-sdm/uecm in NRF profile | Moderate | M–L | P2 | the profile-advertising fix is **S** — do early |
| **G26** | Observability: Prometheus metrics per NF + OAM read surfaces (registered-ue-context, pdu-session-info) | Moderate | M | P2 | §4.3 |
| **G27** | CHF CDR: ASN.1 BER CHFRecord (TS 32.298) + CDR files + CGF export | Minor–Mod | M | P3 | 130's P4-10 |
| **G28** | NRF: status subscriptions + notify push, profile PATCH, capacity/load/locality + per-NF info blocks, param-complete discovery, persistence | Moderate | M–L | P2–P3 | subscriptions half is the valuable half |
| **G29** | Deployment: Makefile/justfile, run/kill scripts, CI workflow, container images | Moderate (ops) | S–M | P3 | §4.3 |
| **G30** | Non-3GPP access: N3IWF (IKEv2/EAP-5G/xfrm) then TNGF (+RADIUS); AMF access-type dimension | Major | **XL** | P3 | 130's P3-8; only if WLAN access is a product goal |

Suggested first wave by value-per-effort: **G1 → ~~G11~~ (done, [139](139-upf-downlink-qfi.md))
→ ~~G6~~ (leak done, [140](140-smf-ipam-pool.md)) → ~~G4~~ (liveness done,
[141](141-pfcp-liveness.md)) → G7 → G2 → G23 → G5**, then decide the §7 pivot
question before committing to G16/G18-class interop refactors.

## Sources

- Survey transcripts: six per-area agent reports (2026-08-07) over
  `~/free5gc-4.2.2/NFs/{amf,smf,upf,ausf,udm,udr,pcf,chf,nssf,nef,nrf,bsf,
  n3iwf,tngf}`, `webconsole/`, `config/`, `test.sh`, gtp5g sources; and
  radian `nf/*/src`, `crates/{sbi-core,pfcp,gtpu,n6,nas,ngap,aka,
  subscriber-db}/src`, `ran/gnb`, `bdd/`.
- Anchors cited inline are to those trees at survey date; re-verify line
  numbers before coding against them.
- Predecessor: [130-free5gc-functionality-gap.md](130-free5gc-functionality-gap.md)
  (method + 3GPP TS references there still apply).
