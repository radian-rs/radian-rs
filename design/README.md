# radian-rs — Design Notes

`radian-rs` is a greenfield Rust implementation of a 3GPP 5G/6G core (5GC).

These notes capture the early architecture research that scopes the encoding/codec
surface of the project and assesses build feasibility.

## Index

| Doc | Topic |
|---|---|
| [01-asn1-rust-gap-analysis.md](01-asn1-rust-gap-analysis.md) | Rust ASN.1 ecosystem vs. 3GPP needs — how big is the gap? |
| [02-nf-interface-encoding-map.md](02-nf-interface-encoding-map.md) | Full NF / interface ASN.1-vs-JSON split + phased build plan |
| [03-n2-ngap-slice.md](03-n2-ngap-slice.md) | First protocol slice: AMF N2 (NGAP/SCTP) + NAS decode |
| [04-sbi-spine-nrf.md](04-sbi-spine-nrf.md) | SBI spine: HTTP/2 + JSON in sbi-core, and the NRF (TS 29.510) |
| [05-aka-authentication.md](05-aka-authentication.md) | 5G-AKA: AUSF + UDM + the `aka` crypto crate (Milenage, TS 33.501) |
| [06-amf-auth-join.md](06-amf-auth-join.md) | AMF authentication: joins N2 + SBI — discover AUSF, run 5G-AKA, K_SEAF |
| [07-registration-complete.md](07-registration-complete.md) | Complete registration: K_AMF, NAS security, Security Mode + Registration Accept |
| [08-n4-pfcp.md](08-n4-pfcp.md) | User-plane start: N4 PFCP (SMF↔UPF) association + heartbeat via rs-pfcp |
| [09-pfcp-session.md](09-pfcp-session.md) | PFCP Session Establishment: SMF provisions PDR/FAR, UPF allocates N3 F-TEID |
| [10-subscriber-db.md](10-subscriber-db.md) | Subscription store: SubscriberDb/ArpfKeyStore traits + redb persistence (K isolated) |
| [11-gtpu-datapath.md](11-gtpu-datapath.md) | GTP-U datapath: N3 uplink decap, UPF serves N4 + N3, TEID-to-session routing |
| [12-credential-hardening.md](12-credential-hardening.md) | Credential store hardening: gate demo subscriber, redb file 0600 (PR #11 review) |
| [13-encryption-at-rest.md](13-encryption-at-rest.md) | Encryption-at-rest: AES-256-GCM for K/OPc, KEK-injected (HSM seam) |
| [14-pfcp-session-modification.md](14-pfcp-session-modification.md) | PFCP Session Modification: install downlink Outer Header Creation (gNB F-TEID) |
| [15-smf-pdu-session.md](15-smf-pdu-session.md) | SMF as a real NF: Nsmf_PDUSession (Create/Update SMContext) drives N4 establishment + modification |
| [16-amf-pdu-session-leg.md](16-amf-pdu-session-leg.md) | AMF leg: UE NAS-SM → discover SMF (NRF) → CreateSMContext; SMF NRF registration; PR#16 review fixes |
| [17-n2-pdu-session-setup.md](17-n2-pdu-session-setup.md) | N2 PDU Session Resource Setup: N2 SM-info transfer-IEs, learn gNB F-TEID → UpdateSMContext |
| [18-n6-forwarding.md](18-n6-forwarding.md) | N6 forwarding: SMF UE-IP allocation, UPF routes downlink by UE IP, real TUN datapath (N3↔N6) |
| [19-suci-deconcealment-live-ue.md](19-suci-deconcealment-live-ue.md) | Live-UE registration: SUCI→SUPI null-scheme deconcealment + replay UE security capability (free-ran-ue interop) |
| [20-live-pdu-session-signaling.md](20-live-pdu-session-signaling.md) | Live PDU-session signaling: configurable UPF bind + post-registration Configuration Update Command |
| [21-n1-sm-pdu-session-accept.md](21-n1-sm-pdu-session-accept.md) | N1 SM PDU Session Establishment Accept: real 5GSM accept (IP/QoS/AMBR/S-NSSAI/DNN) → live UE completes |
| [22-bdd-datapath.md](22-bdd-datapath.md) | Netns datapath BDD test: cucumber `bdd/` crate drives PFCP+GTP-U through a real UPF+N6 TUN, verifies an ICMP round trip |
| [23-bdd-sim-e2e.md](23-bdd-sim-e2e.md) | Simulator-driven e2e BDD (`@sim`): free-ran-ue gNB/UE + full core → registration → PDU session → ping; AUSF self-registers |
| [24-db-subscriber-nf.md](24-db-subscriber-nf.md) | DB design study: subscriber (UDR) vs NF-profile (NRF) storage — RDB vs NoSQL vs embedded, staged path (redb → Postgres+JSONB; NRF stays DB-less) |
| [25-nrf-heartbeat-expiry.md](25-nrf-heartbeat-expiry.md) | NRF soft state: heartbeat-TTL eviction, assigned heartBeatTimer, register_and_maintain loops in AUSF/SMF |
| [26-udr-nudr-relocation.md](26-udr-nudr-relocation.md) | Subscriber store behind nf-udr over Nudr: SQN split from encrypted creds, AM/SM/SMF-selection JSON documents, stateless UDM (K never on the wire) |
| [27-smf-subscription-data.md](27-smf-subscription-data.md) | SMF reads sm-data/smf-select-data via Nudm_SDM: DNN authorization (403, no N4), subscribed S-NSSAI + session AMBR drive the N1 accept |
| [28-requested-dnn.md](28-requested-dnn.md) | UE-requested DNN: parse the UL NAS Transport 0x25 IE, drive CreateSMContext + N1 accept with it (default `internet` when omitted) |
| [29-pdu-session-reject.md](29-pdu-session-reject.md) | 5GSM PDU Session Establishment Reject: SMF 403 → cause #27 (else #31), NAS-protected DL NAS Transport; negative BDD scenario |
| [30-reject-backoff-timer.md](30-reject-backoff-timer.md) | T3396 back-off IE on the reject: GprsTimer3 encoding (finest-fitting unit, round up), 600s on cause #27, none on #31 |
| [31-requested-snssai.md](31-requested-snssai.md) | UE-requested S-NSSAI: parse the 0x22 IE, slice-keyed subscription validation (403 SNSSAI_DENIED/DNN_DENIED ProblemDetails), 5GSM cause #70 |
| [32-allowed-nssai.md](32-allowed-nssai.md) | Allowed NSSAI at registration: Nudm_SDM am-data, 0x15 IE in the Registration Accept (fail-open), local slice admission at PDU establishment |
| [33-nssai-intersection.md](33-nssai-intersection.md) | Requested-NSSAI intersection: 0x2F IE parsed, allowed = requested ∩ subscribed, rejected NSSAI IE 0x11 (cause: not available in PLMN) |
| [34-registration-reject-62.md](34-registration-reject-62.md) | Registration Reject 5GMM cause #62 when no requested slice is subscribed: rejected NSSAI (0x69) attached, UE context released |
| [35-ue-context-release.md](35-ue-context-release.md) | NGAP UE Context Release Command after the #62 reject (UE-NGAP-IDs pair + NAS cause); multi-PDU downlink answers |
| [36-reg-reject-t3346.md](36-reg-reject-t3346.md) | T3346 back-off IE on the Registration Reject: GprsTimer2 encoding (2s/1min/decihour units), 600s on cause #62 |
| [37-deregistration.md](37-deregistration.md) | UE-initiated deregistration: PFCP Session Deletion, Nsmf ReleaseSMContext, Deregistration Accept (unless switch-off), UEContextReleaseCommand |
| [38-network-dereg.md](38-network-dereg.md) | Network-initiated dereg: UDR DELETE → AMF callback (namf-callback :8001, UE_DIRECTORY) → Deregistration Request (UE terminated) + full teardown |
| [39-t3522.md](39-t3522.md) | T3522: dereg accept-wait, 6s retransmissions (5 sends) then abort; DeregCmd channel, stale-expiry no-ops; live-traced vs free-ran-ue |
| [40-uecm.md](40-uecm.md) | Nudm_UECM serving-AMF tracking: amf-3gpp-access context data in the UDR, withdrawal notifies the stored deregCallbackUri, purge on dereg |
| [41-smf-uecm.md](41-smf-uecm.md) | SMF-side Nudm_UECM (smf-registrations per PDU session, register on create / purge on release) + config-derived AMF callback advertise address |
| [42-uecm-expiry.md](42-uecm-expiry.md) | UECM stale-registration expiry: UDR sweep evicts context data whose serving NF is gone from the NRF (reuses NRF heartbeat), fail-safe on unreachable NRF |
| [43-multi-pdu-ue-ambr.md](43-multi-pdu-ue-ambr.md) | Multiple PDU sessions per UE (sm_refs keyed by psi, release all on dereg) + UE-AMBR from am-data → NGAP UEAggregateMaximumBitRate IE |
| [44-smf-selection.md](44-smf-selection.md) | AMF-side SMF selection by (S-NSSAI, DNN): NRF profile smfInfo + filtered discovery, AMF stores the selected SMF base per session (modify/release hit the same one) |
| [45-per-flow-qos.md](45-per-flow-qos.md) | Per-flow QoS (5QI/ARP/GBR): NGAP QosFlow list in the N2 transfer + NAS Authorized QoS flow descriptions IE (0x79) in the N1 accept, subscription-driven; GBR flow live-verified |
| [46-sbi-oauth.md](46-sbi-oauth.md) | SBI OAuth2 access tokens (TS 33.501): NRF token endpoint, HS256 JWT, UDR enforced via oauth::protect, secretless TokenSource; opt-in via RADIAN_SBI_SECRET |
| [47-pcf-smpolicy.md](47-pcf-smpolicy.md) | Real PCF — Npcf_SMPolicyControl (TS 29.512): sbi_core::npcf policy engine + PcfClient, SMF sources SM policy (AMBR + QoS flows) from the NRF-discovered PCF, deletes on release, falls back to sm-data when no PCF; shared QosFlowPolicy types |
| [48-pcf-udr-policy.md](48-pcf-udr-policy.md) | PCF policy from the UDR (Nudr policy-data, TS 29.519 — DataSet::Policy, per-subscriber, PolicyConfig-shaped doc, local fallback) + Npcf_SMPolicyControl_Update: PCF re-reads UDR on update, SMF refresh-policy trigger re-authorizes a live session; UPF/RAN propagation deferred |
| [49-upf-ambr-qer.md](49-upf-ambr-qer.md) | Session AMBR onto the user plane: SMF installs it as an N4 QER (Create at establishment, Update QER on refresh); UPF polices uplink+downlink with a clock-injected token bucket in the n6 datapath (RateLimited drop); a mid-session change re-rates the policer live. Per-flow GBR + N2/N1 modify still deferred |
| [50-n2n1-pdu-modify.md](50-n2n1-pdu-modify.md) | Mid-session QoS change to the RAN/UE: ngap PDU Session Resource Modify (session AMBR + add-or-modify flows + N1) + nas PDU Session Modification Command (0xCB); AMF namf-comm route → per-association task builds the protected N1 + N2 modify (UeCmd::ModifyPolicy); SMF refresh-policy notifies the serving AMF. Unit/integration-pinned (not @sim-exercised) |
| [51-upf-per-flow-gbr.md](51-upf-per-flow-gbr.md) | Per-flow GBR enforcement at the UPF: SMF installs a per-flow QER (MBR=MFBR) + a classifier PDR (SDF filter = proto+port range) per GBR flow; UPF classifies each packet (transport_key) and polices it against the matched flow's MFBR bucket, else the session AMBR. QosFlowPolicy gains a packet filter; demo = UDP 5000–5010. Establishment-time only; mid-session per-flow re-rate + GFBR/URR deferred |
| [52-upf-per-flow-modify.md](52-upf-per-flow-modify.md) | Mid-session per-flow QoS changes at the UPF: session_flow_modification_request (Create/Update/Remove QER+PDR, stable ids per QFI); handle_n4 applies remove→create→update; SMF refresh-policy diffs old vs new flows (diff_flows) and drives it. RAN/UE add-or-modify already covered by design/50; QoS-flow release toward gNB/UE still deferred |
| [53-qos-flow-release.md](53-qos-flow-release.md) | RAN/UE QoS-flow release: ngap modify gains an N2 QosFlowToReleaseList (cause 5GC-generated), nas modification command appends an N1 delete-flow-description (opcode 2) per released QFI; AMF ModifyPolicy.released_qfis threads them through; SMF refresh-policy computes the fully-gone GBR QFIs and sends releasedQfis. Finishes the release path (design/52) |
| [54-gfbr-urr.md](54-gfbr-urr.md) | GFBR admission control (SMF budget + reserve/release; refuse a session whose GFBR exceeds it → 503 → 5GSM #26; RADIAN_SMF_GFBR_BUDGET_MBPS) + URR usage reporting (UPF session-level volume URR, counts admitted bytes, VolumeMeasurement in the deletion response; SMF logs it). Establishment-time admission + at-deletion reporting; per-flow URRs/thresholds/Nchf deferred |
| [55-sbi-asymmetric-oauth.md](55-sbi-asymmetric-oauth.md) | Asymmetric SBI token signing (ES256/P-256 + JWKS): NRF signs tokens with a private key + serves /oauth2/jwks, resource servers verify via a fetched+cached JWKS (TokenVerifier::Jwks) so a compromised NF can't forge tokens; RADIAN_SBI_OAUTH=asymmetric. HS256 shared-secret mode (design/46) retained. Mutual TLS still deferred |
| [56-sbi-mtls.md](56-sbi-mtls.md) | SBI mutual TLS (TS 33.501 §13.1): sbi_core::tls (TlsIdentity load PEM certs, ServerConfig requires+verifies client cert via WebPkiClientVerifier, run_tls over tokio-rustls+hyper-util; reqwest mTLS client) — rustls **ring** backend (aws-lc-rs unavailable offline). Opt-in on the UDR↔UDM exemplar (RADIAN_UDR/UDM_TLS_DIR). Extending to the NRF/other NFs + rotation/revocation deferred |
| [57-sbi-mtls-mesh.md](57-sbi-mtls-mesh.md) | Full-core mTLS mesh: a process-wide SBI transport (configure_transport/sbi_client/sbi_scheme/sbi_base from one shared RADIAN_SBI_TLS_DIR) so every NF both serves and dials over mTLS; every client constructor uses sbi_client(), registration advertises scheme=sbi_scheme(), NfProfile::service_base() drives discovered client transports (https propagates through NRF discovery). All 7 NFs served via run_tls; replaces design/56 per-NF envs. Live-verified AUSF→UDM→UDR chain over mTLS. Rotation/revocation + PKI bootstrap tool deferred |
| [58-pki-bootstrap-crl.md](58-pki-bootstrap-crl.md) | PKI bootstrap + rotation/revocation: `tools/radian-pki` (init/revoke/rotate over an openssl-ca database — v3 leafs, dual EKU, SAN, chmod-600 keys, real CRL) so a live mTLS core is one `radian-pki init`; sbi_core::tls loads `ca.crl` (fail-closed) and enforces it on BOTH verifiers (revoked client refused at the handshake, revoked server refused by the dialer); `tls::serve` hot-reloads a rotated cert / regenerated CRL on the next accepted connection — live-verified revoke (curl exit 56, no restart) + rotate (serial 1005→1007 live). OCSP/CA-rotation deferred |
| [59-nchf-charging.md](59-nchf-charging.md) | Converged charging: per-flow volume URRs (PER_FLOW_URR_BASE+qfi, partitioned counting — each byte under exactly one URR), session-URR volume threshold → UPF-initiated **Session Report Request** (delta since last report; deletion reports the unreported remainder — no double-billing); SMF N4 rebuilt full-duplex (reader task + pending-map transact) to receive them, acks + relays as Nchf updates; new **nf-chf** (:8007, `sbi_core::nchf`, TS 32.290/32.291 trimmed) keeps CDRs per rating group (0=session, else QFI); SMF as CTF: Nchf create/update/release per PDU session; RADIAN_SMF_USAGE_THRESHOLD_BYTES. Live-verified exact billing (800/540). Quota management, per-flow thresholds, CDR export deferred |
| [60-guti-reregistration.md](60-guti-reregistration.md) | 5G-GUTI re-registration + Identity Response (registration-lifecycle audit slice 1): GUTI_DIRECTORY (5G-TMSI→SUPI) recorded at Registration Accept (fresh GUTI supersedes; survives UE-initiated dereg, dropped on withdrawal); registration_identity classifies Supi/GutiTmsi/Unknown and keeps sec caps + requested NSSAI for the resume; a GUTI hit re-authenticates (fresh 5G-AKA), a miss falls back to Identity Request — whose **Identity Response now has a handler** (was a silent dead end) resuming at authentication. nas: identity_response_suci/supi_from_identity_response, registration_request_with_guti/guti_tmsi_from_registration_request. Security-context reuse (ngKSI), AUTS resync, T3512 deferred |
| [61-sqn-resync.md](61-sqn-resync.md) | SQN resynchronisation / AUTS (audit slice 2): Authentication Failure was unhandled → a drifted-SQN UE could never register. aka compute_auts (USIM: (SQNms⊕AK*)‖MAC-S, f1*/f5*, AMF*=0) + sqn_ms_from_auts (ARPF: verify MAC-S → SQNms, None on mismatch); subscriber-db ArpfKeyStore::resync_sqn adopts the UE SQN (redb-persisted); SBI chain nudr resync endpoint → nudm relay → **nausf resynchronizationInfo in the authenticate request** (relays to UDM before fetching fresh AV, TS 29.509); AMF on_authentication_failure arm resyncs ONCE (resync_attempted guard) via AmfAuth::resync then re-challenges, else aborts+releases; nas authentication_failure_synch/authentication_failure_info (cause #21). Live-verified 403 (bogus AUTS refused at ARPF through AUSF→UDM→UDR) + happy path through real SBI servers. Algorithm negotiation/ngKSI, T3512 deferred |

## One-paragraph summary

For a 5G **core**, the ASN.1 dependency is small and is *not* the bottleneck:
~90% of the 5GC is HTTP/2 + JSON (the Service-Based Interfaces), and the only
ASN.1 the core proper needs is **NGAP** (N2), shared by the AMF (full PDU set)
and SMF (the N2-SM-info transfer-IE subset). Working Rust NGAP codecs already
exist (`oxirush-ngap`; or generate from TS 38.413 via `rasn` / `rasn-compiler`).
Everything else binary in the core is non-ASN.1 TLV: NAS (N1), PFCP (N4),
GTP-U (N3/N9). The RAN side (RRC/F1AP/E1AP/XnAP) is where ASN.1 cost would
explode — a separate, project-sized effort.

> Research dates: 2026-06-28. Spec/TS numbers are release-dependent; re-verify
> against the 3GPP release being targeted before locking interfaces.
