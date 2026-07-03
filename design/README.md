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
