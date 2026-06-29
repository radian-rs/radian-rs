# radiant-rs — Design Notes

`radiant-rs` is a greenfield Rust implementation of a 3GPP 5G/6G core (5GC).

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
