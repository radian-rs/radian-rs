# Architecture

radian-rs is a Cargo workspace. Reusable protocol logic lives in library
**crates** under `crates/`; each network function is a thin binary under `nf/`
that wires those crates to sockets.

## Network functions

Each NF is its own `tokio` binary. The ones that carry the end-to-end flow:

| NF | Binary | Role | Interfaces |
|----|--------|------|------------|
| **NRF** | `nf-nrf` | NF discovery + registration | SBI |
| **AMF** | `nf-amf` | Access & Mobility Management | N2 (NGAP/SCTP), N1 (NAS), SBI |
| **AUSF** | `nf-ausf` | Authentication Server | SBI |
| **UDM** | `nf-udm` | Unified Data Management | SBI |
| **SMF** | `nf-smf` | Session Management | SBI, N4 (PFCP) |
| **UPF** | `nf-upf` | User Plane | N4 (PFCP), N3 (GTP-U), N6 (TUN) |

`nf-udr` and `nf-pcf` exist as scaffolding for later work.

The **UPF is the only NF with no SBI** — it is pure binary TLV, controlled over
N4 and forwarding over N3/N6. Every other NF speaks the Service-Based Interface.

## Interfaces

```
        UE
        │  N1 (NAS)         ┌──────┐  SBI    ┌──────┐
   ┌────┴────┐   N2 (NGAP)  │ AUSF │────────▶│ UDM  │
   │  gNB    │─────────────▶│ AMF  │────────▶└──────┘
   └────┬────┘   SCTP :38412│      │  SBI ▲
        │  N3 (GTP-U)       └──┬───┘      │
        │  :2152          SBI  │          │ discover via NRF
        ▼                      ▼          │
   ┌─────────┐   N4 (PFCP)  ┌──────┐   ┌──────┐
   │  UPF    │◀─────────────│ SMF  │   │ NRF  │
   │ N6 TUN  │   :8805      └──────┘   └──────┘
   └────┬────┘
        │ N6
        ▼
   data network
```

- **N1 (NAS, TS 24.501)** — the UE↔AMF signalling layer, tunnelled inside NGAP.
  Binary TLV, split into 5GMM (mobility) and 5GSM (session) messages.
- **N2 (NGAP, TS 38.413)** — gNB↔AMF over SCTP (:38412), APER-encoded ASN.1.
- **N3 (GTP-U, TS 29.281)** — gNB↔UPF user data over UDP (:2152).
- **N4 (PFCP, TS 29.244)** — SMF↔UPF session control over UDP (:8805).
- **N6** — the UPF's link to the data network, a Linux TUN device.
- **SBI** — the HTTP/2 + JSON service bus between the control-plane NFs.

## The SBI transport

Service-Based Interfaces in radian-rs run over **HTTP/2 cleartext (h2c)** with
JSON bodies. `crates/sbi-core` provides the server (`axum`) and the client
(`reqwest` with HTTP/2 prior knowledge), plus the NRF, AUSF, and UDM service
modules. JSON follows the 3GPP OpenAPI conventions (camelCase field names).

> SBI is **unauthenticated** by design at this stage — no TLS, no OAuth2. This
> is a known, documented gap (TS 33.501 hardening) and relies on running the NFs
> on a trusted segment. The same posture applies to N4 and N3, which rely on
> network isolation or IPsec that is not yet implemented.

## Crates

| Crate | What it wraps / provides |
|-------|--------------------------|
| `common` | tracing/log setup, the NF banner |
| `sbi-core` | SBI HTTP/2 server + client; NRF, AUSF, UDM service modules |
| `ngap` | NGAP (TS 38.413) via `oxirush-ngap`; NG Setup, PDU Session Resource Setup |
| `nas` | NAS (TS 24.501) via `oxirush-nas`; registration, security, session messages |
| `pfcp` | PFCP (TS 29.244) via `rs-pfcp`; SMF request builders + UPF session state |
| `gtpu` | GTP-U (TS 29.281) codec: G-PDU encap/decap, Echo |
| `n6` | N6 forwarding plane + a real TUN adapter |
| `aka` | 5G-AKA (Milenage + TS 33.501 KDFs) |
| `subscriber-db` | subscription store: traits + in-memory and encrypted-redb backends |
| `bdd` | netns-based integration tests |

The design pattern throughout: a mature codec crate wrapped by a thin radian
crate that exposes exactly the messages the NFs need, so the NF binaries stay
small and the protocol knowledge stays in one place.

## A note on process design

Like the network it models, radian-rs is many processes, not one. But each
process is a single async binary that runs its own event loop over `tokio` —
there is no per-NF thread soup or internal socket orchestration. Start the NFs
you need, point them at each other (mostly through the NRF), and the core comes
up.
