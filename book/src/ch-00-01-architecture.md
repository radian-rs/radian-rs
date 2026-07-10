# Architecture

radian-rs is a Cargo workspace. Reusable protocol logic lives in library
**crates** under `crates/`; each network function is a thin binary under `nf/`
that wires those crates to sockets.

## Network functions

Each NF is its own `tokio` binary. Every SBI NF self-registers with the NRF on
startup and is discovered through it.

| NF | Binary | Role | Interfaces |
|----|--------|------|------------|
| **NRF** | `nf-nrf` | NF discovery + registration | SBI (:8000) |
| **AMF** | `nf-amf` | Access & Mobility Management | N2 (NGAP/SCTP :38412), N1 (NAS), SBI (:8001) |
| **SMF** | `nf-smf` | Session Management | SBI (:8002), N4 (PFCP) |
| **UPF** | `nf-upf` | User Plane | N4 (PFCP :8805), N3 (GTP-U :2152), N6 (TUN) |
| **AUSF** | `nf-ausf` | Authentication Server (5G-AKA) | SBI (:8003) |
| **UDM** | `nf-udm` | Unified Data Management — a stateless `Nudr` front-end | SBI (:8004) |
| **UDR** | `nf-udr` | Unified Data Repository — owns the subscriber store + ARPF | SBI (:8005) |
| **PCF** | `nf-pcf` | Policy Control — SM policy + AM policy | SBI (:8006) |
| **CHF** | `nf-chf` | Charging Function — converged charging | SBI (:8007) |

The **UPF is the only NF with no SBI** — it is pure binary TLV, controlled over
N4 and forwarding over N3/N6. Every other NF speaks the Service-Based Interface.

The subscriber data path is split for key isolation: the **UDR** owns the redb
subscriber store and co-hosts the ARPF (5G-AKA vector generation), so the
long-term key **K never crosses the SBI**; the **UDM** is a thin, stateless
`Nudr` front-end the AUSF/AMF/SMF talk to.

## Interfaces

The physical (binary) interfaces carry the user plane and the RAN signalling:

```
   UE
   │  N1 (NAS, tunnelled in NGAP)
┌──┴───┐   N2 (NGAP/SCTP :38412)   ┌───────┐
│ gNB  │──────────────────────────▶│  AMF  │
└──┬───┘                           │ :8001 │
   │  N3 (GTP-U :2152)             └───┬───┘
   ▼                                   │ SBI
┌───────┐   N4 (PFCP :8805)   ┌───────┐│
│  UPF  │◀────────────────────│  SMF  ││
│ N6 TUN│                     │ :8002 │┘
└──┬────┘                     └───────┘
   │ N6
   ▼
 data network
```

Everything else is the **Service-Based Interface** control plane (HTTP/2 + JSON).
Every SBI NF registers with and is discovered through the **NRF (:8000)**. The
subscriber-data chain and the AMF/SMF service dependencies:

```
   AUSF :8003 ──Nudm──▶ UDM :8004 ──Nudr──▶ UDR :8005
                                            (subscriber store + ARPF — K stays here)

   AMF :8001 ─┬─ Nausf ────────────────▶ AUSF          (5G-AKA challenge)
              ├─ Nudm_SDM ──────────────▶ UDM           (subscription data, UECM)
              └─ Npcf_AMPolicyControl ──▶ PCF :8006     (access & mobility policy)

   SMF :8002 ─┬─ Nudm_SDM ──────────────▶ UDM           (session subscription)
              ├─ Npcf_SMPolicyControl ──▶ PCF :8006     (SM policy — QoS, AMBR)
              ├─ Nchf_ConvergedCharging ▶ CHF :8007     (charging session)
              └─ N4 (PFCP) ─────────────▶ UPF           (user-plane control)
```

The **UDM** never sees the long-term key: it relays `Nudm` requests to the
**UDR**, which co-hosts the ARPF and generates the 5G-AKA vectors in place.

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
(`reqwest` with HTTP/2 prior knowledge), plus the service modules for the NRF,
AUSF, UDM, UDR, PCF (SM + AM policy), and CHF. JSON follows the 3GPP OpenAPI
conventions (camelCase field names).

> SBI runs **unauthenticated by default**. OAuth2 access tokens (TS 33.501) and a
> mutual-TLS mesh are implemented but **opt-in** (`RADIAN_SBI_*`); without them,
> the NFs rely on running on a trusted segment. The same posture applies to N4
> and N3, which rely on network isolation or IPsec that is not yet implemented.

## Crates

| Crate | What it wraps / provides |
|-------|--------------------------|
| `common` | tracing/log setup, the NF banner |
| `sbi-core` | SBI HTTP/2 server + client; NRF, AUSF, UDM, UDR, PCF, CHF service modules; OAuth2 + mTLS |
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
