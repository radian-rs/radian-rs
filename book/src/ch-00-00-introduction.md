# radian-rs 5G Core

Welcome to an introductory book about *radian-rs*. radian-rs is a greenfield
implementation of a 3GPP 5G/6G core network (5GC), written from scratch in Rust.
Memory-safe, async to the core, and built one working slice at a time — from the
first NGAP message on the wire to a real user packet forwarded end to end.

radian-rs is not a fork or a port. It grows the 5G core the way the standards
layer it: the N2 (NGAP) control plane, the N1 (NAS) mobility and session layer,
the Service-Based Interfaces (SBI) that stitch the network functions together,
and the N4/N3/N6 user plane that actually moves traffic. Each interface is a
small, focused Rust crate; each network function is its own binary.

## What it does today

A real UE — validated against the independent, free5GC-based
[free-ran-ue](ch-04-00-free-ran-ue-interop.md) simulator — can go from power-on
to a forwarded IP packet through radian-rs:

1. The gNB brings up **N2** (NGAP over SCTP) and completes **NG Setup**.
2. The UE **registers**: identity, **5G-AKA** mutual authentication, and a NAS
   **security context** (integrity + ciphering).
3. The UE establishes a **PDU session**: the AMF discovers the SMF, the SMF
   drives the UPF over **N4 (PFCP)**, and the tunnel endpoints are exchanged over
   **N2** and **N4**.
4. The UPF **forwards** the user's packets between **N3 (GTP-U)** and **N6** (a
   real Linux TUN) — and a `ping` from the UE reaches the data network and back.

The whole journey is reproducible with a single command (see
[BDD Tests](ch-04-01-bdd-tests.md)).

## Why Rust, why per-NF binaries

The 5G core is a distributed system of cooperating network functions (NFs). Each
NF in radian-rs is a standalone async binary — `nf-amf`, `nf-smf`, `nf-upf`, and
so on — that speaks the standardized interfaces to its peers. This maps cleanly
onto containers (one process per container) and mirrors how a real 5GC is
deployed, while keeping each NF small enough to read in an afternoon.

Rust's guarantees matter here: the core parses attacker-adjacent binary
protocols (NGAP/APER, NAS/TLV, PFCP, GTP-U) on every message, and does
cryptography (Milenage, key derivation, AES) on every registration. Memory
safety and an `async` runtime (`tokio`) let radian-rs do that without a class of
bugs that has historically plagued C-based cores.

## The ASN.1 surface is small

A common worry with 5G is ASN.1. For a 5G **core**, that worry is misplaced. The
only ASN.1 the core proper needs is **NGAP** (N2, TS 38.413, APER) — shared by
the AMF (the full message set) and the SMF (a small transfer-IE subset). Roughly
90% of the 5GC is HTTP/2 + JSON (the SBIs), and the rest of the binary surface —
NAS (N1), PFCP (N4), GTP-U (N3/N9) — is non-ASN.1 TLV. radian-rs wraps mature
Rust codecs for each (`oxirush-ngap`, `oxirush-nas`, `rs-pfcp`) behind thin,
purpose-built crates.

The RAN protocols (RRC, F1AP, E1AP, XnAP) are where ASN.1 cost explodes — but
those live in the *radio* network, not the core, and are out of scope here.

## How to read this book

The [Architecture](ch-00-01-architecture.md) chapter maps the network functions,
interfaces, and crates. [Building and Running](ch-00-02-building-and-running.md)
gets a core up on your machine. From there the book follows the call flow: the
[access and mobility](ch-01-00-n2-ngap.md) layer, the
[SBI spine](ch-02-00-sbi-nrf.md), and the
[session and user plane](ch-03-00-pdu-session.md). The final part covers
[interoperability](ch-04-00-free-ran-ue-interop.md) and the
[test harness](ch-04-01-bdd-tests.md) that keeps it honest.

> radian-rs is a work in progress. Where a capability is deliberately deferred
> — SBI OAuth2/TLS, N4/N3 IPsec, ECIES SUCI, SQN resync — this book says so
> plainly rather than implying more than exists.
