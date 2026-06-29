# Rust ASN.1 Ecosystem vs. 3GPP 5G Core — Gap Analysis

> Research date: 2026-06-28. Verify crate versions and 3GPP releases before committing.

## TL;DR

For a 5G **core**, the ASN.1 gap is **small and not the bottleneck** — because almost
none of the 5GC is ASN.1. The only ASN.1 the core proper needs is **NGAP** (N2,
AMF↔gNB), and multiple working Rust options already exist for it. If scope extends
to the **RAN** (gNB), the ASN.1 surface explodes (RRC, F1AP, E1AP, XnAP) and the gap
becomes real — but it is still "hardening / maintenance," not "no codec exists."

## Where ASN.1 actually lives in a 5GC

| Interface | Protocol | Encoding | ASN.1? |
|---|---|---|---|
| SBI (Namf/Nsmf/Nnrf/Nudm…) — most of the core | HTTP/2 + JSON | OpenAPI/JSON | **No** |
| N1 (UE↔AMF) | NAS-MM/SM (TS 24.501) | hand-defined TLV/IEI | **No** |
| N2 (AMF↔gNB) | **NGAP** (TS 38.413) | **APER** | **Yes** |
| N4 (SMF↔UPF) | PFCP (TS 29.244) | custom TLV | **No** |
| N3/N9 | GTP-U (TS 29.281) | custom TLV | **No** |

A pure 5GC's entire ASN.1 dependency is **NGAP**. NAS is the common misconception —
it is *not* ASN.1. The encoding rule that matters is **PER** (APER for the *AP
protocols, UPER for RRC/LPP), which rules out DER-only crates (`rust-asn1`, rasn's
DER path) used for X.509 — they are useless for 3GPP.

## The Rust ASN.1 / 3GPP landscape

| Project | What it is | Encoding | 3GPP coverage | Maturity |
|---|---|---|---|---|
| **rasn** + **rasn-compiler** (librasn) | Pure-Rust `no_std` codec framework + ASN.1→Rust compiler | BER/CER/DER/**APER/UPER**/OER/JER/XER | IOCs, parameterization, table constraints, open types; NGAP/S1AP demonstrated | **Most active & strategic.** ~62 releases (latest Dec 2025). "Not all features supported yet"; real rough edges (e.g. open S1AP compile issue) |
| **Hampi** (gabhijit / ystero-dev: `asn1-compiler`/`asn1-codecs`) | 3GPP-first ASN.1 toolkit | APER/UPER | NGAP/S1AP/RANAP full encode/decode; RRC/E2AP/SUPL/E2SM codegen | Works, 3GPP-focused; maintenance cadence unclear |
| **oxirush-ngap** (+ **oxirush-nas**) | Ready-made auto-generated NGAP APER codec on crates.io; sister crate for NAS | APER | NGAP from official 3GPP ASN.1 | **Drop-in** for NGAP; v0.3.x, updated recently |
| **alsoran** → QCore | Rust gNB-CU PoC w/ custom Python ASN.1 autogen | APER/UPER | NGAP/F1AP/E1AP/RRC | PoC, **no longer maintained** ("lives on in QCore"); proves feasibility |
| asn1rs / rust-asn1 | older UPER / DER-only | — | — | Not suitable for 3GPP AP protocols |

## How much gap — by layer

- **NGAP (the core's only ASN.1 need): ~80–90% there.** `cargo add oxirush-ngap`
  today, or generate from TS 38.413 via rasn-compiler / Hampi. Remaining work is
  integration, IE/edge-case hardening, and tracking the target 3GPP release — not
  writing a PER codec.
- **The genuinely hard ASN.1 part isn't the encoding rules — it's that 3GPP modules
  use the full nasty ASN.1**: information object classes, parameterized types, table
  constraints driving open types in the `ProtocolIE-Field` / `ProtocolIE-Container`
  pattern. The Rust compilers handle these "mostly"; expect to hand-patch generator
  output and occasionally fix/file upstream bugs on the gnarliest modules. Bounded cost.
- **Everything else in the core is not an ASN.1 problem:** NAS (`oxirush-nas` or
  hand-rolled), PFCP (`rs-pfcp`, interop-tested vs go-pfcp), GTP-U, and the SBI which
  is OpenAPI→JSON (codegen from the 3GPP YAML). ASN.1 maturity will not gate a 5GC.
- **If scope extends to RAN: the gap widens.** RRC (TS 38.331, UPER, very large),
  F1AP, E1AP, XnAP. Codecs *can* be generated (alsoran/QCore did it), but nothing
  here is production-grade-and-maintained.

## The real "gap"

It is **not** "a Rust APER codec for 5G doesn't exist" — it does, several times over:

1. **No batteries-included "3GPP-in-Rust" stack** equivalent to free5GC (Go) or
   Open5GS (C) — pieces must be assembled.
2. **Production hardening + maintenance ownership** — most projects are PoC-grade or
   thin single-maintainer crates.
3. **3GPP release currency** — keeping generated bindings tracking the target spec.
4. **Generator rough edges** on the hairiest modules.

## Recommendation

Build on **rasn** (librasn): most active, broadest encoding-rule support, pure-Rust
`no_std`, the direction the ecosystem is converging on. Use **oxirush-ngap** as a fast
start / reference oracle, and pin a specific TS 38.413 release. Budget real ASN.1
effort for *generator-output cleanup and version tracking*, and spend the bulk of
engineering on the non-ASN.1 ~90% of the core (SBI/NFs, NAS, PFCP, state machines).

## Sources

- rasn — https://docs.rs/rasn/latest/rasn/ ; compiler — https://github.com/librasn/compiler ; S1AP compile issue — https://github.com/librasn/compiler/issues/14
- Hampi — https://github.com/gabhijit/hampi ; https://crates.io/crates/asn1-codecs
- oxirush-nas — https://crates.io/crates/oxirush-nas ; oxirush-ngap (crates.io, v0.3.x)
- alsoran — https://github.com/nplrkn/alsoran
- 5GC SBA encoding — https://devopedia.org/5g-core-restful-apis ; https://arxiv.org/html/2405.10635v1
