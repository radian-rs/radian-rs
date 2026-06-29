# 5G Core NF / Interface Encoding Map + Build Plan

> Research date: 2026-06-28. TS numbers are release-dependent (figures reflect ~Rel-17);
> re-verify against the targeted 3GPP release before locking interfaces.

Headline: **encoding is concentrated, not spread.** ~90% of the core is JSON, and the
ASN.1 burden collapses onto essentially one-and-a-half NFs (AMF, and an NGAP subset in SMF).

## Encoding taxonomy (the 5 buckets)

| Bucket | Used by | Codec effort |
|---|---|---|
| **JSON / HTTP-2 (OpenAPI)** | All SBI (every NF's `Nxxx` service) | Generate from 3GPP YAML; serde |
| **ASN.1 APER** | NGAP, NRPPa; (RAN: XnAP/F1AP/E1AP/E2AP; EPC: S1AP/X2AP) | rasn / oxirush-ngap |
| **ASN.1 UPER** | LPP; (RAN: RRC) | rasn |
| **Custom binary TLV** (3GPP hand-defined, *not* ASN.1) | NAS (24.501), GTP-U (29.281), PFCP (29.244), GTPv2-C (29.274) | hand-rolled / oxirush-nas / rs-pfcp |
| **Raw IP / EAP / JWE** | N6, NSSAAF EAP relay, SEPP N32-f | n/a or existing crates |

## Table 1 — Network Functions (all SBI = HTTP/2 + JSON)

Every NF's service interface is JSON. The **Extra codec** column is where the
binary/ASN.1 work actually lives.

| NF | SBI service | Spec (TS) | SBI enc. | Extra codec needed |
|---|---|---|---|---|
| **NRF** | Nnrf | 29.510 | JSON | — |
| **AMF** | Namf | 29.518 | JSON | **NGAP (APER)** + **NAS-MM (TLV)** |
| **SMF** | Nsmf | 29.502 / 29.508 | JSON | **NGAP "N2 SM info" transfer-IEs (APER)** + NAS-SM (TLV) + **PFCP (TLV, N4)** |
| **UPF** | *(no SBI)* | 29.244 | — | **PFCP (TLV)** + **GTP-U (TLV)** |
| **AUSF** | Nausf | 29.509 | JSON | — (EAP/5G-AKA blobs opaque) |
| **UDM** | Nudm | 29.503 | JSON | — |
| **UDR** | Nudr | 29.504 | JSON | — |
| **PCF** | Npcf | 29.507/512/514/525 | JSON | — |
| **NSSF** | Nnssf | 29.531 | JSON | — |
| **NEF** | Nnef (+T8) | 29.591 / 29.522 | JSON | — |
| **NWDAF** | Nnwdaf | 29.520 | JSON | — |
| **CHF** | Nchf | 32.291 / 32.290 | JSON | — (Nchf replaces Diameter Gy) |
| **SMSF** | Nsmsf | 29.540 | JSON | SMS TPDU (TS 23.040 TLV) over NAS |
| **LMF** | Nlmf | 29.572 | JSON | **NRPPa (APER)** + **LPP (UPER)** |
| **GMLC** | Ngmlc | 29.515 | JSON | — |
| **5G-EIR** | N5g-eir | 29.511 | JSON | — |
| **BSF** | Nbsf | 29.521 | JSON | — |
| **NSSAAF** | Nnssaaf | 29.526 | JSON | EAP relay to AAA (opaque) |
| **UCMF** | Nucmf | 29.673 | JSON | stores opaque UE-radio-cap (RRC ASN.1) — *not decoded* |
| **SCP** | *(proxy)* | 29.500 | JSON | — (HTTP/2 routing) |
| **SEPP** | *(N32)* | 29.573 | JSON | JWE/PRINS on N32-f (not ASN.1) |
| **N3IWF/TNGF/W-AGF** | *(no SBI; RAN-side)* | 24.502 | — | **NGAP (APER)** + NAS relay + IPsec |

**Takeaway:** of ~25 NFs, only **AMF, SMF, LMF** (and non-3GPP-access gateway N3IWF)
touch ASN.1 — almost all of it **NGAP**. UPF is the odd one out: no JSON at all, pure TLV.

## Table 2 — Reference-point interfaces (non-SBI)

| IF | Endpoints | Protocol | Spec | Transport | Encoding | ASN.1? |
|---|---|---|---|---|---|---|
| **N1** | UE ↔ AMF | NAS-MM/SM | 24.501 | (in NGAP) | TLV/IEI | **No** |
| **N2** | (R)AN ↔ AMF | **NGAP** | 38.413 | SCTP | **APER** | **Yes** |
| **N3** | (R)AN ↔ UPF | GTP-U | 29.281 | UDP | TLV | No |
| **N4** | SMF ↔ UPF | PFCP | 29.244 | UDP | TLV | No |
| **N6** | UPF ↔ DN | IP | — | IP | — | No |
| **N9** | UPF ↔ UPF | GTP-U | 29.281 | UDP | TLV | No |
| **N26** | AMF ↔ MME | GTPv2-C | 29.274 | UDP | TLV | No |
| **—** | gNB ↔ LMF (via N2) | **NRPPa** | 38.455 | (in NGAP) | **APER** | **Yes** |
| **—** | UE ↔ LMF (via N1/Nlmf) | **LPP** | 37.355 | (in NAS) | **UPER** | **Yes** |
| **Xn** | gNB ↔ gNB | XnAP | 38.423 | SCTP | APER | Yes *(RAN)* |

## Table 3 — RAN-internal & EPC interworking (out of core; included for completeness)

Relevant only if scope extends past the 5GC into gNB or LTE interworking.

| IF | Endpoints | Protocol | Spec | Encoding | ASN.1? |
|---|---|---|---|---|---|
| F1-C | gNB-CU ↔ gNB-DU | F1AP | 38.473 | APER | Yes |
| E1 | CU-CP ↔ CU-UP | E1AP | 38.463 | APER | Yes |
| Uu | UE ↔ gNB | **RRC** | 38.331 | **UPER** | Yes (huge) |
| Uu | UE ↔ gNB | PDCP/RLC/MAC | 38.323/322/321 | bit-field | No |
| E2 | RIC ↔ E2 node | E2AP + E2SM | O-RAN | APER | Yes |
| S1-MME | eNB ↔ MME | S1AP | 36.413 | APER | Yes |
| Gx/Gy/S6a | EPC legacy | Diameter | 29.2xx | AVP | No (not JSON either) |

## Two nuances that change the build plan

1. **JSON NFs still shuffle binary they don't parse.** SBI bodies use
   `multipart/related` to carry opaque NAS (`application/vnd.3gpp.5gnas`) and NGAP
   (`application/vnd.3gpp.ngap`) byte-blobs between NFs (e.g.
   `Namf_Communication.N1N2MessageTransfer`). The JSON layer must handle multipart +
   binary passthrough, but **only AMF/SMF/RAN actually decode those parts.** Codec
   ownership is concentrated.
2. **SMF needs NGAP ASN.1 even though it never terminates N2.** The "N2 SM information"
   SMF hands to AMF (e.g. `PDUSessionResourceSetupRequestTransfer`) is an APER-encoded
   NGAP IE from TS 38.413. Budget NGAP ASN.1 for **both** AMF (full PDU set) and SMF
   (the `*Transfer` IE subset).

## Build plan — codec stack per phase

**Phase 0 — substrate (no protocol codecs):** HTTP/2 server/client + OpenAPI→Rust
codegen from the 3GPP Forge YAML, SCTP, UDP, TLS. Unblocks every JSON NF.

**Phase 1 — MVP control core (NRF → AUSF/UDM/UDR → PCF → AMF/SMF):** JSON only,
*except the AMF/SMF NGAP+NAS pair.* Codec shopping list:
- JSON: serde + generated OpenAPI models — *all NFs*
- **NGAP (APER):** `oxirush-ngap` or rasn-compiled TS 38.413 — *AMF (full), SMF (transfer IEs)*
- **NAS (TLV):** `oxirush-nas` or hand-rolled — *AMF (MM), SMF (SM)*

**Phase 2 — user plane (UPF):** zero JSON, zero ASN.1. Just `rs-pfcp` (N4) +
GTP-U (N3/N9). UPF is encoding-isolated from the rest of the core.

**Phase 3 — breadth (NSSF, NEF, NWDAF, CHF, SMSF, BSF, 5G-EIR, SCP, SEPP):** all pure
JSON. No new codecs except SEPP's N32-f JOSE/JWE.

**Phase 4 (optional) — LCS / positioning:** adds **NRPPa (APER)** + **LPP (UPER)** in
LMF — the only *new* ASN.1 beyond NGAP.

**Phase 5 (optional) — RAN / EPC:** ASN.1 cost explodes here (RRC UPER, F1AP/E1AP/XnAP
APER). Separate, project-sized effort.

**Net:** to stand up a working 5GC control+user plane (Phases 0–2), the entire ASN.1
dependency is **NGAP**, shared by AMF and SMF, with everything else JSON + three TLV
codecs (NAS, PFCP, GTP-U). A very tractable codec surface.

## Proposed crate boundaries (maps encoding boundaries → crates)

```
crates/         # shared libraries (one per encoding boundary)
  common/       # shared identifiers (SUPI/PLMN/S-NSSAI), tracing bootstrap
  sbi-core/     # HTTP/2 + TLS + OpenAPI models + multipart/related handling
  ngap/         # ASN.1 APER (rasn-generated or oxirush-ngap); shared by AMF + SMF
  nas/          # NAS-MM + NAS-SM TLV codec
  pfcp/         # PFCP (N4) TLV codec
  gtpu/         # GTP-U (N3/N9) datapath
nf/             # per-NF service binaries
  nf-nrf/  nf-amf/  nf-smf/  nf-upf/  nf-ausf/  nf-udm/  nf-udr/  nf-pcf/
```

This layout is scaffolded in the repo (`cargo build` green); protocol codecs and
NF logic are stubs.

## Sources

- 5GC SBA / RESTful APIs — https://devopedia.org/5g-core-restful-apis ; 3GPP Forge OpenAPI — https://forge.3gpp.org/
- N1N2 binary media types — https://www.iana.org/assignments/media-types/application/vnd.3gpp.5gnas ; TS 29.518 YAML — https://www.3gpp.org/ftp/Specs/archive/OpenAPI/Rel-16/TS29518_Namf_Communication.yaml
- 5G interfaces — https://www.3glteinfo.com/5g/architecture/interfaces/
- NG-RAN positioning (NRPPa/LPP) — https://www.etsi.org/deliver/etsi_ts/138300_138399/138305/15.00.00_60/ts_138305v150000p.pdf
