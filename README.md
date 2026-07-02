# radian-rs

A greenfield Rust implementation of a 3GPP 5G/6G core (5GC).

> Status: **scaffold**. Crate layout and encoding boundaries are in place; protocol
> codecs and network-function logic are stubs. See [`design/`](design/) for the
> architecture research that drives this layout.

## Workspace layout

```
crates/            # shared libraries (one per encoding boundary)
  common/          # shared identifiers (SUPI/PLMN/S-NSSAI), tracing bootstrap
  sbi-core/        # HTTP/2 + OpenAPI SBI runtime (JSON, multipart/related)
  ngap/            # NGAP (TS 38.413) — ASN.1 APER; shared by AMF + SMF
  nas/             # NAS-MM / NAS-SM (TS 24.501) — binary TLV (not ASN.1)
  pfcp/            # PFCP (TS 29.244, N4) — binary TLV
  gtpu/            # GTP-U (TS 29.281, N3/N9) — datapath
nf/                # per-NF service binaries
  nf-nrf  nf-amf  nf-smf  nf-upf  nf-ausf  nf-udm  nf-udr  nf-pcf
```

The split mirrors the encoding analysis: ~90% of the core is JSON (`sbi-core`),
the only ASN.1 dependency is `ngap` (used by AMF and SMF), and the rest is
hand-defined TLV (`nas`, `pfcp`, `gtpu`).

## Build

```sh
cargo build
cargo run -p nf-nrf      # binds a placeholder SBI listener
```
