# `f1ap` — F1 Application Protocol (TS 38.473) APER codec + message builders

The control protocol between the gNB-CU and gNB-DU over the **F1** interface, wire-encoded
as ASN.1 **APER** (like NGAP on N2; unlike RRC's UPER). This crate is the F1 counterpart to
`crates/ngap` and `crates/rrc`: a machine-generated codec plus hand-written builders/parsers
for the message subset the CU/DU exchange (design/128 Phase 3, the interop rung — a Rust CU
speaks F1 to OCUDU's `odu`, so a real srsUE attaches to the radian core through a Rust CU).

## Layout

- **`asn/*.asn`** — the vendored TS 38.473 modules (the codec's *input*, pristine): the six
  standard split modules (CommonDataTypes, Constants, Containers, IEs, PDU-Contents,
  PDU-Descriptions).
- **`src/generated.rs`** — the **generated** APER codec (~11.7k lines). A vendored artifact:
  never hand-edit; regenerate (below) and let the round-trip tests catch drift. Marked
  `linguist-generated` and `#[rustfmt::skip]` / `#[allow(warnings)]`.
- **`src/messages.rs`** — the public API: `f1_setup_request/response`,
  `initial_ul_rrc_message_transfer`, `dl_rrc_message_transfer`, `ul_rrc_message_transfer`,
  and the matching parsers. RRC rides opaque (`RRCContainer = OCTET STRING`), like NAS in
  NGAP. UE Context management + Paging are a follow-up slice.

## Provenance (pin)

- **Spec:** TS 38.473 **V19.3.0** (Rel-19), as vendored by the Wireshark project at
  `epan/dissectors/asn1/f1ap/` — clean 3GPP ASN.1, no dissector directives, self-contained
  (imports only within the six F1AP modules).
- **Generator:** Hampi `rs-asn1c`, from the **`asn1-compiler` 0.7.2** crate — the same
  version pairing as the checked-in `src/generated.rs` and the `asn1-codecs` /
  `asn1_codecs_derive` 0.7.2 runtime. F1AP is APER (Hampi's NGAP/S1AP strength): codegen was
  clean with **zero** extension-drop warnings (unlike RRC/UPER — see design/129).

**Release skew:** V19.3.0 is newer than OCUDU targets (~Rel-17). The base procedures (F1
Setup, RRC transfer, UE context) are release-stable; before the OCUDU-interop rung, pin the
release OCUDU's `odu` uses and re-confirm the round-trips.

## Regenerating `src/generated.rs`

```sh
cargo install asn1-compiler@0.7.2      # provides the `rs-asn1c` binary
crates/f1ap/asn/regenerate.sh          # runs rs-asn1c over asn/*.asn → src/generated.rs
cargo test -p f1ap                      # MUST stay green
```

## Licensing / attribution

- `asn/*.asn` reproduce 3GPP TS 38.473 ASN.1 (vendored via Wireshark, GPL-2.0-or-later; the
  ASN.1 itself is 3GPP's and may carry additional licensing terms). Vendored for code
  generation only.
