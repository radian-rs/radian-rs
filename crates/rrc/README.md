# `rrc` — Radio Resource Control (TS 38.331) UPER codec + message builders

The Uu control protocol between the UE and the NG-RAN, wire-encoded as ASN.1 **UPER**.
This crate is the RRC counterpart to `crates/ngap` (which does NGAP/APER for N2): a
machine-generated codec plus hand-written builders/parsers for the message subset the
Rust gNB and its co-located test UE exchange (design/128 Phase 1, design/129).

## Layout

- **`asn/rrc.asn`** — the vendored TS 38.331 ASN.1 module (the codec's *input*, pristine).
- **`src/generated.rs`** — the **generated** UPER codec (≈11k lines, ~5200 types). A
  vendored artifact: never hand-edit it; regenerate (below) and let the golden test catch
  drift. Marked `linguist-generated` and `#[rustfmt::skip]` / `#[allow(warnings)]`.
- **`src/messages.rs`** — the public API: `rrc_setup_request`, `rrc_setup`,
  `rrc_setup_complete`, `ul/dl_information_transfer`, `security_mode_command/complete`,
  `rrc_reconfiguration(_complete)`, `rrc_release`, and `parse_{ul,dl}_{ccch,dcch}`.

## Provenance (pin — design/129 §5.1)

- **Spec:** TS 38.331 **v16.5.0 (Rel-16)** — `asn/rrc.asn` was generated from
  `38331-g50.docx` (see the file's header) and is the copy vendored in
  [`gabhijit/hampi`](https://github.com/gabhijit/hampi) at `examples/specs/rrc/rrc.asn`.
- **Generator:** Hampi `rs-asn1c`, from the **`asn1-compiler` 0.7.2** crate — the same
  version pairing as the checked-in `src/generated.rs` and the `asn1-codecs` /
  `asn1_codecs_derive` 0.7.2 runtime this crate depends on.

Before bumping the 3GPP release or the generator, re-confirm the golden round-trip
(`cargo test -p rrc`) — that is the gate that keeps a regeneration honest.

## Regenerating `src/generated.rs`

```sh
cargo install asn1-compiler@0.7.2      # provides the `rs-asn1c` binary
crates/rrc/asn/regenerate.sh           # runs rs-asn1c over asn/rrc.asn → src/generated.rs
cargo test -p rrc                       # MUST stay green (golden RRCReconfiguration round-trip)
```

## Codec caveat (design/129)

Hampi silently drops some ASN.1 **extension-addition** fields (it warns at codegen). The
messages this crate builds stay within base (non-extension) IEs, and `UECapabilityInformation`
is treated as **opaque** (the CU forwards the octet string; it is never re-encoded here).
Every builder has a round-trip test — the mandatory gate. The anchor test decodes a real
383-byte `RRCReconfiguration` from OCUDU's corpus and re-encodes it **byte-identical**.

## Licensing / attribution

- `asn/rrc.asn` reproduces 3GPP TS 38.331 ASN.1; 3GPP specifications may carry additional
  licensing terms. It is vendored for code generation only.
- The golden test vector in `src/messages.rs` is derived from OCUDU
  (`tests/unittests/asn1/asn1_rrc_nr_test.cpp`, BSD-3-Clause-Open-MPI).
