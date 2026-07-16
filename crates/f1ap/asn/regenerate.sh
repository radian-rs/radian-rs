#!/usr/bin/env bash
# Regenerate crates/f1ap/src/generated.rs from the pinned TS 38.473 modules.
#
# Requires Hampi's `rs-asn1c` (from asn1-compiler 0.7.2, the version this crate's
# generated code + runtime are pinned to):
#     cargo install asn1-compiler@0.7.2
#
# Module order matters (dependency order). After regenerating, `cargo test -p f1ap`
# MUST stay green.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate="$(dirname "$here")"
rs-asn1c --module generated --codec aper --no-rustfmt -- \
  "$here/F1AP-CommonDataTypes.asn" "$here/F1AP-Constants.asn" "$here/F1AP-Containers.asn" \
  "$here/F1AP-IEs.asn" "$here/F1AP-PDU-Contents.asn" "$here/F1AP-PDU-Descriptions.asn"
mv generated "$crate/src/generated.rs"
echo "wrote $crate/src/generated.rs — now run: cargo test -p f1ap"
