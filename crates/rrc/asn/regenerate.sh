#!/usr/bin/env bash
# Regenerate crates/rrc/src/generated.rs from the pinned TS 38.331 module.
#
# Requires Hampi's `rs-asn1c` (from asn1-compiler 0.7.2, the version this crate's
# generated code + runtime are pinned to):
#     cargo install asn1-compiler@0.7.2
#
# After regenerating, `cargo test -p rrc` MUST stay green — the golden
# RRCReconfiguration round-trip is the gate that keeps a regeneration honest.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate="$(dirname "$here")"
rs-asn1c --module generated --codec uper --no-rustfmt -- "$here/rrc.asn"
mv generated "$crate/src/generated.rs"
echo "wrote $crate/src/generated.rs — now run: cargo test -p rrc"
