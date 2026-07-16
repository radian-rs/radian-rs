//! F1AP — F1 Application Protocol (TS 38.473), the control protocol between the gNB-CU
//! and gNB-DU over the F1 interface. Wire encoding is **ASN.1 APER** — the same encoding
//! rules as NGAP (N2), and the same Hampi codec path as `crates/rrc` but APER not UPER
//! (design/128 Phase 3, the interop rung: a Rust CU speaks F1 to OCUDU's `odu`, so a real
//! srsUE attaches to the radian core through a Rust CU).
//!
//! [`generated`] is the machine-generated codec (Hampi `rs-asn1c` over the pinned TS
//! 38.473 modules — see the crate README). This module adds hand-written **builders** and
//! **parsers** for the F1 message subset the CU/DU exchange, mirroring `crates/ngap`. RRC
//! rides opaque inside F1AP (`RRCContainer ::= OCTET STRING`), exactly as NAS rides opaque
//! inside NGAP.

// The generated codec is a vendored artifact — never hand-edited, never linted/formatted.
#[rustfmt::skip]
#[allow(warnings)]
pub mod generated;

mod messages;
pub use messages::*;
