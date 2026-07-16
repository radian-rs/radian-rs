//! RRC — Radio Resource Control (TS 38.331), the Uu control protocol between the UE
//! and the NG-RAN. Wire encoding is **ASN.1 UPER** — the RAN-side counterpart to the
//! core's NGAP/APER surface (see design/01, design/129).
//!
//! [`generated`] is the machine-generated codec (Hampi `rs-asn1c` over a pinned
//! TS 38.331 module — see the crate README for provenance/regeneration). This module
//! adds hand-written **builders** (for the messages the gNB and the co-located test UE
//! send) and **parsers** (for what they receive), exactly the subset design/128 Phase 1
//! needs, mirroring `crates/ngap`. NAS is carried transparently (an octet string);
//! UECapabilityInformation is treated as opaque (design/129 §5.5).
//!
//! # Codec caveat (design/129)
//! Hampi silently drops some ASN.1 **extension-addition** fields (it warns at codegen).
//! Every builder here therefore has a **round-trip test against a golden or
//! self-consistent PDU** — the gate that makes a "mostly-works" generator safe. Do not
//! add a builder without one.

// The generated codec is a vendored artifact — never hand-edited, never linted/formatted.
#[rustfmt::skip]
#[allow(warnings)]
pub mod generated;

mod messages;
pub use messages::*;
