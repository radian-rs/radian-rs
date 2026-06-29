//! NAS — Non-Access Stratum (TS 24.501), the N1 protocol between UE and core.
//! 5GMM (mobility) is handled by the AMF; 5GSM (session) by the SMF.
//!
//! NAS is **hand-defined binary TLV/IEI — not ASN.1**. Carried transparently
//! inside NGAP on N2, and over the SBI as `application/vnd.3gpp.5gnas`.
//!
//! Thin re-export of [`oxirush_nas`], keeping the NAS codec behind this crate
//! boundary (see `design/02`). Primary entry points:
//! [`decode_nas_5gs_message`] / [`encode_nas_5gs_message`].

pub use oxirush_nas::*;
