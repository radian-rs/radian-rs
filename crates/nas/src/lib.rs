//! NAS — Non-Access Stratum (TS 24.501), the N1 protocol between UE and core.
//! 5GMM (mobility) is handled by the AMF; 5GSM (session) by the SMF.
//!
//! NAS is **hand-defined binary TLV/IEI — not ASN.1**. Carried transparently
//! inside NGAP on N2, and over the SBI as `application/vnd.3gpp.5gnas`.
//!
//! TODO: back this with `oxirush-nas` or a hand-rolled IEI codec.

use bytes::Bytes;

#[derive(Debug, thiserror::Error)]
pub enum NasError {
    #[error("nas codec not implemented")]
    NotImplemented,
}

/// NAS protocol discriminator (TS 24.007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NasKind {
    /// 5GS Mobility Management (AMF).
    Mm,
    /// 5GS Session Management (SMF).
    Sm,
}

/// Opaque NAS message placeholder.
#[derive(Debug, Clone)]
pub struct NasMessage {
    pub kind: NasKind,
    pub raw: Bytes,
}

impl NasMessage {
    pub fn decode(_buf: &[u8]) -> Result<Self, NasError> {
        Err(NasError::NotImplemented)
    }

    pub fn encode(&self) -> Result<Bytes, NasError> {
        Err(NasError::NotImplemented)
    }
}
