//! NGAP — NG Application Protocol (TS 38.413), the N2 control protocol between
//! the (R)AN and the AMF. Wire encoding is **ASN.1 APER**.
//!
//! This is the 5GC's only mandatory ASN.1 surface. It is shared by:
//!   * the AMF — full PDU set (terminates N2), and
//!   * the SMF — the `*Transfer` IE subset ("N2 SM information").
//!
//! TODO: back this with `oxirush-ngap`, or rasn-generated bindings compiled from
//! TS 38.413 ASN.1 (pin a specific 3GPP release). The placeholder below only
//! fixes the crate boundary.

use bytes::Bytes;

#[derive(Debug, thiserror::Error)]
pub enum NgapError {
    #[error("ngap codec not implemented")]
    NotImplemented,
}

/// Opaque NGAP PDU placeholder (APER-encoded bytes).
#[derive(Debug, Clone)]
pub struct NgapPdu(pub Bytes);

impl NgapPdu {
    pub fn decode(_buf: &[u8]) -> Result<Self, NgapError> {
        Err(NgapError::NotImplemented)
    }

    pub fn encode(&self) -> Result<Bytes, NgapError> {
        Err(NgapError::NotImplemented)
    }
}
