//! PFCP — Packet Forwarding Control Protocol (TS 29.244), the N4 protocol between
//! SMF (control) and UPF (user plane). Runs over UDP; encoding is **binary TLV
//! (not ASN.1)**.
//!
//! TODO: back this with `rs-pfcp` (interop-tested against go-pfcp) or a hand-rolled
//! IE codec. The placeholder below only fixes the crate boundary.

use bytes::Bytes;

#[derive(Debug, thiserror::Error)]
pub enum PfcpError {
    #[error("pfcp codec not implemented")]
    NotImplemented,
}

/// Opaque PFCP message placeholder.
#[derive(Debug, Clone)]
pub struct PfcpMessage(pub Bytes);

impl PfcpMessage {
    pub fn decode(_buf: &[u8]) -> Result<Self, PfcpError> {
        Err(PfcpError::NotImplemented)
    }

    pub fn encode(&self) -> Result<Bytes, PfcpError> {
        Err(PfcpError::NotImplemented)
    }
}
