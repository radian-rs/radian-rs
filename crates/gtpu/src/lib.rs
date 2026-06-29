//! GTP-U — GPRS Tunnelling Protocol, user plane (TS 29.281), used on N3 ((R)AN↔UPF)
//! and N9 (UPF↔UPF). Runs over UDP; encoding is **binary TLV (not ASN.1)**.
//!
//! TODO: implement the GTP-U header + extension headers and the datapath
//! (encap/decap, echo, error indication). The placeholder below fixes the boundary.

use bytes::Bytes;

#[derive(Debug, thiserror::Error)]
pub enum GtpuError {
    #[error("gtpu codec not implemented")]
    NotImplemented,
}

/// Minimal GTP-U header fields (TS 29.281 §5).
#[derive(Debug, Clone)]
pub struct GtpuHeader {
    pub message_type: u8,
    /// Tunnel Endpoint Identifier.
    pub teid: u32,
}

/// A GTP-U packet: header plus opaque payload.
#[derive(Debug, Clone)]
pub struct GtpuPacket {
    pub header: GtpuHeader,
    pub payload: Bytes,
}

impl GtpuPacket {
    pub fn decode(_buf: &[u8]) -> Result<Self, GtpuError> {
        Err(GtpuError::NotImplemented)
    }

    pub fn encode(&self) -> Result<Bytes, GtpuError> {
        Err(GtpuError::NotImplemented)
    }
}
