//! AMF — Access and Mobility Management Function (Namf, TS 29.518).
//!
//! The 5GC's primary ASN.1 NF: it terminates **N2 (NGAP/SCTP)** via the `ngap`
//! crate and relays **NAS-MM** (`nas`), in addition to its SBI services.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("amf");

    // TODO: bring up N2 — NGAP over SCTP on :38412 — via the `ngap` crate,
    //       and NAS-MM handling via `nas`.
    // TODO: implement Namf_Communication / _EventExposure / _MT / _Location.
    let sbi: SocketAddr = "0.0.0.0:8001".parse()?;
    sbi_core::serve(sbi).await?;
    Ok(())
}
