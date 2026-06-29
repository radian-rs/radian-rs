//! SMF — Session Management Function (Nsmf, TS 29.502 / 29.508).
//!
//! Serves `Nsmf_PDUSession` (called by the AMF) and drives the UPF over **N4 (PFCP)**
//! via the `pfcp` crate. NAS-SM (`nas`) and the N2 SM information transfer-IEs
//! (NGAP-encoded via `ngap`) arrive in later slices.

mod pdu_session;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use pdu_session::SmfState;

const UPF_N4_ENV: &str = "RADIANT_SMF_UPF_N4";
const DEFAULT_UPF_N4: &str = "127.0.0.1:8805";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("smf");

    let upf_n4: SocketAddr = std::env::var(UPF_N4_ENV)
        .unwrap_or_else(|_| DEFAULT_UPF_N4.to_string())
        .parse()?;
    let smf_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: real N4 source address / config

    let smf = Arc::new(SmfState::connect(upf_n4, smf_ip).await?);
    smf.associate().await?;
    tracing::info!(%upf_n4, "PFCP association established with UPF");

    let sbi: SocketAddr = "0.0.0.0:8002".parse()?;
    sbi_core::run(sbi, pdu_session::router(smf)).await?;
    Ok(())
}
