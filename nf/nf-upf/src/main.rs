//! UPF — User Plane Function. The one NF with **no SBI**: pure binary TLV.
//! Controlled over **N4 (PFCP)** via `pfcp`; forwards user traffic over
//! **N3/N9 (GTP-U)** via `gtpu`.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("upf");

    // TODO: PFCP (N4) association + session handling via `pfcp`.
    // TODO: GTP-U (N3/N9) datapath (encap/decap, QoS) via `gtpu`.
    tracing::info!("UPF datapath not yet implemented; awaiting Ctrl-C");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
