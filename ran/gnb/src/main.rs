//! radian-gnb — the standalone gNodeB binary (design/128 Phase 0). See the
//! library crate for the architecture; this main just reads `RADIAN_GNB_*`
//! configuration, binds the fake-Uu UDP adapter, and runs the gNB.

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("gnb");

    let cfg = radian_gnb::GnbConfig::from_env()?;
    info!(
        gnb_id = format_args!("{:#x}", cfg.gnb_id),
        plmn = format_args!("{}/{}", cfg.mcc, cfg.mnc),
        tacs = ?cfg.tacs,
        amf = %cfg.amf_addr,
        "gNB starting"
    );
    let uu = radian_gnb::UdpUu::bind(cfg.uu_bind).await?;
    radian_gnb::run(cfg, uu).await
}
