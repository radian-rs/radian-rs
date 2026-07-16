//! radian-gnb — the standalone gNodeB binary (design/128 Phase 0). See the library crate for
//! the architecture; this main reads `RADIAN_GNB_*` configuration and runs the gNB over either
//! the fake-Uu UDP adapter (default) or, in **F1 mode** (`RADIAN_GNB_F1`=1), a real F1 south
//! side to a gNB-DU (design/128 Phase 3e — CU-shaped).

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
        f1 = cfg.f1_mode,
        "gNB starting"
    );
    if cfg.f1_mode {
        let f1 = radian_gnb::f1::F1Transport::bind(
            cfg.f1c_bind,
            cfg.f1u_bind,
            cfg.du_f1u,
            cfg.mcc.clone(),
            cfg.mnc.clone(),
        )
        .await?;
        radian_gnb::run(cfg, f1).await
    } else {
        let uu = radian_gnb::UdpUu::bind(cfg.uu_bind).await?;
        radian_gnb::run(cfg, uu).await
    }
}
