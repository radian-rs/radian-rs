//! radian-du — a Rust **gNB-DU stub** (design/128 Phase 3e). It terminates F1 toward the CU
//! (`radian-gnb --f1`) and the Uu toward a UE, standing in for OCUDU's `odu` in CI so a UE
//! registers on the core through a real F1 split without a PHY. Configuration is read from
//! `RADIAN_DU_*`; see [`radian_gnb::du`] for the architecture.

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::init_tracing();
    common::banner("du");

    let cfg = radian_gnb::du::DuConfig::from_env()?;
    info!(
        cu_f1c = %cfg.cu_f1c,
        uu = %cfg.uu_bind,
        gnb_du_id = cfg.gnb_du_id,
        "gNB-DU starting"
    );
    radian_gnb::du::run(cfg).await
}
