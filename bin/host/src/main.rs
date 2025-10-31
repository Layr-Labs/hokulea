//! Main entrypoint for the host binary.

use clap::Parser;
use hokulea_host_bin::{cfg::SingleChainHostWithEigenDA, init_tracing_subscriber};
use tracing::info;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cfg = SingleChainHostWithEigenDA::try_parse()?;
    init_tracing_subscriber(cfg.verbose)?;

    cfg.start().await?;

    info!("Exiting host program.");
    Ok(())
}
