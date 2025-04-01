//! Main entrypoint for the host binary.

use anyhow::Result;

use clap::Parser;
use hokulea_host_bin::cfg::SingleChainHostWithEigenDA;
use kona_cli::init_tracing_subscriber;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cfg = SingleChainHostWithEigenDA::try_parse()?;
    init_tracing_subscriber(2, None::<EnvFilter>)?;

    cfg.start().await?;

    info!("Exiting host program.");
    Ok(())
}
