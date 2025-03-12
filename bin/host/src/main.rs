//! Main entrypoint for the host binary.

use anyhow::Result;

use clap::Parser;
use hokulea_host_bin::cfg::SingleChainHostWithEigenDA;
use kona_host::cli::init_tracing_subscriber;
use tracing::info;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cfg = SingleChainHostWithEigenDA::try_parse()?;
    init_tracing_subscriber(2)?;

    cfg.start().await?;

    info!("Exiting host program.");
    Ok(())
}
