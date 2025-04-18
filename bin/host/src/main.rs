//! Main entrypoint for the host binary.

use tracing_subscriber::{filter::LevelFilter, prelude::*, EnvFilter};

use clap::Parser;
use hokulea_host_bin::cfg::SingleChainHostWithEigenDA;
use tracing::info;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cfg = SingleChainHostWithEigenDA::try_parse()?;
    init_tracing_subscriber(cfg.verbose)?;

    cfg.start().await?;

    info!("Exiting host program.");
    Ok(())
}

fn init_tracing_subscriber(verbosity_level: u8) -> anyhow::Result<(), anyhow::Error> {
    // Convert verbosity_level to a LevelFilter
    let level = match verbosity_level {
        0 => LevelFilter::INFO,
        1 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let mut filter_builder = EnvFilter::builder()
        .with_default_directive(level.into())
        .parse("")?;

    // Only show info logs for these http related crates.
    // Their debug logs are extremely verbose, and clutter the output
    // because of the multiple calls to the l1 and l2 nodes for block headers etc,
    // making it hard to focus on the actual debug logs related to eigenda stuff.
    filter_builder = filter_builder
        .add_directive("hyper_util=info".parse()?)
        .add_directive("reqwest=info".parse()?)
        .add_directive("alloy_rpc_client=info".parse()?)
        .add_directive("alloy_transport_http=info".parse()?);

    // Initialize the subscriber
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter_builder)
        .init();
    Ok(())
}
