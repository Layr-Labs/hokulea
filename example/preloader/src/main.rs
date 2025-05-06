//! Main entrypoint for the example binary, which runs both host and client

use clap::Parser;
use hokulea_host_bin::{init_tracing_subscriber, cfg::SingleChainHostWithEigenDA};
use kona_preimage::{
    BidirectionalChannel, HintWriter, OracleReader,
};
use tokio::task;
use kona_client::fpvm_evm::FpvmOpEvmFactory;
use hokulea_witgen_client::witgen_client;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cfg = SingleChainHostWithEigenDA::try_parse()?;
    init_tracing_subscriber(cfg.verbose)?;

    let hint = BidirectionalChannel::new()?;
    let preimage = BidirectionalChannel::new()?;

    let server_task = cfg.start_server(hint.host, preimage.host).await?;
    // Start the client program in a separate child process.
    
    let client_task = task::spawn(
        witgen_client::run_preloaded_eigenda_client(
            OracleReader::new(preimage.client.clone()),
            HintWriter::new(hint.client.clone()),
            FpvmOpEvmFactory::new(
                HintWriter::new(hint.client),
                OracleReader::new(preimage.client),
            ),
        ),
    );

    let (_, client_result) = tokio::try_join!(server_task, client_task)?;

    // Bubble up the exit status of the client program if execution completes.
    std::process::exit(client_result.is_err() as i32)
}