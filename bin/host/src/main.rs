//! Main entrypoint for the host binary.

use anyhow::Result;
use clap::Parser;
use hokulea_host::args::EigenDaArgs;
use hokulea_host::start_server_and_native_client;
use kona_host::{init_tracing_subscriber, start_server};

use tracing::{error, info};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let eigenda_args = EigenDaArgs::parse();
    init_tracing_subscriber(eigenda_args.kona_cfg.v)?;

    if eigenda_args.kona_cfg.server {
        start_server(eigenda_args.kona_cfg).await?;
    } else {
        let status = match start_server_and_native_client(
            eigenda_args.kona_cfg,
            eigenda_args.eigenda_proxy_address.unwrap(),
        )
        .await
        {
            Ok(status) => status,
            Err(e) => {
                error!(target: "hokulea_host", "Exited with an error: {:?}", e);
                panic!("{e}");
            }
        };

        // Bubble up the exit status of the client program.
        std::process::exit(status as i32);
    }

    info!("Exiting host program.");
    Ok(())
}
