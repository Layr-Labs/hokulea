pub mod fetcher;

pub mod eigenda_blobs;

pub mod server;

pub mod preimage;

use server::PreimageServer;

use kona_host::cli::HostCli;

use kona_host::kv;

use hokulea_client;

use crate::eigenda_blobs::OnlineEigenDABlobProvider;
use anyhow::{anyhow, Result};
use fetcher::Fetcher;
use kona_preimage::{
    BidirectionalChannel, HintReader, HintWriter, NativeChannel, OracleReader, OracleServer,
};
use kv::KeyValueStore;
use std::sync::Arc;
use tokio::{sync::RwLock, task};
use tracing::info;

/// Starts the [PreimageServer] and the client program in separate threads. The client program is
/// ran natively in this mode.
///
/// ## Takes
/// - `cfg`: The host configuration.
///
/// ## Returns
/// - `Ok(exit_code)` if the client program exits successfully.
/// - `Err(_)` if the client program failed to execute, was killed by a signal, or the host program
///   exited first.
pub async fn start_server_and_native_client(cfg: HostCli) -> Result<i32> {
    let hint_chan = BidirectionalChannel::new()?;
    let preimage_chan = BidirectionalChannel::new()?;
    let kv_store = cfg.construct_kv_store();
    let fetcher = if !cfg.is_offline() {
        let (l1_provider, blob_provider, l2_provider) = cfg.create_providers().await?;
        let eigenda_blob_provider = OnlineEigenDABlobProvider::new_http(
            //EIGENDA_ADDRESS.to_string(),
            "http://127.0.0.1:3100".to_string(),
        )
        .await
        .map_err(|e| anyhow!("Failed to load eigenda blob provider configuration: {e}"))?;
        info!(target: "host", "create fetch with eigenda_provider");
        Some(Arc::new(RwLock::new(Fetcher::new(
            kv_store.clone(),
            l1_provider,
            blob_provider,
            eigenda_blob_provider,
            l2_provider,
            cfg.agreed_l2_head_hash,
        ))))
    } else {
        None
    };

    info!(target: "host", "fetcher");

    // Create the server and start it.
    let server_task = task::spawn(start_native_preimage_server(
        kv_store,
        fetcher,
        hint_chan.host,
        preimage_chan.host,
    ));

    // Start the client program in a separate child process.
    let program_task = task::spawn(hokulea_client::run(
        OracleReader::new(preimage_chan.client),
        HintWriter::new(hint_chan.client),
    ));

    // Execute both tasks and wait for them to complete.
    info!("Starting preimage server and client program.");
    let (_, client_result) = tokio::try_join!(server_task, program_task,)?;
    info!(target: "hokulea_host", "Preimage server and client program have joined.");

    Ok(client_result.is_err() as i32)
}

pub async fn start_native_preimage_server<KV>(
    kv_store: Arc<RwLock<KV>>,
    fetcher: Option<Arc<RwLock<Fetcher<KV>>>>,
    hint_chan: NativeChannel,
    preimage_chan: NativeChannel,
) -> Result<()>
where
    KV: KeyValueStore + Send + Sync + ?Sized + 'static,
{
    let hint_reader = HintReader::new(hint_chan);
    let oracle_server = OracleServer::new(preimage_chan);

    PreimageServer::new(oracle_server, hint_reader, kv_store, fetcher)
        .start()
        .await
}
