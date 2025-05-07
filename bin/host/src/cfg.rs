use crate::eigenda_blobs::OnlineEigenDABlobProvider;
use crate::handler::SingleChainHintHandlerWithEigenDA;
use anyhow::Result;
use clap::Parser;
use hokulea_proof::hint::ExtendedHintType;
use kona_cli::cli_styles;
use kona_client::fpvm_evm::FpvmOpEvmFactory;
use kona_host::single::SingleChainHostError;
use kona_host::single::SingleChainProviders;
use kona_host::PreimageServer;
use kona_host::{OfflineHostBackend, OnlineHostBackend, OnlineHostBackendCfg};
use kona_preimage::{
    BidirectionalChannel, Channel, HintReader, HintWriter, OracleReader, OracleServer,
};
use kona_std_fpvm::{FileChannel, FileDescriptor};
use serde::Serialize;
use std::sync::Arc;
use tokio::task::{self, JoinHandle};

/// The host Eigenda binary CLI application arguments.
#[derive(Default, Parser, Serialize, Clone, Debug)]
#[command(styles = cli_styles())]
pub struct SingleChainHostWithEigenDA {
    #[clap(flatten)]
    pub kona_cfg: kona_host::single::SingleChainHost,

    /// URL of the EigenDA RPC endpoint.
    #[clap(
        long,
        visible_alias = "eigenda",
        requires = "l2_node_address",
        requires = "l1_node_address",
        requires = "l1_beacon_address",
        env
    )]
    pub eigenda_proxy_address: Option<String>,

    /// Verbosity level (-v, -vv, -vvv, etc.)
    /// TODO: think this should be upstreamed to kona_cfg
    #[clap(
        short,
        long,
        action = clap::ArgAction::Count,
        default_value_t = 0
    )]
    pub verbose: u8,
}

impl SingleChainHostWithEigenDA {
    /// Starts the [SingleChainHostWithEigenDA] application. This is copy from
    /// <https://github.com/op-rs/kona/blob/b3eef14771015f6f7427f4f05cf70e508b641802/bin/host/src/single/cfg.rs#L133-L143>
    pub async fn start(self) -> Result<(), SingleChainHostError> {
        if self.kona_cfg.server {
            let hint = FileChannel::new(FileDescriptor::HintRead, FileDescriptor::HintWrite);
            let preimage =
                FileChannel::new(FileDescriptor::PreimageRead, FileDescriptor::PreimageWrite);

            self.start_server(hint, preimage).await?.await?
        } else {
            self.start_native().await
        }
    }

    /// Start a server with eigenda backend
    pub async fn start_server<C>(
        &self,
        hint: C,
        preimage: C,
    ) -> Result<JoinHandle<Result<(), SingleChainHostError>>, SingleChainHostError>
    where
        C: Channel + Send + Sync + 'static,
    {
        let kv_store = self.kona_cfg.create_key_value_store()?;

        let task_handle = if self.is_offline() {
            task::spawn(async {
                PreimageServer::new(
                    OracleServer::new(preimage),
                    HintReader::new(hint),
                    Arc::new(OfflineHostBackend::new(kv_store)),
                )
                .start()
                .await
                .map_err(SingleChainHostError::from)
            })
        } else {
            let providers = self.create_providers().await?;
            let backend = OnlineHostBackend::new(
                self.clone(),
                kv_store.clone(),
                providers,
                SingleChainHintHandlerWithEigenDA,
            );

            task::spawn(async {
                PreimageServer::new(
                    OracleServer::new(preimage),
                    HintReader::new(hint),
                    Arc::new(backend),
                )
                .start()
                .await
                .map_err(SingleChainHostError::from)
            })
        };

        Ok(task_handle)
    }

    /// Creates the providers with eigenda
    pub async fn create_providers(
        &self,
    ) -> Result<SingleChainProvidersWithEigenDA, SingleChainHostError> {
        let kona_providers = self.kona_cfg.create_providers().await?;

        let eigenda_blob_provider = OnlineEigenDABlobProvider::new_http(
            self.eigenda_proxy_address
                .clone()
                .ok_or(SingleChainHostError::Other("EigenDA API URL must be set"))?,
        );

        Ok(SingleChainProvidersWithEigenDA {
            kona_providers,
            eigenda_blob_provider,
        })
    }

    /// Starts the host in native mode, running both the client and preimage server in the same
    /// process.
    async fn start_native(&self) -> Result<(), SingleChainHostError> {
        let hint = BidirectionalChannel::new()?;
        let preimage = BidirectionalChannel::new()?;

        let server_task = self.start_server(hint.host, preimage.host).await?;
        // Start the client program in a separate child process.

        let client_task = task::spawn(hokulea_client_bin::client::run_direct_client(
            OracleReader::new(preimage.client.clone()),
            HintWriter::new(hint.client.clone()),
            FpvmOpEvmFactory::new(
                HintWriter::new(hint.client),
                OracleReader::new(preimage.client),
            ),
        ));

        let (_, client_result) = tokio::try_join!(server_task, client_task)?;

        // Bubble up the exit status of the client program if execution completes.
        std::process::exit(client_result.is_err() as i32)
    }
}

impl SingleChainHostWithEigenDA {
    /// Returns `true` if the host is running in offline mode.
    pub const fn is_offline(&self) -> bool {
        self.kona_cfg.is_offline() && self.eigenda_proxy_address.is_none()
    }
}

/// Specify the wrapper type
impl OnlineHostBackendCfg for SingleChainHostWithEigenDA {
    type HintType = ExtendedHintType;
    type Providers = SingleChainProvidersWithEigenDA;
}

#[derive(Debug, Clone)]
pub struct SingleChainProvidersWithEigenDA {
    pub kona_providers: SingleChainProviders,
    /// The EigenDA blob provider
    pub eigenda_blob_provider: OnlineEigenDABlobProvider,
}
