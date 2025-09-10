//! Contains the [EigenDAPreimageSource] and EigenDA blob derivation, which is a concrete
//! implementation of the [DataAvailabilityProvider] trait for the EigenDA protocol.
use crate::traits::EigenDAPreimageProvider;
use crate::{eigenda_preimage::EigenDAPreimageSource, HokuleaErrorKind};
use kona_derive::errors::PipelineErrorKind;

use crate::eigenda_data::EncodedPayload;
use alloc::vec::Vec;
use alloc::{boxed::Box, fmt::Debug};
use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use kona_derive::{
    errors::PipelineError,
    sources::EthereumDataSource,
    traits::{BlobProvider, ChainProvider, DataAvailabilityProvider},
    types::PipelineResult,
};
use kona_protocol::{BlockInfo, DERIVATION_VERSION_0};
use tracing::warn;

#[derive(Debug, Clone)]
pub enum EigenDAOrCalldata {
    EigenDA(EncodedPayload),
    Calldata(Bytes),
}

/// A factory for creating an EigenDADataSource iterator. The internal behavior is that
/// data is fetched from eigenda or stays as it is if Eth calldata is desired. Those data
/// are cached. When next() is called it just returns the next cached encoded payload.
/// Otherwise, EOF is sent if iterator is empty
#[derive(Debug, Clone)]
pub struct EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Clone,
    B: BlobProvider + Send + Clone,
    A: EigenDAPreimageProvider + Send + Clone,
{
    /// The ethereum source.
    pub ethereum_source: EthereumDataSource<C, B>,
    /// The eigenda preimage source.
    pub eigenda_source: EigenDAPreimageSource<A>,
    /// Whether the source is open. When it is open, the next() call will consume data
    /// at this current stage, as opposed to pull it from the next stage
    pub open: bool,
    /// eigenda encoded payload or ethereum calldata that does not use eigenda in failover mode
    pub data: Vec<EigenDAOrCalldata>,
}

impl<C, B, A> EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Clone + Debug,
    B: BlobProvider + Send + Clone + Debug,
    A: EigenDAPreimageProvider + Send + Clone + Debug,
{
    /// Instantiates a new [EigenDADataSource].
    pub const fn new(
        ethereum_source: EthereumDataSource<C, B>,
        eigenda_source: EigenDAPreimageSource<A>,
    ) -> Self {
        Self {
            ethereum_source,
            eigenda_source,
            open: false,
            data: Vec::new(),
        }
    }
}

#[async_trait]
impl<C, B, A> DataAvailabilityProvider for EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Sync + Clone + Debug,
    B: BlobProvider + Send + Sync + Clone + Debug,
    A: EigenDAPreimageProvider + Send + Sync + Clone + Debug,
{
    type Item = Bytes;

    async fn next(
        &mut self,
        block_ref: &BlockInfo,
        batcher_addr: Address,
    ) -> PipelineResult<Self::Item> {
        debug!("Data Available Source next {} {}", block_ref, batcher_addr);
        // if loading failed for provider reason, the all data are reloaded next time,
        // no data is consumed at this point
        self.load_eigenda_or_calldata(block_ref, batcher_addr)
            .await?;

        match self.next_data()? {
            EigenDAOrCalldata::Calldata(c) => return Ok(c),
            EigenDAOrCalldata::EigenDA(encoded_payload) => {
                match encoded_payload.decode() {
                    Ok(c) => return Ok(c),
                    // if encodoed payload cannot be decoded, try next data, since load_encoded_payload
                    // has openned the stage already, it won't load the l1 block again
                    Err(_) => self.next(block_ref, batcher_addr).await,
                }
            }
        }
    }

    fn clear(&mut self) {
        self.data.clear();
        self.ethereum_source.clear();
        self.open = false;
    }
}

impl<C, B, A> EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Sync + Clone + Debug,
    B: BlobProvider + Send + Sync + Clone + Debug,
    A: EigenDAPreimageProvider + Send + Sync + Clone + Debug,
{
    // load calldata, currenly there is only one cert per calldata
    // this is still required, in case the provider returns error
    // the open variable ensures we don't have to load the ethereum source again
    // If this function returns early with error, no state is corrupted
    async fn load_eigenda_or_calldata(
        &mut self,
        block_ref: &BlockInfo,
        batcher_addr: Address,
    ) -> PipelineResult<()> {
        if self.open {
            return Ok(());
        }

        let mut calldata_list: Vec<Bytes> = Vec::new();
        // drain all the ethereum calldata from the l1 block
        loop {
            match self.ethereum_source.next(block_ref, batcher_addr).await {
                Ok(d) => calldata_list.push(d),
                Err(e) => {
                    // break out the loop after having all batcher calldata for that block number
                    if let PipelineErrorKind::Temporary(PipelineError::Eof) = e {
                        break;
                    }
                    return Err(e);
                }
            };
        }

        // all data returnable to l1 retriever, including both eigenda encoded payload and Derivation version 0
        // eth data defined
        let mut self_contained_data: Vec<EigenDAOrCalldata> = Vec::new();

        for data in &calldata_list {
            // if data is op channel frame
            if data[0] == DERIVATION_VERSION_0 {
                info!(
                    target = "eth-datasource",
                    stage = "hokulea_load_encoded_payload",
                    "use ethda at l1 block number {}",
                    block_ref.number
                );
                self_contained_data.push(EigenDAOrCalldata::Calldata(data.clone()));
            } else {
                // retrieve all data from eigenda
                match self.eigenda_source.next(data, block_ref.number).await {
                    Err(e) => match e {
                        HokuleaErrorKind::Discard(e) => {
                            warn!("Hokulea derivation discard {}", e);
                            continue;
                        }
                        HokuleaErrorKind::Temporary(e) => {
                            return Err(PipelineError::Provider(e).temp())
                        }
                        HokuleaErrorKind::Critical(e) => {
                            return Err(PipelineError::Provider(e).crit())
                        }
                    },
                    Ok(encoded_payload) => {
                        self_contained_data.push(EigenDAOrCalldata::EigenDA(encoded_payload));
                    }
                }
            }
        }

        self.data = self_contained_data;
        self.open = true;
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn next_data(&mut self) -> Result<EigenDAOrCalldata, PipelineErrorKind> {
        // if all eigenda encoded payload are processed, send signal to driver to advance
        if self.data.is_empty() {
            return Err(PipelineError::Eof.temp());
        }
        Ok(self.data.remove(0))
    }
}
