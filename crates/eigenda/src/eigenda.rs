//! Contains the [EigenDADataSource], which is a concrete implementation of the
//! [DataAvailabilityProvider] trait for the EigenDA protocol.
use crate::eigenda_blobs::EigenDABlobSource;
use crate::traits::EigenDABlobProvider;
use crate::AltDACommitment;

use alloc::{boxed::Box, fmt::Debug};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use kona_derive::{
    errors::PipelineError,
    sources::EthereumDataSource,
    traits::{BlobProvider, ChainProvider, DataAvailabilityProvider},
    types::PipelineResult,
};
use maili_protocol::{BlockInfo, DERIVATION_VERSION_0};

/// A factory for creating an Ethereum data source provider.
#[derive(Debug, Clone)]
pub struct EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Clone,
    B: BlobProvider + Send + Clone,
    A: EigenDABlobProvider + Send + Clone,
{
    /// The blob source.
    pub ethereum_source: EthereumDataSource<C, B>,
    /// The eigenda source.
    pub eigenda_source: EigenDABlobSource<A>,
}

impl<C, B, A> EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Clone + Debug,
    B: BlobProvider + Send + Clone + Debug,
    A: EigenDABlobProvider + Send + Clone + Debug,
{
    /// Instantiates a new [EigenDADataSource].
    pub const fn new(
        ethereum_source: EthereumDataSource<C, B>,
        eigenda_source: EigenDABlobSource<A>,
    ) -> Self {
        Self {
            ethereum_source,
            eigenda_source,
        }
    }
}

#[async_trait]
impl<C, B, A> DataAvailabilityProvider for EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Sync + Clone + Debug,
    B: BlobProvider + Send + Sync + Clone + Debug,
    A: EigenDABlobProvider + Send + Sync + Clone + Debug,
{
    type Item = Bytes;

    async fn next(&mut self, block_ref: &BlockInfo) -> PipelineResult<Self::Item> {
        // data is either an op channel frame or an eigenda cert
        let data = self.ethereum_source.next(block_ref).await?;

        // if data is op channel framce
        if data[0] == DERIVATION_VERSION_0 {
            // see https://github.com/op-rs/kona/blob/ace7c8918be672c1761eba3bd7480cdc1f4fa115/crates/protocol/protocol/src/frame.rs#L140
            return Ok(data);
        }
        if data.len() <= 2 {
            return Err(PipelineError::NotEnoughData.temp());
        }

        let altda_commitment: AltDACommitment = match data[1..].try_into() {
            Ok(a) => a,
            Err(e) => {
                // same handling procudure as in kona
                // https://github.com/op-rs/kona/blob/ace7c8918be672c1761eba3bd7480cdc1f4fa115/crates/protocol/derive/src/stages/frame_queue.rs#L130
                // https://github.com/op-rs/kona/blob/ace7c8918be672c1761eba3bd7480cdc1f4fa115/crates/protocol/derive/src/stages/frame_queue.rs#L165
                error!("failed to parse altda commitment {}", e);
                return Err(PipelineError::NotEnoughData.temp());
            }
        };

        // see https://github.com/ethereum-optimism/optimism/blob/0bb2ff57c8133f1e3983820c0bf238001eca119b/op-alt-da/damgr.go#L211
        // TODO check rbn + STALE_GAP < l1_block_number {
        info!("altda_commitment {:?}", altda_commitment.digest_template());
        let eigenda_blob = self.eigenda_source.next(&altda_commitment).await?;
        Ok(eigenda_blob)
    }

    fn clear(&mut self) {
        self.eigenda_source.clear();
        self.ethereum_source.clear();
    }
}
