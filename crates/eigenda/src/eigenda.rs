//! Contains the [EigenDADataSource], which is a concrete implementation of the
//! [DataAvailabilityProvider] trait for the EigenDA protocol.

use crate::eigenda_blobs::EigenDABlobSource;
use crate::errors::CodecError;
use crate::traits::EigenDABlobProvider;
use crate::BlobInfo;
use alloy_rlp::Decodable;

use alloc::{boxed::Box, fmt::Debug};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use kona_derive::{
    errors::{PipelineEncodingError, PipelineError, PipelineErrorKind},
    sources::EthereumDataSource,
    traits::{BlobProvider, ChainProvider, DataAvailabilityProvider},
    types::PipelineResult,
};
use op_alloy_protocol::BlockInfo;

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
        // then acutally use ethereum da to fetch. items are Bytes
        let cert = self.ethereum_source.next(block_ref).await?;

        // verify if cert is too stale
        let cert_blob_info = BlobInfo::decode(&mut &cert.as_ref()[4..]).unwrap();
        info!("cert_blob_info {:?}", cert_blob_info);
        let rbn = cert_blob_info
            .blob_verification_proof
            .batch_medatada
            .batch_header
            .reference_block_number as u64;
        let l1_block_number = block_ref.number;

        // ToDo make it part of rollup config
        let stale_gap = 100 as u64;

        // check staleness
        if rbn + stale_gap < l1_block_number {
            // return error
            unimplemented!()
        }

        let eigenda_blob = self.eigenda_source.next(&cert).await?;
        Ok(eigenda_blob)
    }

    fn clear(&mut self) {
        self.eigenda_source.clear();
        self.ethereum_source.clear();
    }
}
