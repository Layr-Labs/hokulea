//! Contains the [EigenDADataSource], which is a concrete implementation of the
//! [DataAvailabilityProvider] trait for the EigenDA protocol.

use crate::eigenda_blobs::EigenDABlobSource;
use crate::traits::EigenDABlobProvider;
use crate::errors::CodecError;

use alloc::{boxed::Box, fmt::Debug};
use alloy_primitives::Bytes;
use bytes::buf::Buf;
use async_trait::async_trait;
use kona_derive::{
    sources::EthereumDataSource,
    traits::{BlobProvider, ChainProvider, DataAvailabilityProvider},
    types::PipelineResult,
    errors::{PipelineErrorKind, PipelineError, PipelineEncodingError},
};
use op_alloy_protocol::BlockInfo;
use rust_kzg_bn254::helpers::remove_empty_byte_from_padded_bytes_unchecked;

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
        let item = self.ethereum_source.next(block_ref).await?;

        // just dump all the data out
        info!(target: "eth-datasource", "next item {:?}", item);

        let padded_eigenda_blob = self.eigenda_source.next(&item).await?;
        info!(target: "eigenda-datasource", "eigenda_source_result {:?}", padded_eigenda_blob);

        // get the actual blob as encoded inside blob
        let eigenda_blob = self.default_decode_blob(padded_eigenda_blob)?;

        Ok(eigenda_blob)
    }

    fn clear(&mut self) {
        self.eigenda_source.clear();
        self.ethereum_source.clear();
    }
}

impl<C, B, A> EigenDADataSource<C, B, A> 
where
    C: ChainProvider + Send + Sync + Clone + Debug,
    B: BlobProvider + Send + Sync + Clone + Debug,
    A: EigenDABlobProvider + Send + Sync + Clone + Debug,
{
    // https://github.com/Layr-Labs/eigenda/blob/1345e77c8a91fed8e5e33f02c3e32c9ed9921670/api/clients/codecs/default_blob_codec.go#L44
    fn default_decode_blob(&self, padded_eigenda_blob: Bytes) -> PipelineResult<Bytes> {
        if padded_eigenda_blob.len() < 32 {
            // ToDo format error better
            //return Err(PipelineErrorKind::Temporary(PipelineError::BadEncoding(PipelineEncodingError::SpanBatchError(()))));
            unimplemented!()
        }

        info!(target: "eigenda-datasource", "padded_eigenda_blob {:?}", padded_eigenda_blob);

        let content_size = padded_eigenda_blob.slice(2..6).get_u32();
        info!(target: "eigenda-datasource", "content_size {:?}", content_size);
        let codec_data = padded_eigenda_blob.slice(32..);

        let blob_content = remove_empty_byte_from_padded_bytes_unchecked(codec_data.as_ref());
        let blob_content: Bytes = blob_content.into();

        Ok(blob_content.slice(..content_size as usize))
    }

}