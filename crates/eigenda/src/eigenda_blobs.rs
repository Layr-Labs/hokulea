//! Blob Data Source

use crate::traits::EigenDABlobProvider;
use crate::{eigenda_data::EigenDABlobData, AltDACommitment};

use alloc::vec::Vec;
use alloy_primitives::Bytes;
use kona_derive::{
    errors::{BlobProviderError, PipelineError},
    types::PipelineResult,
};

/// A data iterator that reads from a blob.
#[derive(Debug, Clone)]
pub struct EigenDABlobSource<B>
where
    B: EigenDABlobProvider + Send,
{
    /// Fetches blobs.
    pub eigenda_fetcher: B,
    /// EigenDA blobs.
    pub data: Vec<EigenDABlobData>,
    /// Whether the source is open.
    pub open: bool,
}

impl<B> EigenDABlobSource<B>
where
    B: EigenDABlobProvider + Send,
{
    /// Creates a new blob source.
    pub const fn new(eigenda_fetcher: B) -> Self {
        Self {
            eigenda_fetcher,
            data: Vec::new(),
            open: false,
        }
    }

    /// Fetches the next blob from the source.
    pub async fn next(&mut self, eigenda_commitment: &AltDACommitment) -> PipelineResult<Bytes> {
        self.load_blobs(eigenda_commitment).await?;
        let next_data = match self.next_data() {
            Ok(d) => d,
            Err(e) => return e,
        };
        // Decode the blob data to raw bytes.
        // Otherwise, ignore blob and recurse next.
        match next_data.decode() {
            Ok(d) => Ok(d),
            Err(e) => {
                warn!(target: "blob-source", "Failed to decode blob data, skipping {}", e);
                panic!()
            }
        }
    }

    /// Clears the source.
    pub fn clear(&mut self) {
        self.data.clear();
        self.open = false;
    }

    /// Loads blob data into the source if it is not open.
    async fn load_blobs(
        &mut self,
        eigenda_commitment: &AltDACommitment,
    ) -> Result<(), BlobProviderError> {
        if self.open {
            return Ok(());
        }

        match self.eigenda_fetcher.get_blob(eigenda_commitment).await {
            Ok(data) => {
                self.open = true;
                let new_blob: Vec<u8> = data.into();
                let eigenda_blob = EigenDABlobData {
                    blob: new_blob.into(),
                };
                self.data.push(eigenda_blob);

                info!(target: "eigenda-blobsource", "load_blobs {:?}", self.data);

                Ok(())
            }
            Err(e) => {
                error!("EigenDA blob source fetching error {}", e);
                self.open = true;
                Ok(())
            }
        }
    }

    // TODO refactor later to avoid large object movement
    #[allow(clippy::result_large_err)]
    fn next_data(&mut self) -> Result<EigenDABlobData, PipelineResult<Bytes>> {
        info!(target: "eigenda-blobsource", "self.data.is_empty() {:?}", self.data.is_empty());

        if self.data.is_empty() {
            return Err(Err(PipelineError::Eof.temp()));
        }
        Ok(self.data.remove(0))
    }
}
