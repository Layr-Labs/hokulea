//! Blob Data Source

use crate::eigenda_data::EigenDABlobData;
use crate::traits::EigenDABlobProvider;

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
    pub altda_fetcher: B,
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
    pub const fn new(altda_fetcher: B) -> Self {
        Self {
            altda_fetcher,
            data: Vec::new(),
            open: false,
        }
    }

    /// Loads blob data into the source if it is not open.
    async fn load_blobs(&mut self, altda_commitment: &Bytes) -> Result<(), BlobProviderError> {
        if self.open {
            return Ok(());
        }

        info!(target: "eigenda-blobsource", "going to fetch through altda fetcher");
        // it should use self.altda_fetcher to get the blob
        let data = self.altda_fetcher.get_blob(altda_commitment).await;
        match data {
            Ok(data) => {
                self.open = true;
                let new_blob = data.clone();
                // new_blob.truncate(data.len()-1);
                let eigenda_blob = EigenDABlobData { blob: new_blob };
                self.data.push(eigenda_blob);

                info!(target: "eigenda-blobsource", "load_blobs {:?}", self.data);

                Ok(())
            }
            Err(_) => {
                self.open = true;
                return Ok(());
            }
        }
    }

    fn next_data(&mut self) -> Result<EigenDABlobData, PipelineResult<Bytes>> {
        info!(target: "eigenda-blobsource", "self.data.is_empty() {:?}", self.data.is_empty());

        if self.data.is_empty() {
            return Err(Err(PipelineError::Eof.temp()));
        }
        Ok(self.data.remove(0))
    }

    pub async fn next(&mut self, altda_commitment: &Bytes) -> PipelineResult<Bytes> {
        info!(target: "eigenda-blobsource", "next");
        self.load_blobs(altda_commitment).await?;
        info!(target: "eigenda-blobsource", "next 1");
        let next_data = match self.next_data() {
            Ok(d) => d,
            Err(e) => return e,
        };
        info!(target: "eigenda-blobsource", "next 2");
        // Decode the blob data to raw bytes.
        // Otherwise, ignore blob and recurse next.
        match next_data.decode() {
            Ok(d) => {
                info!(target: "eigenda-blobsource", "next 3");
                Ok(d)
            }
            Err(_) => {
                warn!(target: "blob-source", "Failed to decode blob data, skipping");
                panic!()
                // todo need to add recursion
                // self.next(altda_commitment).await
            }
        }
    }

    pub fn clear(&mut self) {
        self.data.clear();
        self.open = false;
    }
}
