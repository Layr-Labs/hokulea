//! Blob Data Source

use crate::traits::EigenDABlobProvider;
use crate::HokuleaPreimageError;
use crate::{eigenda_data::EigenDABlobData, AltDACommitment};

use crate::errors::{HokuleaErrorKind, HokuleaStatelessError};
use alloc::vec::Vec;
use alloy_primitives::Bytes;

/// A data iterator that reads from a blob.
#[derive(Debug, Clone)]
pub struct EigenDABlobSource<B>
where
    B: EigenDABlobProvider + Send,
{
    /// Fetches blobs.
    pub eigenda_fetcher: B,
}

impl<B> EigenDABlobSource<B>
where
    B: EigenDABlobProvider + Send,
{
    /// Creates a new blob source.
    pub const fn new(eigenda_fetcher: B) -> Self {
        Self { eigenda_fetcher }
    }

    /// Fetches the next blob from the source.
    pub async fn next(
        &mut self,
        calldata: &Bytes,
        l1_inclusion_bn: u64,
    ) -> Result<EigenDABlobData, HokuleaErrorKind> {
        let eigenda_commitment = self.parse(calldata)?;

        // get recency window size, discard the old cert if necessary
        match self
            .eigenda_fetcher
            .get_recency_window(&eigenda_commitment)
            .await
        {
            Ok(recency) => {
                // see spec <https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#1-rbn-recency-validation>
                if l1_inclusion_bn > eigenda_commitment.get_rbn() + recency {
                    warn!(
                        "da cert is not recent enough l1_inclusion_bn:{} rbn:{} recency:{}",
                        l1_inclusion_bn,
                        eigenda_commitment.get_rbn(),
                        recency
                    );
                    return Err(HokuleaPreimageError::NotRecentCert.into());
                }
            }
            Err(e) => return Err(e.into()),
        };

        // get cert validty via preimage oracle, discard cert if invalid
        match self.eigenda_fetcher.get_validity(&eigenda_commitment).await {
            Ok(true) => (),
            Ok(false) => return Err(HokuleaPreimageError::InvalidCert.into()),
            Err(e) => return Err(e.into()),
        }

        // get blob via preimage oracle
        match self.eigenda_fetcher.get_blob(&eigenda_commitment).await {
            Ok(data) => {
                let new_blob: Vec<u8> = data.into();

                let eigenda_blob = EigenDABlobData {
                    blob: new_blob.into(),
                };

                Ok(eigenda_blob)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn parse(&mut self, data: &Bytes) -> Result<AltDACommitment, HokuleaStatelessError> {
        if data.len() <= 2 {
            // recurse if data is mailformed
            warn!(target: "blob_source", "Failed to decode blob data, skipping");
            return Err(HokuleaStatelessError::InsufficientEigenDACertLength);
        }
        let altda_commitment: AltDACommitment = match data[1..].try_into() {
            Ok(a) => a,
            Err(e) => {
                error!("failed to parse altda commitment {}", e);
                return Err(HokuleaStatelessError::ParseError(e));
            }
        };
        Ok(altda_commitment)
    }
}
