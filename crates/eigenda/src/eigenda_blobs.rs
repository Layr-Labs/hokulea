//! Blob Data Source

use crate::traits::EigenDABlobProvider;
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
        _l1_inclusion_bn: u64,
    ) -> Result<EigenDABlobData, HokuleaErrorKind> {
        let eigenda_commitment = self.parse(calldata)?;

        // for recency check, there are two approaches, depending how many interface we want
        // 1. define a new interface in EigenDABlobProvider trait to get_recency_window. Then discard the old cert.
        //    This requires add new impl in OracleEigenDAProvider proof/src/eigenda_provider.rs
        //    and OracleEigenDAWitnessProvider from witgen/src/witness_provider. We will also add new field in EigenDABlobWitnessData
        //    which is populated in the get_recency_window path
        // 2. let get_blob returns 2 struct (Blob, recency), the provider can set Blob to empty if recency
        //    failed, but it requires changing the get_blob interface of EigenDABlobProvider, to additionally accept
        //    l1_inclusion_bn. Inside get_blob, the get_recency_window is fetched first.
        // RECENCY IS unhandled at the moment

        // overload the preimage oracle returns recency checks, it is also out of consideration of
        // code reuse, alternative is to add a function into EigenDABlobProvider for recency window.
        // But that creates some boilerplate code, also in the future, we will have a single onchain
        // verifier entry that also checks the recency, and therefore entirely making it unnecessary
        // to check it in the offchain hokulea code.
        match self.eigenda_fetcher.get_blob(&eigenda_commitment).await {
            Ok(data) => {
                let new_blob: Vec<u8> = data.into();

                let eigenda_blob = EigenDABlobData {
                    blob: new_blob.into(),
                };

                Ok(eigenda_blob)
            }
            Err(e) => {
                warn!("EigenDA blob source cannot fetch {}", e);
                Err(e.into())
            }
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
                // same handling procudure as in kona
                // https://github.com/op-rs/kona/blob/ace7c8918be672c1761eba3bd7480cdc1f4fa115/crates/protocol/derive/src/stages/frame_queue.rs#L130
                // https://github.com/op-rs/kona/blob/ace7c8918be672c1761eba3bd7480cdc1f4fa115/crates/protocol/derive/src/stages/frame_queue.rs#L165
                error!("failed to parse altda commitment {}", e);
                return Err(HokuleaStatelessError::ParseError(e));
            }
        };
        Ok(altda_commitment)
    }
}
