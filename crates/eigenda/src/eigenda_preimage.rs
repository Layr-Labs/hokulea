//! EigenDAPreimageSource Source

use crate::eigenda_data::EncodedPayload;
use crate::traits::EigenDAPreimageProvider;
use crate::HokuleaPreimageError;

use crate::errors::{HokuleaErrorKind, HokuleaStatelessError};
use alloy_primitives::Bytes;
use eigenda_cert::AltDACommitment;

/// A data iterator that reads from a preimage.
#[derive(Debug, Clone)]
pub struct EigenDAPreimageSource<B>
where
    B: EigenDAPreimageProvider + Send,
{
    /// Fetches eigenda preimage.
    pub eigenda_fetcher: B,
}

impl<B> EigenDAPreimageSource<B>
where
    B: EigenDAPreimageProvider + Send,
{
    /// Creates a new preimage source.
    pub const fn new(eigenda_fetcher: B) -> Self {
        Self { eigenda_fetcher }
    }

    /// Fetches the preimages from the source for calldata.
    pub async fn next(
        &mut self,
        calldata: &Bytes,
        l1_inclusion_bn: u64,
    ) -> Result<EncodedPayload, HokuleaErrorKind> {
        let altda_commitment = self.parse(calldata)?;

        info!(target: "eigenda_preimage_source", "parsed an altda commitment of version {}", altda_commitment.cert_version_str());

        // get recency window size, discard the old cert if necessary
        match self
            .eigenda_fetcher
            .get_recency_window(&altda_commitment)
            .await
        {
            Ok(recency) => {
                // see spec <https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#1-rbn-recency-validation>
                if l1_inclusion_bn > altda_commitment.get_rbn() + recency {
                    warn!(
                        "da cert is not recent enough l1_inclusion_bn:{} rbn:{} recency:{}",
                        l1_inclusion_bn,
                        altda_commitment.get_rbn(),
                        recency
                    );
                    return Err(HokuleaPreimageError::NotRecentCert.into());
                }
            }
            Err(e) => return Err(e.into()),
        };

        // get cert validty via preimage oracle, discard cert if invalid
        match self.eigenda_fetcher.get_validity(&altda_commitment).await {
            Ok(true) => (),
            Ok(false) => return Err(HokuleaPreimageError::InvalidCert.into()),
            Err(e) => return Err(e.into()),
        }

        // get encoded payload via preimage oracle
        self.eigenda_fetcher
            .get_encoded_payload(&altda_commitment)
            .await
            .map_err(|e| e.into())
    }

    fn parse(&mut self, data: &Bytes) -> Result<AltDACommitment, HokuleaStatelessError> {
        if data.len() <= 2 {
            // recurse if data is mailformed
            warn!(target: "preimage_source", "Failed to decode altda commitment, skipping");
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
