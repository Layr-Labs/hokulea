use alloc::boxed::Box;
use alloc::sync::Arc;
use alloy_primitives::{keccak256, Bytes};
use async_trait::async_trait;
use hokulea_eigenda::EigenDABlobProvider;
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};

use kona_proof::errors::OracleProviderError;

use crate::hint::ExtendedHintType;

/// The oracle-backed EigenDA provider for the client program.
#[derive(Debug, Clone)]
pub struct OracleEigenDAProvider<T: CommsClient> {
    /// The preimage oracle client.
    oracle: Arc<T>,
}

impl<T: CommsClient> OracleEigenDAProvider<T> {
    /// Constructs a new oracle-backed EigenDA provider.
    pub fn new(oracle: Arc<T>) -> Self {
        Self { oracle }
    }
}

#[async_trait]
impl<T: CommsClient + Sync + Send> EigenDABlobProvider for OracleEigenDAProvider<T> {
    type Error = OracleProviderError;

    async fn get_blob(&mut self, cert: &Bytes) -> Result<Bytes, Self::Error> {
        self.oracle
            .write(&ExtendedHintType::EigenDACommitment.encode_with(&[cert]))
            .await
            .map_err(OracleProviderError::Preimage)?;
        let data = self
            .oracle
            .get(PreimageKey::new(
                *keccak256(cert),
                PreimageKeyType::GlobalGeneric,
            ))
            .await
            .map_err(OracleProviderError::Preimage)?;
        Ok(data.into())
    }

    async fn get_element(&mut self, cert: &Bytes, element: &Bytes) -> Result<Bytes, Self::Error> {
        self.oracle
            .write(&ExtendedHintType::EigenDACommitment.encode_with(&[cert]))
            .await
            .map_err(OracleProviderError::Preimage)?;

        let cert_point_key = Bytes::copy_from_slice(&[cert.to_vec(), element.to_vec()].concat());

        self.oracle
            .write(&ExtendedHintType::EigenDACommitment.encode_with(&[&cert_point_key]))
            .await
            .map_err(OracleProviderError::Preimage)?;
        let data = self
            .oracle
            .get(PreimageKey::new(
                *keccak256(cert_point_key),
                PreimageKeyType::GlobalGeneric,
            ))
            .await
            .map_err(OracleProviderError::Preimage)?;
        Ok(data.into())
    }
}
