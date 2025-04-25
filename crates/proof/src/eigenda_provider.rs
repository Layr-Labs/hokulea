use alloc::boxed::Box;
use alloc::sync::Arc;
use alloy_primitives::keccak256;
use async_trait::async_trait;
use hokulea_eigenda::{
    AltDACommitment, EigenDABlobProvider, EigenDAVersionedCert, BYTES_PER_FIELD_ELEMENT,
};
use kona_preimage::{errors::PreimageOracleError, CommsClient, PreimageKey, PreimageKeyType};
use kona_proof::errors::OracleProviderError;
use rust_kzg_bn254_primitives::blob::Blob;

use crate::hint::ExtendedHintType;
use tracing::info;

use alloc::vec;
use alloc::vec::Vec;

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

    /// Get V1 blobs. TODO remove in the future if not needed for testing
    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error> {
        let altda_commitment_bytes = altda_commitment.to_bytes();
        self.oracle
            .write(&ExtendedHintType::EigenDACert.encode_with(&[&altda_commitment_bytes]))
            .await
            .map_err(OracleProviderError::Preimage)?;

        let blob_length_fe: u64 = match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V1(c) => {
                info!(target: "eigenda-blobsource", "blob version: V1");
                c.blob_header.data_length as u64
            }
            EigenDAVersionedCert::V2(c) => {
                info!(target: "eigenda-blobsource", "blob version: V2");
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .length as u64
            }
        };

        // data_length measurs in field element, multiply to get num bytes
        let mut blob: Vec<u8> = vec![0; blob_length_fe as usize * BYTES_PER_FIELD_ELEMENT];
        let field_element_key = altda_commitment.digest_template();
        fetch_blob(
            field_element_key,
            blob_length_fe,
            self.oracle.clone(),
            &mut blob,
        )
        .await?;

        Ok(blob.into())
    }
}

/// This is a helper that constructs comm keys for every field element,
/// The key must be consistnet to the prefetch function from the FetcherWithEigenDASupport
/// object inside the host
async fn fetch_blob<T: CommsClient>(
    mut field_element_key: [u8; 80],
    blob_length: u64,
    oracle: Arc<T>,
    blob: &mut [u8],
) -> Result<(), OracleProviderError> {
    for idx_fe in 0..blob_length {
        // last 8 bytes for index
        let index_byte: [u8; 8] = idx_fe.to_be_bytes();
        field_element_key[72..].copy_from_slice(&index_byte);
        //field_element_key[72..].copy_from_slice(i.to_be_bytes().as_ref());

        // note we didn't use get_exact because host might return an empty list when the cert is
        // wrong with respect to the view function
        // https://github.com/Layr-Labs/eigenda/blob/master/contracts/src/core/EigenDACertVerifier.sol#L165
        //
        let field_element = oracle
            .get(PreimageKey::new(
                *keccak256(field_element_key),
                PreimageKeyType::GlobalGeneric,
            ))
            .await
            .map_err(OracleProviderError::Preimage)?;

        // if field element is 0, it means the host has identified that the data
        // has breached eigenda invariant, i.e cert is valid
        if field_element.is_empty() {
            return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                "field elememnt is empty, breached eigenda invariant".into(),
            )));
        }

        // an eigenda field element contains 32 bytes
        assert!(field_element.len() == 32);

        blob[(idx_fe as usize) << 5..(idx_fe as usize + 1) << 5]
            .copy_from_slice(field_element.as_ref());
    }
    Ok(())
}
