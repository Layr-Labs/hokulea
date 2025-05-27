use alloc::boxed::Box;
use alloc::sync::Arc;
use alloy_primitives::keccak256;
use async_trait::async_trait;
use hokulea_eigenda::{
    AltDACommitment, EigenDABlobProvider, EigenDAVersionedCert, BYTES_PER_FIELD_ELEMENT,
    RESERVED_INTERFACE_BYTE_FOR_VALIDITY, RESERVED_INTERFACE_BYTE_INDEX,
};
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use rust_kzg_bn254_primitives::blob::Blob;

use crate::errors::HokuleaOracleProviderError;
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
    type Error = HokuleaOracleProviderError;

    /// Query preimage about the validity of a DA cert
    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        let altda_commitment_bytes = altda_commitment.to_bytes();
        // hint the host if it is the first time
        self.oracle
            .write(&ExtendedHintType::EigenDACert.encode_with(&[&altda_commitment_bytes]))
            .await
            .map_err(HokuleaOracleProviderError::Preimage)?;

        let mut address_template = altda_commitment.digest_template();

        // make the call about validity of a altda commitment
        address_template[RESERVED_INTERFACE_BYTE_INDEX] = RESERVED_INTERFACE_BYTE_FOR_VALIDITY;

        let validity = self
            .oracle
            .get(PreimageKey::new(
                *keccak256(address_template),
                PreimageKeyType::GlobalGeneric,
            ))
            .await
            .map_err(HokuleaOracleProviderError::Preimage)?;

        // cert expects returns a boolean
        if validity.is_empty() || validity.len() != 1 {
            return Err(HokuleaOracleProviderError::InvalidCertQueryResponse);
        }

        match validity[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HokuleaOracleProviderError::InvalidCertQueryResponse),
        }
    }

    /// Get V1 blobs. TODO remove in the future if not needed for testing
    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error> {
        let altda_commitment_bytes = altda_commitment.to_bytes();
        self.oracle
            .write(&ExtendedHintType::EigenDACert.encode_with(&[&altda_commitment_bytes]))
            .await
            .map_err(HokuleaOracleProviderError::Preimage)?;

        //info!(target: "eigenda-blobsource", "altda_commitment {:?}", altda_commitment);

        let blob_length_fe: u64 = match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V1(_) => panic!("hokulea does not support eigenda v1. This should have been filtered out at the start of derivation, please report bug"),
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
        self.fetch_blob(field_element_key, blob_length_fe, &mut blob)
            .await?;

        Ok(blob.into())
    }
}

impl<T: CommsClient + Sync + Send> OracleEigenDAProvider<T> {
    /// This is a helper that constructs comm keys for every field element,
    /// The key must be consistnet to the prefetch function from the FetcherWithEigenDASupport
    /// object inside the host
    async fn fetch_blob(
        &mut self,
        mut field_element_key: [u8; 80],
        blob_length: u64,
        blob: &mut [u8],
    ) -> Result<(), HokuleaOracleProviderError> {
        for idx_fe in 0..blob_length {
            // last 8 bytes for index
            let index_byte: [u8; 8] = idx_fe.to_be_bytes();
            field_element_key[72..].copy_from_slice(&index_byte);

            // get field element
            let mut field_element = [0u8; 32];
            self.oracle
                .get_exact(
                    PreimageKey::new(
                        *keccak256(field_element_key),
                        PreimageKeyType::GlobalGeneric,
                    ),
                    &mut field_element,
                )
                .await
                .map_err(HokuleaOracleProviderError::Preimage)?;

            blob[(idx_fe as usize) << 5..(idx_fe as usize + 1) << 5]
                .copy_from_slice(field_element.as_ref());
        }
        Ok(())
    }
}
