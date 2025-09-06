use alloc::boxed::Box;
use alloc::sync::Arc;
use alloy_primitives::keccak256;
use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_eigenda::{
    EigenDAPreimageProvider, EncodedPayload, BYTES_PER_FIELD_ELEMENT,
    RESERVED_EIGENDA_API_BYTE_FOR_RECENCY, RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY,
    RESERVED_EIGENDA_API_BYTE_INDEX,
};
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};

use crate::errors::HokuleaOracleProviderError;
use crate::hint::ExtendedHintType;

use alloc::vec;
use alloc::vec::Vec;

/// The oracle-backed EigenDA provider for the client program.
#[derive(Debug, Clone)]
pub struct OracleEigenDAPreimageProvider<T: CommsClient> {
    /// The preimage oracle client.
    oracle: Arc<T>,
}

impl<T: CommsClient> OracleEigenDAPreimageProvider<T> {
    /// Constructs a new oracle-backed EigenDA provider.
    pub fn new(oracle: Arc<T>) -> Self {
        Self { oracle }
    }
}

#[async_trait]
impl<T: CommsClient + Sync + Send> EigenDAPreimageProvider for OracleEigenDAPreimageProvider<T> {
    type Error = HokuleaOracleProviderError;

    /// Fetch preimage about the recency window
    async fn get_recency_window(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<u64, Self::Error> {
        let altda_commitment_bytes = altda_commitment.to_rlp_bytes();
        // hint the host about a new altda commitment. If it is the first time the host receiving it, the
        // host then prepares all the necessary preimage; if not, the host simply returns data from its cache
        self.oracle
            .write(&ExtendedHintType::EigenDACert.encode_with(&[&altda_commitment_bytes]))
            .await
            .map_err(HokuleaOracleProviderError::Preimage)?;

        let mut address_template = altda_commitment.digest_template();

        // make the call about recency of a altda commitment
        address_template[RESERVED_EIGENDA_API_BYTE_INDEX] = RESERVED_EIGENDA_API_BYTE_FOR_RECENCY;

        let recency_bytes = self
            .oracle
            .get(PreimageKey::new(
                *keccak256(address_template),
                PreimageKeyType::GlobalGeneric,
            ))
            .await
            .map_err(HokuleaOracleProviderError::Preimage)?;

        // recency is 8 bytes
        if recency_bytes.is_empty() || recency_bytes.len() != 8 {
            return Err(HokuleaOracleProviderError::InvalidCertQueryResponse);
        }

        let mut buf: [u8; 8] = [0; 8];
        buf.copy_from_slice(&recency_bytes);

        // use BigEndian
        Ok(u64::from_be_bytes(buf))
    }

    /// Query preimage about the validity of a DA cert
    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        let altda_commitment_bytes = altda_commitment.to_rlp_bytes();
        // hint the host about a new altda commitment. If it is the first time the host receiving it, the
        // host then prepares all the necessary preimage; if not, the host simply returns data from its cache
        self.oracle
            .write(&ExtendedHintType::EigenDACert.encode_with(&[&altda_commitment_bytes]))
            .await
            .map_err(HokuleaOracleProviderError::Preimage)?;

        let mut address_template = altda_commitment.digest_template();

        // make the call about validity of a altda commitment
        address_template[RESERVED_EIGENDA_API_BYTE_INDEX] = RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY;

        let validity = self
            .oracle
            .get(PreimageKey::new(
                *keccak256(address_template),
                PreimageKeyType::GlobalGeneric,
            ))
            .await
            .map_err(HokuleaOracleProviderError::Preimage)?;

        // validity is expected as a boolean
        if validity.is_empty() || validity.len() != 1 {
            return Err(HokuleaOracleProviderError::InvalidCertQueryResponse);
        }

        match validity[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HokuleaOracleProviderError::InvalidCertQueryResponse),
        }
    }

    /// Get encoded payload
    async fn get_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<EncodedPayload, Self::Error> {
        let altda_commitment_bytes = altda_commitment.to_rlp_bytes();
        // hint the host about a new altda commitment. If it is the first time the host receiving it, the
        // host then prepares all the necessary preimage; if not, the host simply returns data from its cache
        self.oracle
            .write(&ExtendedHintType::EigenDACert.encode_with(&[&altda_commitment_bytes]))
            .await
            .map_err(HokuleaOracleProviderError::Preimage)?;

        let blob_length_fe = altda_commitment.get_num_field_element();

        // data_length measurs in field element, multiply to get num bytes
        let mut encoded_payload: Vec<u8> = vec![0; blob_length_fe * BYTES_PER_FIELD_ELEMENT];
        let field_element_key = altda_commitment.digest_template();
        self.fetch_encoded_payload(
            field_element_key,
            blob_length_fe as u64,
            &mut encoded_payload,
        )
        .await?;

        Ok(EncodedPayload {
            encoded_payload: encoded_payload.into(),
        })
    }
}

impl<T: CommsClient + Sync + Send> OracleEigenDAPreimageProvider<T> {
    /// This is a helper that constructs comm keys for every field element,
    /// The key must be consistnet to the prefetch function from the FetcherWithEigenDASupport
    /// object inside the host
    async fn fetch_encoded_payload(
        &mut self,
        mut field_element_key: [u8; 80],
        blob_length: u64,
        encoded_payload: &mut [u8],
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

            encoded_payload[(idx_fe as usize) << 5..(idx_fe as usize + 1) << 5]
                .copy_from_slice(field_element.as_ref());
        }
        Ok(())
    }
}
