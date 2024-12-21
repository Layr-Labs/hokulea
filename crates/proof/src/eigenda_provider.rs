use alloc::boxed::Box;
use alloc::sync::Arc;
use alloy_primitives::{keccak256, Bytes};
use async_trait::async_trait;
use hokulea_eigenda::{BlobInfo, EigenDABlobProvider};
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};

use kona_proof::errors::OracleProviderError;

use crate::hint::ExtendedHintType;
use alloy_rlp::Decodable;
use tracing::info;

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

        // the fourth because 0x01010000 in the beginnin is metadata
        let item_slice = cert.as_ref();
        let cert_blob_info = BlobInfo::decode(&mut &item_slice[4..]).unwrap();
        info!("cert_blob_info {:?}", cert_blob_info);

        // hack - remove later, when cert actually contain length
        let data = self
            .oracle
            .get(PreimageKey::new(
                *keccak256(cert),
                PreimageKeyType::GlobalGeneric,
            ))
            .await
            .map_err(OracleProviderError::Preimage)?;

        let mut blob: Vec<u8> = vec![0; cert_blob_info.blob_header.data_length as usize];

        // 96 because our g1 commitment has 64 bytes in v1
        let mut field_element_key = [0u8; 96];

        // ToDo data_length should be power of 2, proxy should have returned it with dividing 32
        let data_length = cert_blob_info.blob_header.data_length as u64 / 32;

        info!("cert_blob_info.blob_header.data_length {:?}", data_length);

        field_element_key[..32].copy_from_slice(&cert_blob_info.blob_header.commitment.x);
        field_element_key[32..64].copy_from_slice(&cert_blob_info.blob_header.commitment.y);
        for i in 0..data_length {
            field_element_key[88..].copy_from_slice(i.to_be_bytes().as_ref());

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
                .map_err(OracleProviderError::Preimage)?;
            blob[(i as usize) << 5..(i as usize + 1) << 5].copy_from_slice(field_element.as_ref());
        }

        info!("cert_blob_info blob {:?}", blob);

        Ok(blob.into())
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
