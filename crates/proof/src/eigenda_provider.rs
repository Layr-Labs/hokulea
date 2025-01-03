use alloc::boxed::Box;
use alloc::sync::Arc;
use alloy_primitives::{keccak256, Bytes};
use async_trait::async_trait;
use hokulea_eigenda::{BlobInfo, EigenDABlobProvider, BYTES_PER_FIELD_ELEMENT};
use kona_preimage::{errors::PreimageOracleError, CommsClient, PreimageKey, PreimageKeyType};

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

        // the fourth because 0x01010000 in the beginning is metadata
        let item_slice = cert.as_ref();

        // cert should at least contain 32 bytes for header + 4 bytes for commitment type metadata
        if item_slice.len() <= 32 + 4 {
            return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                "does not contain header".into(),
            )));
        }

        // the first four bytes are metadata, like cert version, OP generic commitement
        // see https://github.com/Layr-Labs/eigenda-proxy/blob/main/commitments/mode.go#L39
        // the first byte my guess is the OP
        let cert_blob_info = BlobInfo::decode(&mut &item_slice[4..]).unwrap();
        info!("cert_blob_info {:?}", cert_blob_info);

        // data_length measurs in field element, multiply to get num bytes
        let mut blob: Vec<u8> =
            vec![0; cert_blob_info.blob_header.data_length as usize * BYTES_PER_FIELD_ELEMENT];

        // 96 because our g1 commitment has 64 bytes in v1
        // why 96, the original 4844 has bytes length of 80 (it has 48 bytes for commitment)
        // even then, it is not that the entire 80 bytes are used. Some bytes are empty
        // for solidity optimization, I remember.
        //
        // TODO: investigate later to decide a right size
        let mut blob_key = [0u8; 96];

        // In eigenDA terminology, length describes the number of field element, size describes
        // number of bytes.
        let data_length = cert_blob_info.blob_header.data_length as u64;

        info!("cert_blob_info.blob_header.data_length {:?}", data_length);

        // the common key
        blob_key[..32].copy_from_slice(&cert_blob_info.blob_header.commitment.x);
        blob_key[32..64].copy_from_slice(&cert_blob_info.blob_header.commitment.y);

        for i in 0..data_length {
            blob_key[88..].copy_from_slice(i.to_be_bytes().as_ref());

            let mut field_element = [0u8; 32];
            self.oracle
                .get_exact(
                    PreimageKey::new(*keccak256(blob_key), PreimageKeyType::GlobalGeneric),
                    &mut field_element,
                )
                .await
                .map_err(OracleProviderError::Preimage)?;

            // if field element is 0, it means the host has identified that the data
            // has breached eigenda invariant, i.e cert is valid
            if field_element.is_empty() {
                return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                    "field elememnt is empty, breached eigenda invariant".into(),
                )));
            }

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
