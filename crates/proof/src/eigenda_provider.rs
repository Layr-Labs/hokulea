use alloc::boxed::Box;
use alloc::sync::Arc;
use alloy_primitives::keccak256;
use async_trait::async_trait;
use hokulea_eigenda::{BlobInfo, EigenDABlobProvider, BYTES_PER_FIELD_ELEMENT};
use kona_preimage::{errors::PreimageOracleError, CommsClient, PreimageKey, PreimageKeyType};

use kona_proof::errors::OracleProviderError;

use eigenda_v2_struct_rust::EigenDAV2Cert;
use rust_kzg_bn254_primitives::blob::Blob;

use crate::hint::ExtendedHintType;
use alloy_rlp::Encodable;

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
    async fn get_blob(&mut self, meta_data: [u8; 4], cert: &BlobInfo) -> Result<Blob, Self::Error> {
        let mut cert_rlp_bytes = Vec::<u8>::new();
        // rlp encode of cert
        cert.encode(&mut cert_rlp_bytes);

        // proxy_request_key equals to the original data derived from ethereum_source from the next
        // function inside [DataAvailabilityProvider] object
        // it is a bit of extra work but, it makes the interface very clear
        let mut proxy_request_key = meta_data.to_vec();
        proxy_request_key.extend_from_slice(&cert_rlp_bytes);

        self.oracle
            .write(&ExtendedHintType::EigenDACertV1.encode_with(&[&proxy_request_key]))
            .await
            .map_err(OracleProviderError::Preimage)?;

        let blob_length = cert.blob_header.data_length as u64;

        // data_length measurs in field element, multiply to get num bytes
        let mut blob: Vec<u8> = vec![0; blob_length as usize * BYTES_PER_FIELD_ELEMENT];
        let field_element_key = get_eigenda_field_element_key_part(&proxy_request_key);
        fetch_blob(
            field_element_key,
            blob_length,
            self.oracle.clone(),
            &mut blob,
        )
        .await?;

        Ok(blob.into())
    }

    /// get_blob_v2 takes a v2 cert type as opposed to bytes stream
    async fn get_blob_v2(
        &mut self,
        meta_data: [u8; 4],
        cert: &EigenDAV2Cert,
    ) -> Result<Blob, Self::Error> {
        let mut cert_rlp_bytes = Vec::<u8>::new();
        // rlp encode of cert
        cert.encode(&mut cert_rlp_bytes);

        // proxy_request_key equals to the original data derived from ethereum_source from the next
        // function inside [DataAvailabilityProvider] object
        // it is a bit of extra work but, it makes the interface very clear
        let mut proxy_request_key = meta_data.to_vec();
        proxy_request_key.extend_from_slice(&cert_rlp_bytes);

        self.oracle
            .write(&ExtendedHintType::EigenDACertV2.encode_with(&[&proxy_request_key]))
            .await
            .map_err(OracleProviderError::Preimage)?;

        let blob_length = cert
            .blob_inclusion_info
            .blob_certificate
            .blob_header
            .commitment
            .length as u64;

        // data_length measurs in field element, multiply to get num bytes
        let mut blob: Vec<u8> = vec![0; blob_length as usize * BYTES_PER_FIELD_ELEMENT];
        let field_element_key = get_eigenda_field_element_key_part(&proxy_request_key);
        fetch_blob(
            field_element_key,
            blob_length,
            self.oracle.clone(),
            &mut blob,
        )
        .await?;

        Ok(Blob::new(&blob))
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
    for i in 0..blob_length {
        // last 8 bytes for index
        let index_byte: [u8; 8] = i.to_be_bytes();
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

        blob[(i as usize) << 5..(i as usize + 1) << 5].copy_from_slice(field_element.as_ref());
    }
    Ok(())
}

/// This function preprare a holder for a key used to fetch field elements for
/// eigenda blob. The analogous code for eth blob can be found
/// <https://github.com/op-rs/kona/blob/08064c4f464b016dc98671f2b3ea60223cfa11a9/crates/proof/proof/src/l1/blob_provider.rs#L57C9-L57C70>
///
/// EigenDA include the hash digest of the entire cert into the key to ensure
/// uniqueness of the (cert, i, field element). The uniqueness is required for eigenda because
/// 1. if a cert is valid, we can generate a proof for index i that the corressponding
///    polynomial evaluation is some field element.
/// 2. if a cert is invalid, the entire blob is empty, regardless what index is specified
///
/// To see why we can't use kzg commitment like ethereum blob
/// For instance, an adversary can first provide a valid (cert1, 0, A), then it uploads
/// another tuple (cert2, 0, B) containing the invalid cert. However, cert1 and cert2 both
/// has the same commitment. Therefore the value A is overwritten by the empty byte
///
/// By hashing the entire cert, such problem is avoided entirely
///
/// Input is a rlp encoding of the cert for v1 or v2
/// Output returns 80 bytes consistent to the interface used by eth blob
///
pub fn get_eigenda_field_element_key_part(cert_rlp: &[u8]) -> [u8; 80] {
    let mut field_element_key = [0u8; 80];
    field_element_key[..32].copy_from_slice(keccak256(cert_rlp).as_slice());
    field_element_key
}
