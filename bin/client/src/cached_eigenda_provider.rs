use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use async_trait::async_trait;
use kona_preimage::errors::PreimageOracleError;
use kona_preimage::CommsClient;

use hokulea_eigenda::BlobInfo;
use hokulea_eigenda::EigenDABlobProvider;
use hokulea_proof::eigenda_provider::OracleEigenDAProvider;
use hokulea_cryptography::witness::EigenDABlobWitness;

use kona_proof::errors::OracleProviderError;

use std::sync::Mutex;
use alloc::sync::Arc;

/// CachedOracleEigenDAProvider is a wrapper outside OracleEigenDAProvider. Its intended use
/// case is to fetch all eigenda blobs received during the derivation pipeline. So that it
/// is able to compute and cache the kzg witnesses, which can be verified inside ZKVM by checking
/// the point opening at the random Fiat Shamir evaluation index.
#[derive(Debug, Clone)]
pub struct CachedOracleEigenDAProvider<T: CommsClient> {
    /// The preimage oracle client.
    oracle: OracleEigenDAProvider<T>,
    /// kzg proof witness
    pub witness: Arc<Mutex<EigenDABlobWitness>>,
}

impl<T: CommsClient> CachedOracleEigenDAProvider<T> {
    /// Constructs a new oracle-backed EigenDA provider.
    pub fn new(oracle: OracleEigenDAProvider<T>, witness: Arc<Mutex<EigenDABlobWitness>>) -> Self {
        Self { oracle, witness }
    }
}

#[async_trait]
impl<T: CommsClient + Sync + Send> EigenDABlobProvider for CachedOracleEigenDAProvider<T> {
    type Error = OracleProviderError;

    async fn get_blob(&mut self, cert: &Bytes) -> Result<Bytes, Self::Error> {
        let blob = self.oracle.get_blob(cert).await?;
        let cert_blob_info = match BlobInfo::decode(&mut &cert[4..]) {
            Ok(c) => c,
            Err(_) => {
                return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                    "does not contain header".into(),
                )));
            }
        };

        let mut witness = self.witness.lock().unwrap();

        let _ = witness.push_witness(&blob).map_err(|e| {
            return Err::<T, kona_proof::errors::OracleProviderError>(OracleProviderError::Preimage(PreimageOracleError::Other(
                e.to_string(),
            )));
        });

        let last_commitment = witness.commitments.last().unwrap();

        // make sure locally computed proof equals to returned proof from the provider
        if last_commitment[..32] != cert_blob_info.blob_header.commitment.x[..]
            || last_commitment[32..64] != cert_blob_info.blob_header.commitment.y[..]
        {
            return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                "proxy commitment is different from computed commitment proxy".into(),
            )));
        };

        Ok(blob)
    }
}