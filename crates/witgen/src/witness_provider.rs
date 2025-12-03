use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_eigenda::{EigenDAPreimageProvider, EncodedPayload};
use hokulea_proof::eigenda_witness::EigenDAPreimage;
use std::sync::{Arc, Mutex};

/// This is a wrapper around OracleEigenDAPreimageProvider.
/// OracleEigenDAPreimageProviderWithPreimage is only inteneded to be used outside
/// FPVM or ZKVM. Its sole purpose is to generate KZG proof at the
/// client side
#[derive(Debug, Clone)]
pub struct OracleEigenDAPreimageProviderWithPreimage<T: EigenDAPreimageProvider> {
    /// Eigenda provider
    pub provider: T,
    /// Store preimage data
    pub preimage: Arc<Mutex<EigenDAPreimage>>,
}

/// Implement EigenDAPreimageProvider for OracleEigenDAPreimageProviderWithPreimage
/// whose goal is to prepare preimage sucht that the guest code of zkvm can consume data that is
/// easily verifiable.
/// Note because EigenDA uses filtering approach, in the EigenDAPreimage
/// the number of certs does not have to equal to
/// the number of encoded payload, since some certs might have been invalid due to incorrect or stale certs
#[async_trait]
impl<T: EigenDAPreimageProvider + Send> EigenDAPreimageProvider
    for OracleEigenDAPreimageProviderWithPreimage<T>
{
    type Error = T::Error;

    async fn check_validity_and_offchain_derivation_version(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        // get cert validity
        match self
            .provider
            .check_validity_and_offchain_derivation_version(altda_commitment)
            .await
        {
            Ok(validity) => {
                let mut preimage = self.preimage.lock().unwrap();

                preimage
                    .validities
                    .push((altda_commitment.clone(), validity));
                Ok(validity)
            }
            Err(e) => Err(e),
        }
    }

    async fn get_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<EncodedPayload, Self::Error> {
        // only a single encoded payload is returned from a cert
        match self.provider.get_encoded_payload(altda_commitment).await {
            Ok(encoded_payload) => {
                let mut witness = self.preimage.lock().unwrap();
                witness
                    .encoded_payloads
                    .push((altda_commitment.clone(), encoded_payload.clone()));
                Ok(encoded_payload)
            }
            Err(e) => Err(e),
        }
    }
}
