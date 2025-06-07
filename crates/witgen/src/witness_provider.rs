use alloy_primitives::{FixedBytes, B256};
use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_compute_proof::compute_kzg_proof;
use hokulea_eigenda::EigenDABlobProvider;
use hokulea_proof::cert_validity::CertValidity;
use hokulea_proof::eigenda_blob_witness::EigenDABlobWitnessData;
use rust_kzg_bn254_primitives::blob::Blob;
use std::sync::{Arc, Mutex};

/// This is a wrapper around OracleEigenDAProvider, with
/// additional functionalities to generate eigenda witness
/// which is KZG proof on the FS point out of the blob itself.
/// OracleEigenDAWitnessProvider is only inteneded to be used outside
/// FPVM or ZKVM. Its sole purpose is to generate KZG proof at the
/// client side
#[derive(Debug, Clone)]
pub struct OracleEigenDAWitnessProvider<T: EigenDABlobProvider> {
    /// Eigenda provider
    pub provider: T,
    /// Store witness data
    pub witness: Arc<Mutex<EigenDABlobWitnessData>>,
}

/// Implement EigenDABlobProvider for OracleEigenDAWitnessProvider
/// whose goal is to prepare preimage sucht that the guest code of zkvm can consume data that is
/// easily verifiable.
/// Note because EigenDA uses filtering approach, in the EigenDABlobWitnessData
/// the number of certs does not have to equal to
/// the number of blobs, since some certs might have been invalid due to incorrect or stale certs
#[async_trait]
impl<T: EigenDABlobProvider + Send> EigenDABlobProvider for OracleEigenDAWitnessProvider<T> {
    type Error = T::Error;

    /// Fetch primage about the recency window
    async fn get_recency_window(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<u64, Self::Error> {
        match self.provider.get_recency_window(altda_commitment).await {
            Ok(recency) => {
                let mut witness = self.witness.lock().unwrap();

                witness.recency.push((altda_commitment.clone(), recency));
                Ok(recency)
            }
            Err(e) => Err(e),
        }
    }

    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        // get cert validity
        match self.provider.get_validity(altda_commitment).await {
            Ok(validity) => {
                let mut witness = self.witness.lock().unwrap();

                // ToDo (bx) could have got l1_head_hash, l1_chain_id from oracle, like what we did in preloader example
                let cert_validity = CertValidity {
                    claimed_validity: validity,
                    // canoe proof generated outside to for potential optimization
                    canoe_proof: None,
                    // the rest of the field needs to be supplied within zkVM
                    l1_head_block_hash: B256::ZERO,
                    l1_chain_id: 0,
                };

                witness
                    .validity
                    .push((altda_commitment.clone(), cert_validity));
                Ok(validity)
            }
            Err(e) => Err(e),
        }
    }

    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error> {
        // only a single blob is returned from a cert
        match self.provider.get_blob(altda_commitment).await {
            Ok(blob) => {
                // Compute kzg proof for the entire blob on a deterministic random point
                let kzg_proof = match compute_kzg_proof(blob.data()) {
                    Ok(p) => p,
                    Err(e) => panic!("cannot generate a kzg proof: {}", e),
                };
                let fixed_bytes: FixedBytes<64> = FixedBytes::from_slice(kzg_proof.as_ref());

                // ToDo(bx) claimed_validity currently set to true, but needs to connect from response from the host
                let mut witness = self.witness.lock().unwrap();
                witness
                    .blob
                    .push((altda_commitment.clone(), blob.clone().into(), fixed_bytes));
                Ok(blob)
            }
            Err(e) => Err(e),
        }
    }
}
