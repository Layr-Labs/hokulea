use alloy_primitives::{FixedBytes, B256};
use async_trait::async_trait;
use eigenda_cert::{AltDACommitment, EigenDACertV2, EigenDAVersionedCert};
use hokulea_compute_proof::compute_kzg_proof;
use hokulea_eigenda::EigenDABlobProvider;
use hokulea_proof::cert_validity::CertValidity;
use hokulea_proof::eigenda_blob_witness::EigenDABlobWitnessData;
use rust_kzg_bn254_primitives::blob::Blob;
use std::sync::{Arc, Mutex};
use tracing::debug;

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

                let cert = self.get_cert(altda_commitment);

                witness.recency.push((cert, recency));
                Ok(recency)
            }
            Err(e) => Err(e),
        }
    }

    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        let cert = self.get_cert(altda_commitment);

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

                witness.validity.push((cert, cert_validity));
                Ok(validity)
            }
            Err(e) => Err(e),
        }
    }

    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error> {
        // only a single blob is returned from a cert
        match self.provider.get_blob(altda_commitment).await {
            Ok(blob) => {
                let cert = self.get_cert(altda_commitment);

                // Compute kzg proof for the entire blob on a deterministic random point
                let kzg_proof = match compute_kzg_proof(blob.data()) {
                    Ok(p) => p,
                    Err(e) => panic!("cannot generate a kzg proof: {}", e),
                };
                let fixed_bytes: FixedBytes<64> = FixedBytes::from_slice(kzg_proof.as_ref());

                // ToDo(bx) claimed_validity currently set to true, but needs to connect from response from the host
                let mut witness = self.witness.lock().unwrap();
                witness.blob.push((cert, blob.clone().into(), fixed_bytes));
                Ok(blob)
            }
            Err(e) => Err(e),
        }
    }
}

/// helper function, to be removed after changed EigenDABlobWitnessData to take AltDACommitment
/// in its fields
impl<T: EigenDABlobProvider + Send> OracleEigenDAWitnessProvider<T> {
    pub fn get_cert(&self, altda_commitment: &AltDACommitment) -> EigenDACertV2 {
        // V1 is not supported for secure integration, feel free to contribute
        let cert = match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V2(c) => c,
            _ => panic!("only v2 is supported"),
        };
        debug!(
            target = "OracleEigenDAWitnessProvider",
            "pusehd a cert {}",
            cert.to_digest()
        );
        cert.clone()
    }
}
