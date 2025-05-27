use alloy_primitives::{FixedBytes, B256};
use async_trait::async_trait;
use hokulea_compute_proof::compute_kzg_proof;
use hokulea_eigenda::{AltDACommitment, EigenDABlobProvider, EigenDAVersionedCert};
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
///
/// The first call to that uses the preimage must register the cert, currently it is get_validity
#[async_trait]
impl<T: EigenDABlobProvider + Send> EigenDABlobProvider for OracleEigenDAWitnessProvider<T> {
    type Error = T::Error;

    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        // register cert
        self.init_cert(altda_commitment);

        // get cert validity
        match self.provider.get_validity(altda_commitment).await {
            Ok(validity) => {
                let mut witness = self.witness.lock().unwrap();

                // ToDo (bx) could have got l1_head_hash, l1_chain_id from oracle, like what we did in preloader example
                witness.validity.push(CertValidity {
                    claimed_validity: validity,
                    canoe_proof: Vec::new(),
                    l1_head_block_hash: B256::ZERO,
                    l1_chain_id: 0,
                });
                Ok(validity)
            }
            Err(e) => Err(e),
        }
    }

    /// This function populates
    /// 1. eigenda cert
    /// 2. eigenda blob
    /// 3. kzg blob proof on the random FS point
    /// 4. CertValidity with claimed_validity = true, and receipt = None
    /// The receipt is intended to assert the eigenda cert passing the view call on chain
    /// The receipt generation is not included, it is expected that it takes significantly more time
    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error> {
        // only a single blob is returned from a cert
        match self.provider.get_blob(altda_commitment).await {
            Ok(blob) => {
                // Compute kzg proof for the entire blob on a deterministic random point
                let kzg_proof = match compute_kzg_proof(blob.data()) {
                    Ok(p) => p,
                    Err(e) => panic!("cannot generate a kzg proof: {}", e),
                };
                // ToDo(bx) claimed_validity currently set to true, but needs to connect from response from the host
                let mut witness = self.witness.lock().unwrap();
                let fixed_bytes: FixedBytes<64> = FixedBytes::from_slice(kzg_proof.as_ref());
                witness.kzg_proofs.push(fixed_bytes);
                witness.eigenda_blobs.push(blob.clone().into());

                return Ok(blob);
            }
            Err(e) => {
                return Err(e);
            }
        };
    }
}

impl<T: EigenDABlobProvider + Send> OracleEigenDAWitnessProvider<T> {
    /// Always called by the first preimage contact to record a list of certs
    pub fn init_cert(&mut self, altda_commitment: &AltDACommitment) {
        // The first preimage communication always have to record the cert
        let mut witness = self.witness.lock().unwrap();
        // V1 is not supported for secure integration, feel free to contribute
        let cert = match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V1(_) => panic!("secure v1 integration is not supported"),
            EigenDAVersionedCert::V2(c) => c,
        };
        witness.eigenda_certs.push(cert.clone());
        debug!(
            target = "OracleEigenDAWitnessProvider",
            "pusehd a cert {}",
            cert.digest()
        );
    }
}
