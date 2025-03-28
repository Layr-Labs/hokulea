use alloy_primitives::FixedBytes;
use async_trait::async_trait;
use hokulea_compute_proof::compute_kzg_proof;
use hokulea_eigenda::{AltDACommitment, EigenDABlobProvider, EigenDAVersionedCert};
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

#[async_trait]
impl<T: EigenDABlobProvider + Send> EigenDABlobProvider for OracleEigenDAWitnessProvider<T> {
    type Error = T::Error;

    /// This function populates
    /// 1. eigenda cert
    /// 2. eigenda blob
    /// 3. kzg blob proof on the random FS point
    /// 4. CertValidity with claimed_validity = true, and receipt = None
    /// The receipt is intended to assert the eigenda cert passing the view call on chain
    /// The receipt generation is not included, it is expected that it takes significantly more time
    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error> {
        // V1 is not supported for secure integration, feel free to contribute
        let cert = match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V1(_) => panic!("secure v1 integraiton is not supported"),
            EigenDAVersionedCert::V2(c) => c,
        };

        // only a single blob is returned from a cert
        let blob = self.provider.get_blob(altda_commitment).await?;

        // Compute kzg proof for the entire blob on a deterministic random point
        let kzg_proof = match compute_kzg_proof(blob.data()) {
            Ok(p) => p,
            Err(e) => panic!("cannot generate a kzg proof {}", e),
        };

        // populate witness struct
        let mut witness = self.witness.lock().unwrap();
        witness.eigenda_blobs.push(blob.clone());
        let fixed_bytes: FixedBytes<64> = FixedBytes::from_slice(kzg_proof.as_ref());
        witness.kzg_proofs.push(fixed_bytes);
        witness.eigenda_certs.push(cert.clone());
        witness.validity.push(CertValidity {
            claimed_validity: true,
            receipt: None,
        });

        Ok(blob)
    }
}
