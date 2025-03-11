use hokulea_eigenda::{EigenDABlobProvider, AltDACommitment, EigenDAVersionedCert};
use hokulea_proof::eigenda_blob_witness::EigenDABlobWitnessData;
use std::sync::{Arc, Mutex};
use rust_kzg_bn254_primitives::blob::Blob;
use async_trait::async_trait;
use hokulea_compute_kzg_proof::compute_kzg_proof;
use alloy_primitives::FixedBytes;

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

    async fn get_blob(
        &mut self, altda_commitment: &AltDACommitment
    ) -> Result<Blob, Self::Error> {
        // V1 is not supported for secure integration, feel free to contribute
        let cert = match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V1(_) => panic!("secure v1 integraiton is not supported"),
            EigenDAVersionedCert::V2(c) => c,
        };
        

        // only a single blob is returned from a cert
        let blob = self.provider.get_blob(altda_commitment).await?;
        
        // Compute kzg proof for the entire blob on a deterministic random point
        let kzg_proof = match compute_kzg_proof(&blob.data()) {
            Ok(p) => p,
            Err(e) => panic!("cannot generate a kzg proof {}", e),
        };
        
        // populate witness struct
        let mut witness = self.witness.lock().unwrap();
        witness.eigenda_blobs.push(blob.clone());
        let fixed_bytes: FixedBytes<64> = FixedBytes::from_slice(kzg_proof.as_ref());
        witness.kzg_proofs.push(fixed_bytes);
        witness.eigenda_certs.push(cert.clone()); 
                
        Ok(blob)         
    }
}