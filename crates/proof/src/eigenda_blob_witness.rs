extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::Bytes;

use eigenda_v2_struct_rust::EigenDAV2Cert;
use rust_kzg_bn254_primitives::blob::Blob;

/// stores  
#[derive(Debug, Clone, Default)]
pub struct EigenDABlobWitnessData {
    /// eigenda v2 cert
    pub eigenda_certs: Vec<EigenDAV2Cert>,
    /// blob empty if cert is invalid
    pub eigenda_blobs: Vec<Blob>,
    /// kzg proof on Fiat Shamir points
    pub kzg_proofs: Vec<Bytes>,
    /// a zk proof attesting the Cert is valid
    /// each element is a tuple indicating
    /// (validity, proof for validity) regardless of
    /// validity is true or false
    pub validity_proofs: Vec<(bool, Bytes)>,
}

///
impl EigenDABlobWitnessData {
    pub fn new() -> Self {
        EigenDABlobWitnessData {
            eigenda_certs: Vec::new(),
            eigenda_blobs: Vec::new(),
            kzg_proofs: Vec::new(),
            validity_proofs: Vec::new(),
        }
    }
}
