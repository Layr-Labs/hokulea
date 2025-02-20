extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::Bytes;

use eigenda_v2_struct_rust::EigenDAV2Cert;
use rust_kzg_bn254_primitives::blob::Blob;

use crate::cert_validity_proof::CertValidity;

/// stores  
#[derive(Debug, Clone, Default)]
pub struct EigenDABlobWitnessData {
    /// eigenda v2 cert
    pub eigenda_certs: Vec<EigenDAV2Cert>,
    /// blob empty if cert is invalid
    pub eigenda_blobs: Vec<Blob>,
    /// kzg proof on Fiat Shamir points
    pub kzg_proofs: Vec<Bytes>,
    /// indicates the validity of a cert is either true or false
    /// validity contains a zk proof attesting claimed
    /// validity
    pub validity: Vec<CertValidity>,
}

impl EigenDABlobWitnessData {
    pub fn new() -> Self {
        EigenDABlobWitnessData {
            eigenda_certs: Vec::new(),
            eigenda_blobs: Vec::new(),
            kzg_proofs: Vec::new(),
            validity: Vec::new(),
        }
    }
}
