extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::Bytes;

use eigenda_v2_struct_rust::EigenDAV2Cert;

/// stores  
#[derive(Debug, Clone, Default)]
pub struct EigenDABlobWitnessData {
    /// eigenda v2 cert
    pub eigenda_certs: Vec<EigenDAV2Cert>,
    /// blob empty if cert is invalid
    pub eigenda_blobs: Vec<Bytes>,
    /// kzg proof on Fiat Shamir points
    pub proofs: Vec<Bytes>,
    /// is Cert valid
    pub is_valid: Vec<bool>,
}

/// 
impl EigenDABlobWitnessData {
    pub fn new() -> Self {
        EigenDABlobWitnessData {
            eigenda_certs: Vec::new(),
            eigenda_blobs: Vec::new(),
            proofs: Vec::new(),
            is_valid: Vec::new(),
        }
    }
}

