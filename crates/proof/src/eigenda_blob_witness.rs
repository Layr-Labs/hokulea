extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::FixedBytes;

use eigenda_v2_struct::EigenDAV2Cert;

use crate::cert_validity::CertValidity;
use serde::{Deserialize, Serialize};

/// One EigenDABlobWitnessData corresponds to one EigenDA cert
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EigenDABlobWitnessData {
    /// eigenda v2 cert
    pub eigenda_certs: Vec<EigenDAV2Cert>,
    /// blob empty if cert is invalid
    /// ToDo make Blob Serializable
    pub eigenda_blobs: Vec<Vec<u8>>,
    /// kzg proof on Fiat Shamir points
    pub kzg_proofs: Vec<FixedBytes<64>>,
    /// indicates the validity of a cert is either true or false
    /// validity contains a zk proof attesting claimed
    /// validity
    pub validity: Vec<CertValidity>,
}
