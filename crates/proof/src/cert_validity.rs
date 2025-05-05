use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertValidity {
    /// the claim about if the cert is valid
    pub claimed_validity: bool,
    /// a zkvm proof attesting the above result
    /// in dev mode, receipt is ignored
    /// in the future, to make it generic for sp1-contract-call
    /// Opaque zk proof
    pub receipt: Option<Vec<u8>>,
}
