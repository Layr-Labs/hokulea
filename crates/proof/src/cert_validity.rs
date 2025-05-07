use alloc::vec::Vec;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertValidity {
    /// the claim about if the cert is valid
    pub claimed_validity: bool,
    /// a zkvm proof attesting the above result    
    pub receipt: Vec<u8>,
    /// block hash where view call anchored at
    pub l1_head_block_hash: B256,
    /// block number corresponding to the hash above. This is checked against l1_head_block_hash in the zk view proof
    pub l1_head_block_number: u64,
}
