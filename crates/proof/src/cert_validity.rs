use alloc::vec::Vec;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// The l1_head from the kona_cfg is chosen to anchor the view call.
/// This is because EVM can refer to block hash 8192 most recent block
/// (After Pectra upgrade, <https://eips.ethereum.org/EIPS/eip-2935>).
/// The l1_head from kona_cfg is recent enough. But using the
/// reference block number from eigenda cert can be too old, such that
/// the proving software cannot reach to that state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertValidity {
    /// the claim about if the cert is valid
    pub claimed_validity: bool,
    /// a zkvm proof attesting the above result    
    pub canoe_proof: Vec<u8>,
    /// block hash where view call anchored at, l1_head comes from kona_cfg    
    pub l1_head_block_hash: B256,
}
