use alloy_primitives::{Address, B256};
use eigenda_cert::AltDACommitment;
use serde::{Deserialize, Serialize};

/// CanoeInput contains all the necessary data to create a ZK proof
/// attesting the validity of a cert within an altda commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanoeInput {
    /// altda commitment
    pub altda_commitment: AltDACommitment,
    /// the claim about if the cert is valid, received from the signature from OracleEigenDAPreimageProvider from the derivation pipeline
    /// Added here only for a preventive measure, such that if in the state loading part, zkvm got a different answer than claimed
    /// zkVM can stop early without proving anything.
    pub claimed_validity: bool,
    /// block hash where canoe is anchoring cert verification view call at, l1_head comes from kona_cfg    
    pub l1_head_block_hash: B256,
    /// Block number corresponding to l1_head_block_hash.
    /// Their correspondence is checked in the zk view proof.
    pub l1_head_block_number: u64,
    /// l1 chain id specifies the chain which implicitly along with l1_head_block_number indicates the current EVM version due to hardfork
    pub l1_chain_id: u64,
    /// cert verifier or router verifier address used for verifying the altda commitment
    /// verifier_address must not be manipulated by the zkvm host. It can be set either with a single router address or a set of
    /// fixed cert verifier address
    pub verifier_address: Address,
}
