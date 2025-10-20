use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use alloy_primitives::{Address, B256};
use eigenda_cert::AltDACommitment;

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

#[async_trait]
pub trait CanoeProvider: Clone + Send + 'static {
    type Receipt: Serialize + for<'de> Deserialize<'de>;
    type Proof: Serialize + for<'de> Deserialize<'de>;

    /// create_certs_validity_proof takes a vector of canoe inputs and produces one zk proof attesting
    /// all the claimed validity in vector are indeed correct.
    /// The correctness is defined by evaluating result of applying the DAcert on the specified chain
    /// at a certain block number on the verifier address.
    ///
    /// If the input does not contain any canoe_input to prove against, it returns None
    /// All canoe CanoeInput must share common (l1_chain_id, l1_head_block_number)
    async fn create_certs_validity_proof(
        &self,
        _canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>>;

    /// get_config_hash allows getting l1 config hash from receipt. Note some backend like steel does not
    /// need it, and return None. It is up to the implementer to decide if its CanoeProvider provides it.
    /// Within the client program, sp1-cc allows custom genesis, whereas steel provides only a few genesis
    /// to convert input based on chainID. For sp1-cc, adversary can use a legit chain id, but change all
    /// other fields in the genesis. Hence it is critical that the entire config hash is commited. By
    /// having this function, the host has a mean to extract teh config hash, and provide it to the verifier,
    /// which will be verified within zkVM.
    fn get_config_hash(&self, receipt: &Self::Receipt) -> Option<B256>;

    /// get_recursive_proof returns the zk proof which can be recursively verified by zk vm
    fn get_recursive_proof(&self, receipt: &Self::Receipt) -> Option<Self::Proof>;
}

#[derive(Clone)]
pub struct CanoeNoOpProvider {}

#[async_trait]
impl CanoeProvider for CanoeNoOpProvider {
    type Receipt = ();
    type Proof = ();

    async fn create_certs_validity_proof(
        &self,
        _canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>> {
        None
    }

    fn get_config_hash(&self, _receipt: &Self::Receipt) -> Option<B256> {
        None
    }

    fn get_recursive_proof(&self, _receipt: &Self::Receipt) -> Option<Self::Proof> {
        None
    }
}
