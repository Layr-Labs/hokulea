use alloy_primitives::{Address, B256};
use alloy_sol_types::SolValue;
use anyhow::Result;
use async_trait::async_trait;
use canoe_bindings::{IEigenDACertVerifier, IEigenDACertVerifierBase};
use eigenda_cert::{AltDACommitment, EigenDAVersionedCert};
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

#[async_trait]
pub trait CanoeProvider: Clone + Send + 'static {
    type Receipt: Serialize + for<'de> Deserialize<'de>;

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

    /// get_eth_rpc_url returns eth rpc for fetching the state in order to generate the zk validity proof for DACert
    fn get_eth_rpc_url(&self) -> String;
}

#[derive(Clone)]
pub struct CanoeNoOpProvider {}

#[async_trait]
impl CanoeProvider for CanoeNoOpProvider {
    type Receipt = ();

    async fn create_certs_validity_proof(
        &self,
        _canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>> {
        None
    }

    fn get_eth_rpc_url(&self) -> String {
        "".to_string()
    }
}

/// Call respecting solidity interface
/// V2 is deprecated once router is released
pub enum CertVerifierCall {
    /// V2 calldata
    V2(IEigenDACertVerifier::verifyDACertV2ForZKProofCall),
    /// Base is compatible with Router and calling V3 directly
    Router(IEigenDACertVerifierBase::checkDACertCall),
}

impl CertVerifierCall {
    /// convert eigenda cert type into its solidity type that works with solidity cert verifier interface
    pub fn build(altda_commitment: &AltDACommitment) -> Self {
        match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V2(cert) => {
                CertVerifierCall::V2(IEigenDACertVerifier::verifyDACertV2ForZKProofCall {
                    batchHeader: cert.batch_header_v2.to_sol(),
                    blobInclusionInfo: cert.blob_inclusion_info.clone().to_sol(),
                    nonSignerStakesAndSignature: cert.nonsigner_stake_and_signature.to_sol(),
                    signedQuorumNumbers: cert.signed_quorum_numbers.clone(),
                })
            }
            EigenDAVersionedCert::V3(cert) => {
                let v3_soltype_cert = cert.to_sol();
                CertVerifierCall::Router(IEigenDACertVerifierBase::checkDACertCall {
                    abiEncodedCert: v3_soltype_cert.abi_encode().into(),
                })
            }
        }
    }
}
