<<<<<<< HEAD
<<<<<<< HEAD
use alloy_primitives::{Address, B256};
=======
use alloy_primitives::{B256, Address};
>>>>>>> 7d0bcf8 (working)
=======
use alloy_primitives::{Address, B256};
>>>>>>> 8115961 (fix comments and cleanup)
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
    /// the claim about if the cert is valid, received from the signature from OracleEigenDAProvider from the derivation pipeline
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
<<<<<<< HEAD
<<<<<<< HEAD
    /// cert verifier or router verifier address used for verifying the altda commitment
    /// verifier_address must not be manipulated by the zkvm host. It can be set either with a single router address or a set of
    /// fixed cert verifier address
=======
    /// cert verifier address with respect to the altda commitment at the reference block number within the altda commitment
    /// if a cert verifier router is used, the address is the router address
>>>>>>> 7d0bcf8 (working)
=======
    /// cert verifier or router verifier address used for verifying the altda commitment
>>>>>>> 8115961 (fix comments and cleanup)
    pub verifier_address: Address,
}

#[async_trait]
pub trait CanoeProvider: Clone + Send + 'static {
    type Receipt: Serialize + for<'de> Deserialize<'de>;

<<<<<<< HEAD
<<<<<<< HEAD
    /// create_certs_validity_proof takes a vector of canoe inputs and produces one zk proof attesting
    /// all the claimed validity in vector are indeed correct result.
    /// The correctness is defined by evaluating result of applying the DAcert on the specified chain
    /// at a certain block number on the verifier address.
=======
    /// create_certs_validity_proof takes a vector of canoe inputs and produces one zk proof attesting
    /// the claimed validity boolean value is indeed the evaluating result of applying the DAcert on the
    /// specified chain at a certain block number on the verifier address
>>>>>>> 8115961 (fix comments and cleanup)
    /// The function assumes at least one CanoeInput, and all canoe inputs must share common
    /// (l1_chain_id, l1_head_block_number)
    async fn create_certs_validity_proof(
        &self,
        _canoe_inputs: Vec<CanoeInput>,
    ) -> Result<Self::Receipt>;
<<<<<<< HEAD
=======
    async fn create_certs_validity_proof(&self, input: Vec<CanoeInput>) -> Result<Self::Receipt>;
>>>>>>> 7d0bcf8 (working)
=======
>>>>>>> 8115961 (fix comments and cleanup)

    /// get_eth_rpc_url returns eth rpc for fetching the state in order to generate the zk validity proof for DACert
    fn get_eth_rpc_url(&self) -> String;
}

#[derive(Clone)]
pub struct CanoeNoOpProvider {}

#[async_trait]
impl CanoeProvider for CanoeNoOpProvider {
    type Receipt = ();

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 8115961 (fix comments and cleanup)
    async fn create_certs_validity_proof(
        &self,
        _canoe_inputs: Vec<CanoeInput>,
    ) -> Result<Self::Receipt> {
<<<<<<< HEAD
=======
    async fn create_certs_validity_proof(&self, _canoe_input: Vec<CanoeInput>) -> Result<Self::Receipt> {
>>>>>>> 7d0bcf8 (working)
=======
>>>>>>> 8115961 (fix comments and cleanup)
        Ok(())
    }

    fn get_eth_rpc_url(&self) -> String {
        "".to_string()
    }
}

<<<<<<< HEAD
/// CanoeProviderError allows the caller to handle error types.
/// EmptyCanoeInput happens when there is no canoe to be proven.
#[derive(Debug, thiserror::Error)]
pub enum CanoeProviderError {
    /// Empty Canoe Input
    #[error("Empty Canoe Input")]
    EmptyCanoeInput,
=======
/// Caone Provider Error
#[derive(Debug, thiserror::Error)]
pub enum CanoeProviderError {
    /// Insufficient Canoe Input
    #[error("Insufficient Canoe Input")]
    InsufficientCanoeInput,
>>>>>>> 8115961 (fix comments and cleanup)
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
