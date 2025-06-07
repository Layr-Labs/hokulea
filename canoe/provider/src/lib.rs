use alloy_primitives::B256;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use hokulea_eigenda::{AltDACommitment, EigenDAVersionedCert};
use canoe_bindings::{IEigenDACertVerifier, IEigenDACertVerifierRouter};
use alloy_sol_types::SolValue;

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
}

#[async_trait]
pub trait CanoeProvider: Clone + Send + 'static {
    type Receipt: Serialize + for<'de> Deserialize<'de>;

    async fn create_cert_validity_proof(&self, input: CanoeInput) -> Result<Self::Receipt>;

    fn get_eth_rpc_url(&self) -> String;
}

#[derive(Clone)]
pub struct CanoeNoOpProvider {}

#[async_trait]
impl CanoeProvider for CanoeNoOpProvider {
    type Receipt = ();

    async fn create_cert_validity_proof(&self, _canoe_input: CanoeInput) -> Result<Self::Receipt> {
        Ok(())
    }

    fn get_eth_rpc_url(&self) -> String {
        "".to_string()
    }
}

pub fn build_v2_call(canoe_input: &CanoeInput) -> IEigenDACertVerifier::verifyDACertV2ForZKProofCall {
    match &canoe_input.altda_commitment.versioned_cert {
        EigenDAVersionedCert::V2(cert) => {
            IEigenDACertVerifier::verifyDACertV2ForZKProofCall {
                batchHeader: cert.batch_header_v2.to_sol(),
                blobInclusionInfo: cert
                    .blob_inclusion_info
                    .clone()
                    .to_sol(),
                nonSignerStakesAndSignature: cert
                    .nonsigner_stake_and_signature
                    .to_sol(),
                signedQuorumNumbers: cert.signed_quorum_numbers.clone(),
            }
        }
        _ => panic!("encounter a cert version that is not v2, cannot convert"),
    }
}

pub fn build_v3_call(canoe_input: &CanoeInput) -> IEigenDACertVerifierRouter::checkDACertCall {
    match &canoe_input.altda_commitment.versioned_cert {
        EigenDAVersionedCert::V3(cert) => {
            let v3_soltype_cert = cert.to_sol();
            IEigenDACertVerifierRouter::checkDACertCall {
                abiEncodedCert: v3_soltype_cert.abi_encode().into(),
            }
        }
        _ => panic!("encounter a cert version that is not v3, cannot convert"),
    }
}