//! implement [CanoeVerifier] with steel
#![no_std]
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use alloy_primitives::B256;
use eigenda_cert::AltDACommitment;

use revm_primitives::keccak256;
use risc0_zkvm::Receipt;

use canoe_bindings::Journal;
use canoe_steel_methods::CERT_VERIFICATION_ID;
use canoe_verifier::{chain_spec, CanoeVerifier, CertValidity, HokuleaCanoeVerificationError};
use risc0_steel::ethereum::{
    ETH_HOLESKY_CHAIN_SPEC, ETH_MAINNET_CHAIN_SPEC, ETH_SEPOLIA_CHAIN_SPEC,
};
use tracing::{info, warn};

use revm_primitives::hardfork::SpecId;

// steel library can use a chain spec older than the spec by thecurrent L1. The following allowed forks
// guard the steel from running a stale EVM version. Although not all upgrades touche the EVM execution,
// updating timely ensures consistency and removing possibility of doubts
fn get_allowed_steel_spec_id(chain_id: u64) -> Vec<String> {
    match chain_id {
        // mainnet
        1 => vec![SpecId::PRAGUE.to_string(), SpecId::OSAKA.to_string()],
        // sepolia
        11155111 => vec![SpecId::PRAGUE.to_string(), SpecId::OSAKA.to_string()],
        // holesky
        17000 => vec![SpecId::PRAGUE.to_string(), SpecId::OSAKA.to_string()],
        // kurtosis devnet
        3151908 => vec![SpecId::PRAGUE.to_string(), SpecId::OSAKA.to_string()],
        _ => panic!("unsupported chain id"),
    }
}

#[derive(Clone)]
pub struct CanoeSteelVerifierForDevnetTesting {}

impl CanoeVerifier for CanoeSteelVerifierForDevnetTesting {
    fn validate_cert_receipt(
        &self,
        cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        canoe_proof_bytes: Option<Vec<u8>>,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        warn!(
            "using CanoeSteelVerifierForDevnet which should only be used for testing aginst Devnet"
        );
        validate_cert_receipt(cert_validity_pair, canoe_proof_bytes)
    }

    fn to_journals_bytes(
        &self,
        cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>,
    ) -> Vec<u8> {
        to_journals_bytes(cert_validity_pairs)
    }
}

#[derive(Clone)]
pub struct CanoeSteelVerifier {}

/// Abort in any case that there is problem
/// Expect for a given 1. inputs, 2. compute logics (contract address) 3. output 4. blockhash where it
/// is evaluated. Everything should come as expected.
///     CertValidity provides the output and blockhash which comes from boot info
///     VERIFIER_ADDRESS is currently burned inside the client
///     eigenda_cert contains all the inputs
impl CanoeVerifier for CanoeSteelVerifier {
    fn validate_cert_receipt(
        &self,
        cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        canoe_proof_bytes: Option<Vec<u8>>,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        info!("using CanoeSteelVerifier");
        for (_, cert_validity) in &cert_validity_pair {
            // if it is a kurtosis chain
            if cert_validity.l1_chain_id == 3151908 {
                panic!("trustless secure integration does not support kurtosis devnet");
            }
        }

        validate_cert_receipt(cert_validity_pair, canoe_proof_bytes)
    }

    fn to_journals_bytes(
        &self,
        cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>,
    ) -> Vec<u8> {
        to_journals_bytes(cert_validity_pairs)
    }
}

fn validate_cert_receipt(
    cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
    canoe_proof_bytes: Option<Vec<u8>>,
) -> Result<(), HokuleaCanoeVerificationError> {
    // use default to_journals_bytes implementation
    let journals_bytes = to_journals_bytes(cert_validity_pair);

    cfg_if::cfg_if! {
        if #[cfg(target_os = "zkvm")] {
            use risc0_zkvm::guest::env;
            use tracing::warn;
            if canoe_proof_bytes.is_some() {
                // Risc0 doc https://github.com/risc0/risc0/tree/main/examples/composition
                warn!("steel verification within zkvm requires proof provided via zkVM STDIN by the 'add_assumption'
                        method see <https://github.com/risc0/risc0/tree/main/examples/composition>, but currently proof 
                        is provided from other ways which is not verified within zkVM");
            }

            env::verify(CERT_VERIFICATION_ID, &journals_bytes).map_err(|e| HokuleaCanoeVerificationError::InvalidProofAndJournal(e.to_string()))?;
        } else {
            if canoe_proof_bytes.is_none() {
                return Err(HokuleaCanoeVerificationError::MissingProof);
            }

            let canoe_receipt: Receipt = serde_json::from_slice(canoe_proof_bytes.unwrap().as_ref()).map_err(|e| HokuleaCanoeVerificationError::UnableToDeserializeReceipt(e.to_string()))?;

            canoe_receipt.verify(CERT_VERIFICATION_ID).map_err(|e| HokuleaCanoeVerificationError::InvalidProofAndJournal(e.to_string()))?;

            if canoe_receipt.journal.bytes != journals_bytes {
                return Err(HokuleaCanoeVerificationError::InconsistentPublicJournal)
            }
        }
    }
    Ok(())
}

fn to_journals_bytes(cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>) -> Vec<u8> {
    let mut journals: Vec<Journal> = Vec::new();
    for (altda_commitment, cert_validity) in &cert_validity_pairs {
        let rlp_bytes = altda_commitment.to_rlp_bytes();
        let chain_id: u64 = cert_validity.l1_chain_id;
        let timestamp = cert_validity.l1_head_block_timestamp;
        let block_number = cert_validity.l1_head_block_number;

        let steel_active_fork = get_steel_active_fork(chain_id, timestamp, block_number);
        let derived_active_fork =
            chain_spec::derive_chain_spec_id(chain_id, timestamp, block_number).to_string();
        if steel_active_fork != derived_active_fork {
            warn!("consider bump steel library version. Based on common block number {block_number} timestamp {timestamp}, the derived active fork from revm {derived_active_fork} is different from steel {steel_active_fork} on chain {chain_id}");
            // the steel active fork must be contained in the allowed list
            assert!(get_allowed_steel_spec_id(chain_id).contains(&steel_active_fork));
        }

        let journal = Journal {
            blockNumber: cert_validity.l1_head_block_number,
            certVerifierAddress: cert_validity.verifier_address,
            input: rlp_bytes.into(),
            blockhash: cert_validity.l1_head_block_hash,
            output: cert_validity.claimed_validity,
            l1ChainId: cert_validity.l1_chain_id,
            chainConfigHash: keccak256(steel_active_fork),
            chainSpecHash: B256::default(),
        };

        journals.push(journal);
    }

    bincode::serialize(&journals).expect("should be able to serialize")
}

// get spec id from steel library
fn get_steel_active_fork(chain_id: u64, timestamp: u64, block_number: u64) -> String {
    let spec_id = match chain_id {
        // mainnet
        1 => ETH_MAINNET_CHAIN_SPEC
            .active_fork(block_number, timestamp)
            .expect("should be able to get active fork with steel chain spec on mainnet"),
        // sepolia
        11155111 => ETH_SEPOLIA_CHAIN_SPEC
            .active_fork(block_number, timestamp)
            .expect("should be able to get active fork with steel chain spec on sepolia"),
        // holesky
        17000 => ETH_HOLESKY_CHAIN_SPEC
            .active_fork(block_number, timestamp)
            .expect("should be able to get active fork with steel chain spec on holesky"),
        // kurtosis devnet
        3151908 => ETH_MAINNET_CHAIN_SPEC
            .active_fork(block_number, timestamp)
            .expect("should be able to get active fork with steel chain spec on kurtosis"),
        _ => panic!("unsupported chain id"),
    };
    spec_id.to_string()
}
