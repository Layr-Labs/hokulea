//! implement [CanoeVerifier] with sp1-cc
#![no_std]
extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use alloy_primitives::{keccak256, B256, U256};
use alloy_sol_types::SolValue;
use canoe_bindings::Journal;
use canoe_verifier::{chain_spec, CanoeVerifier, CertValidity, HokuleaCanoeVerificationError};
use eigenda_cert::AltDACommitment;
use rsp_primitives::genesis::Genesis;
use sp1_cc_client_executor::ChainConfig;

use tracing::info;

/// Any change to sp1-cc client including new sp1 toolchain produces a new ELF to be executed and proved by zkVM
/// To generate the new ELF (a newer version than 5.2.1 toolchain tag is also fine)
/// ``` bash
/// cd canoe/sp1-cc/client
/// cargo prove build --output-directory ../elf --elf-name canoe-sp1-cc-client --docker --tag v5.2.1
/// ```
///
/// The verificaiton of the ELF must be hardcoded here which pins an exact version of ELF a prover can use
/// Sp1 toolchain currently does not provide a way to generate such key. It has been raised to the sp1 team.
/// Currently, one can run the preloader example under `example/preloader` and run
/// ``` bash
/// just run-preloader .devnet.env sp1-cc
/// ```
/// or
/// ```bash
/// just get-sp1cc-elf-and-vkey
/// ```
/// The v_key will be printed in the terminal.
pub const V_KEY: [u32; 8] = [
    603562044, 808664524, 175274181, 1060299320, 2427270, 646894831, 504015100, 551610173,
];

#[derive(Clone, Default)]
pub struct CanoeSp1CCVerifier {}

impl CanoeVerifier for CanoeSp1CCVerifier {
    // some variable is unused, because when sp1-cc verifier is not configured in zkVM mode, all tests
    // are skipped because sp1 cannot take sp1-sdk as dependency
    #[allow(unused_variables)]
    fn validate_cert_receipt(
        &self,
        cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        canoe_proof_bytes: Option<Vec<u8>>,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        info!("using CanoeSp1CCVerifier with v_key {:?}", V_KEY);

        assert!(!cert_validity_pair.is_empty());

        cfg_if::cfg_if! {
            if #[cfg(target_os = "zkvm")] {
                use sha2::{Digest, Sha256};
                use sp1_lib::verify::verify_sp1_proof;
                use tracing::warn;

                // while transforming to journal bytes, it verifies if chain config hash is correctly set
                let journals_bytes = self.to_journals_bytes(cert_validity_pair);

                // if not in dev mode, the receipt should be empty
                if canoe_proof_bytes.is_some() {
                    // Sp1 doc https://github.com/succinctlabs/sp1/blob/a1d873f10c32f5065de120d555cfb53de4003da3/examples/aggregation/script/src/main.rs#L75
                    warn!("sp1-cc verification within zkvm requires proof being provided via zkVM stdin");
                }
                // used within zkVM
                let public_values_digest = Sha256::digest(journals_bytes);
                // the function will panic if the proof is incorrect
                // https://github.com/succinctlabs/sp1/blob/011d2c64808301878e6f0375c3596b3e22e53949/crates/zkvm/lib/src/verify.rs#L3
                verify_sp1_proof(&V_KEY, &public_values_digest.into());
                Ok(())
            } else {
                panic!("CanoeSp1CCVerifier should only be used for secure integration whose validation happens in zkVM");
            }
        }
    }

    fn to_journals_bytes(
        &self,
        cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>,
    ) -> Vec<u8> {
        let mut journals: Vec<Journal> = Vec::new();
        for (altda_commitment, cert_validity) in &cert_validity_pairs {
            let rlp_bytes = altda_commitment.to_rlp_bytes();

            // compute chain config hash locally and commit to journal. If the journal is different from
            // the one commited within zkVM, the verification would fail.
            // The library to determine chain spec comes from reth. And by checking the equality, only
            // the sp1-cc updating to the correct fork version can produce a correct output. Or downgrade
            // or patch the reth library such that produces an older fork.
            // By forcing the sp1-cc to match latest reth_evm fork, we can detect the problem early on
            // testnet, and provide fix before mainnet
            let chain_config_hash_derive = derive_chain_config_hash(
                cert_validity.l1_chain_id,
                cert_validity.l1_head_block_timestamp,
                cert_validity.l1_head_block_number,
            );

            // genesis hash, not if the chain id is 3151908, which is used for kurtosis devnet, the system
            // would panic as expected.
            let rsp_genesis_hash = rsp_genesis_hash(cert_validity.l1_chain_id);

            let journal = Journal {
                certVerifierAddress: cert_validity.verifier_address,
                input: rlp_bytes.into(),
                blockhash: cert_validity.l1_head_block_hash,
                output: cert_validity.claimed_validity,
                l1ChainId: cert_validity.l1_chain_id,
                blockNumber: cert_validity.l1_head_block_number,
                chainSpecHash: rsp_genesis_hash,
                chainConfigHash: chain_config_hash_derive,
            };
            journals.push(journal);
        }
        bincode::serialize(&journals).expect("should be able to serialize")
    }
}

/// derive_chain_config_hash locates the active fork first, then compute the chain
/// config hash.
fn derive_chain_config_hash(
    l1_chain_id: u64,
    l1_head_block_timestamp: u64,
    l1_head_block_number: u64,
) -> B256 {
    let spec_id = chain_spec::derive_chain_spec_id(
        l1_chain_id,
        l1_head_block_timestamp,
        l1_head_block_number,
    );
    hash_chain_config(l1_chain_id, spec_id.to_string())
}

/// hash_chain_config implements the method which sp1-cc uses to commit chain spec
/// and active fork. See
/// <https://github.com/succinctlabs/sp1-contract-call/blob/9d9a45c550d3373dbf9bd7fb1f4907356f657722/crates/client-executor/src/lib.rs#L340>
fn hash_chain_config(chain_id: u64, active_fork_name: String) -> B256 {
    let chain_config = ChainConfig {
        chainId: U256::from(chain_id),
        activeForkName: active_fork_name,
    };

    keccak256(chain_config.abi_encode_packed())
}

// compute digest of rsp genesis used by the EVM sketch. Rsp genesis does not recognize custom chain using the try_from
// function. If an adversary fakes the chain id, the hash of genesis would review the difference, because the regular genesis
// is enum without data field. Whereas the hash would include chain config from custom genesis.
// Resulting different genesis hash.
// https://github.com/succinctlabs/rsp/blob/c14b4005ea9257e4d434a080b6900411c17f781b/crates/primitives/src/genesis.rs#L19
fn rsp_genesis_hash(chain_id: u64) -> B256 {
    match Genesis::try_from(chain_id) {
        Ok(genesis) => {
            let rsp_genesis_bytes =
                bincode::serialize(&genesis).expect("should be able to serialize rsp genesis");
            keccak256(rsp_genesis_bytes)
        }
        Err(e) => panic!("rsp does not recognize genesis {e}"),
    }
}
