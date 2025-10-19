//! implement [CanoeVerifier] with sp1-cc
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use canoe_bindings::Journal;
use canoe_verifier::{CanoeVerifier, CertValidity, HokuleaCanoeVerificationError};
use eigenda_cert::AltDACommitment;
use revm_primitives::hardfork::SpecId;
use sp1_cc_client_executor::verifiy_chain_config_eth;

use tracing::{info, warn};

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
    1777037043, 1398335269, 149551801, 141656872, 911486423, 903165919, 1244778574, 1857742015,
];

/// Determine the active fork in L1 chain. It must match the active fork version used by sp1-cc for that specific
/// L1 block height. If there is more active L1 fork, but the verions of sp1-cc used is not up to date. The L1_ACTIVE_FORK
/// must be kept identical to sp1-cc, but it is best to update sp1-cc version.
pub const L1_ACTIVE_FORK: SpecId = SpecId::PRAGUE;

#[derive(Clone)]
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

        // while transforming to journal bytes, it verifies if chain config hash is correctly set
        let journals_bytes = self.to_journals_bytes(cert_validity_pair);

        cfg_if::cfg_if! {
            if #[cfg(target_os = "zkvm")] {
                use sha2::{Digest, Sha256};
                use sp1_lib::verify::verify_sp1_proof;

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
            } else {
                warn!("Skipping sp1CC proof verification in native mode outside of zkVM, because sp1 cannot take sp1-sdk as dependency which is needed for verification in the native mode");
            }
        }
        Ok(())
    }

    fn to_journals_bytes(
        &self,
        cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>,
    ) -> Vec<u8> {
        let mut journals: Vec<Journal> = Vec::new();
        for (altda_commitment, cert_validity) in &cert_validity_pairs {
            let rlp_bytes = altda_commitment.to_rlp_bytes();

            let chain_config_hash = cert_validity
                .chain_config_hash
                .expect("sp1cc verifier expects l1 chain config hash");

            // check chain_config_hash supplied by the host is indeed correct with respect to l1 chain id
            // and active fork
            verifiy_chain_config_eth(chain_config_hash, cert_validity.l1_chain_id, L1_ACTIVE_FORK)
                .expect("sp1cc canoe verifies chain config should have succeeded");

            let journal = Journal {
                certVerifierAddress: cert_validity.verifier_address,
                input: rlp_bytes.into(),
                blockhash: cert_validity.l1_head_block_hash,
                output: cert_validity.claimed_validity,
                l1ChainId: cert_validity.l1_chain_id,
                chainConfigHash: chain_config_hash,
            };

            journals.push(journal);
        }

        bincode::serialize(&journals).expect("should be able to serialize")
    }
}
