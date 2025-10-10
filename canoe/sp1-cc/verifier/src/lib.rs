//! implement [CanoeVerifier] with sp1-cc
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use canoe_verifier::{CanoeVerifier, CertValidity, HokuleaCanoeVerificationError};
use eigenda_cert::AltDACommitment;

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
    1750523715, 1289466902, 1533215549, 1364363175, 1013771822, 1418649948, 112042355, 1809179481,
];

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

        cfg_if::cfg_if! {
            if #[cfg(target_os = "zkvm")] {
                use sha2::{Digest, Sha256};
                use sp1_lib::verify::verify_sp1_proof;

                let journals_bytes = CanoeVerifier::to_journals_bytes(self, cert_validity_pair);

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
}
