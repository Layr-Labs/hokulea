use crate::canoe_verifier::errors::HokuleaCanoeVerificationError;
use crate::canoe_verifier::CanoeVerifier;
use crate::cert_validity::CertValidity;
use alloc::vec::Vec;
use alloy_primitives::B256;
use eigenda_cert::AltDACommitment;

use tracing::{info, warn};

// ToDo(bx) how to automtically update it from ELF directly as oppose to hard code it
// To get vKey of ELF
// cargo prove vkey --elf target/elf-compilation/riscv32im-succinct-zkvm-elf/release/canoe-sp1-cc-client
pub const VKEYHEXSTRING: &str = "00692d1aac07e614ced12f4b16f50834490e735b89d2d3492b343337bb31d227";

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
        info!("using CanoeSp1CCVerifier");

        cfg_if::cfg_if! {
            if #[cfg(target_os = "zkvm")] {
                use sha2::{Digest, Sha256};
                use sp1_lib::verify::verify_sp1_proof;
                use core::str::FromStr;
                use crate::canoe_verifier::to_journals_bytes;

                let journals_bytes = to_journals_bytes(cert_validity_pair);

                // if not in dev mode, the receipt should be empty
                if canoe_proof_bytes.is_some() {
                    // Sp1 doc https://github.com/succinctlabs/sp1/blob/a1d873f10c32f5065de120d555cfb53de4003da3/examples/aggregation/script/src/main.rs#L75
                    warn!("sp1-cc verification within zkvm requires proof being provided via zkVM stdin");
                }
                // used within zkVM
                let public_values_digest = Sha256::digest(journals_bytes);
                let v_key_b256 = B256::from_str(VKEYHEXSTRING).map_err(|_| HokuleaCanoeVerificationError::InvalidVerificationKeyForSp1)?;
                let v_key = b256_to_u32_array(v_key_b256);
                // the function will panic if the proof is incorrect
                // https://github.com/succinctlabs/sp1/blob/011d2c64808301878e6f0375c3596b3e22e53949/crates/zkvm/lib/src/verify.rs#L3
                verify_sp1_proof(&v_key, &public_values_digest.into());
            } else {
                warn!("Skipping sp1CC proof verification in native mode outside of zkVM, because sp1 cannot take sp1-sdk as dependency which is needed for verification in the native mode");
            }
        }
        Ok(())
    }
}

pub fn b256_to_u32_array(b: B256) -> [u32; 8] {
    let bytes: [u8; 32] = b.into();

    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        let start = i * 4;
        // sp1 zkvm is little endian
        out[i] = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        i += 1;
    }
    out
}
