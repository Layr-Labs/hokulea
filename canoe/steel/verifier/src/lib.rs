//! implement [CanoeVerifier] with steel
#![no_std]
extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use alloy_primitives::B256;
use eigenda_cert::AltDACommitment;

use risc0_zkvm::Receipt;

use canoe_bindings::Journal;
use canoe_steel_methods::CERT_VERIFICATION_ID;
use canoe_verifier::{CanoeVerifier, CertValidity, HokuleaCanoeVerificationError};
use tracing::info;

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

        // use default to_journals_bytes implementation
        let journals_bytes = self.to_journals_bytes(cert_validity_pair);

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

    fn to_journals_bytes(
        &self,
        cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>,
    ) -> Vec<u8> {
        let mut journals: Vec<Journal> = Vec::new();
        for (altda_commitment, cert_validity) in &cert_validity_pairs {
            let rlp_bytes = altda_commitment.to_rlp_bytes();
            assert!(cert_validity.chain_config_hash.is_none());

            let journal = Journal {
                certVerifierAddress: cert_validity.verifier_address,
                input: rlp_bytes.into(),
                blockhash: cert_validity.l1_head_block_hash,
                output: cert_validity.claimed_validity,
                l1ChainId: cert_validity.l1_chain_id,
                chainConfigHash: B256::default(),
            };

            journals.push(journal);
        }

        bincode::serialize(&journals).expect("should be able to serialize")
    }
}
