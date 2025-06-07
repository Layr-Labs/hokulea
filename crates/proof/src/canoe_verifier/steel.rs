use crate::canoe_verifier::errors::HokuleaCanoeVerificationError;
use crate::canoe_verifier::{to_journal_bytes, CanoeVerifier};
use crate::cert_validity::CertValidity;
use alloc::string::ToString;
use eigenda_cert::AltDACommitment;

use risc0_zkvm::Receipt;

use canoe_steel_methods::CERT_VERIFICATION_ID;
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
        cert_validity: CertValidity,
        altda_commitment: AltDACommitment,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        info!("using CanoeSteelVerifier");

        let journal_bytes = to_journal_bytes(&cert_validity, &altda_commitment);

        cfg_if::cfg_if! {
            if #[cfg(target_os = "zkvm")] {
                risc0_zkvm::guest::env;
                if cert_validity.canoe_proof.is_some() {
                    // Risc0 doc https://github.com/risc0/risc0/tree/main/examples/composition
                    warn!("steel verification within zkvm requires proof provided via zkVM STDIN by the 'add_assumption'
                        method see <https://github.com/risc0/risc0/tree/main/examples/composition>, but currently proof 
                        is provided from other ways which is not verified within zkVM");
                }

                env::verify(CERT_VERIFICATION_ID, &journal_bytes).map_err(|e| HokuleaCanoeVerificationError::InvalidProofAndJournal(e.to_string()))?;
            } else {
                if cert_validity.canoe_proof.is_none() {
                    return Err(HokuleaCanoeVerificationError::MissingProof);
                }

                let canoe_proof = cert_validity.canoe_proof.expect("canoe proof does not exist in mock mode");

                let canoe_receipt: Receipt = serde_json::from_slice(canoe_proof.as_ref()).map_err(|e| HokuleaCanoeVerificationError::UnableToDeserializeReceipt(e.to_string()))?;

                canoe_receipt.verify(CERT_VERIFICATION_ID).map_err(|e| HokuleaCanoeVerificationError::InvalidProofAndJournal(e.to_string()))?;

                if canoe_receipt.journal.bytes != journal_bytes {
                    return Err(HokuleaCanoeVerificationError::InconsistentPublicJournal)
                }
            }
        }
        Ok(())
    }
}
