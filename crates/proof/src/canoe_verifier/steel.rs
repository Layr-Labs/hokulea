use crate::canoe_verifier::{to_journal_bytes, CanoeVerifier};
use crate::cert_validity::CertValidity;
use eigenda_v2_struct::EigenDAV2Cert;

use risc0_zkvm::Receipt;

use canoe_steel_methods::V2CERT_VERIFICATION_ID;
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
    fn validate_cert_receipt(&self, cert_validity: CertValidity, eigenda_cert: EigenDAV2Cert) {
        info!("using CanoeSteelVerifier");

        let journal_bytes = to_journal_bytes(&cert_validity, &eigenda_cert);

        cfg_if::cfg_if! {
            if #[cfg(target_os = "zkvm")] {
                risc0_zkvm::guest::env;
                if cert_validity.canoe_proof.is_some() {
                    // Risc0 doc https://github.com/risc0/risc0/tree/main/examples/composition
                    warn!("steel verification within zkvm requires proof being provided via zkVM stdin");
                }

                env::verify(V2CERT_VERIFICATION_ID, &journal_bytes).expect("steel proof cannot be verified within zkVM");
            } else {
                if cert_validity.canoe_proof.is_none() {
                    panic!("steel verification in non-zkvm mode requires proof being supplied into CertValidity");
                }

                let canoe_proof = cert_validity.canoe_proof.expect("canoe proof does not exist in mock mode");

                let canoe_receipt: Receipt = serde_json::from_slice(canoe_proof.as_ref()).expect("serde error");
                canoe_receipt
                    .verify(V2CERT_VERIFICATION_ID)
                    .expect("receipt verify correctly");

                assert!(canoe_receipt.journal.bytes == journal_bytes);
            }
        }
    }
}
