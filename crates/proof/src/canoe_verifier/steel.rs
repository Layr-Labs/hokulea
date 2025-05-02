use crate::canoe_verifier::{CanoeVerifier, Journal};
use crate::cert_validity::CertValidity;
use eigenda_v2_struct::EigenDAV2Cert;
use alloy_sol_types::SolValue;
use alloc::vec::Vec;

use risc0_zkvm::Receipt;

use canoe_steel_methods::DACERT_V2_VERIFIER_ID;
use tracing::info;

#[derive(Clone)]
pub struct CanoeSteelVerifier {}

impl CanoeVerifier for CanoeSteelVerifier {    

    fn validate_cert_receipt(
        &self,
        cert_validity: CertValidity,
        eigenda_cert: EigenDAV2Cert,
    ) {         
        info!("using CanoeSteelVerifier");
        // if not in dev mode, the receipt must be non empty
        assert!(cert_validity.receipt.is_some());
        let receipt_bytes = cert_validity.receipt.as_ref().unwrap();

        let canoe_receipt: Receipt = serde_json::from_slice(&receipt_bytes).expect("serde error");
        canoe_receipt.verify(DACERT_V2_VERIFIER_ID).expect("receipt verify correctly");
                 
        let journal = Journal::abi_decode(&canoe_receipt.journal.bytes, true).expect("valid journal");

        // ensure journal attests the same outcome
        // burn address into guest
        //assert!(journal.contract == verifier_contract)


        let batch_header = eigenda_cert.batch_header_v2.to_sol().abi_encode();
        let blob_inclusion_info = eigenda_cert.blob_inclusion_info.to_sol().abi_encode();
        let non_signer_stakes_and_signature = eigenda_cert.nonsigner_stake_and_signature.to_sol().abi_encode();

        let mut buffer = Vec::new();
        buffer.extend(batch_header);
        buffer.extend(blob_inclusion_info);
        buffer.extend(non_signer_stakes_and_signature);
        assert!(buffer == journal.input);
    }

}