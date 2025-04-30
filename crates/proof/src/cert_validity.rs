use alloy_primitives::{hex::FromHex, Address};
use eigenda_v2_struct::EigenDAV2Cert;
use serde::{Deserialize, Serialize};
use alloy_sol_types::SolValue;

use alloc::vec::Vec;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertValidity {
    /// the claim about if the cert is valid
    pub claimed_validity: bool,
    /// a zkvm proof attesting the above result
    /// in dev mode, receipt is ignored
    /// in the future, to make it generic for sp1-contract-call
    /// Opaque zk proof
    pub receipt: Option<Vec<u8>>,
}

impl CertValidity {
    /// verify if the receipt for cert is valid
    /// note this is different from if the cert itself is valid as in the is_valid field
    pub fn validate_cert_receipt(
        &self,
        eigenda_cert: &EigenDAV2Cert,
        validity_call_verifier_id: [u32; 8],
    ) {        
        use crate::journal::Journal;        
        use risc0_zkvm::Receipt;

        // if not in dev mode, the receipt must be non empty
        assert!(self.receipt.is_some());
        let receipt_bytes = self.receipt.as_ref().unwrap();

        let canoe_receipt: Receipt = serde_json::from_slice(&receipt_bytes).expect("serde error");
        canoe_receipt.verify(validity_call_verifier_id).expect("receipt verify correctly");
                 
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

        // ensure journal contains the correct cert
        // assert!(journal.cert_digest == eigenda_cert.digest());     
    }
}
