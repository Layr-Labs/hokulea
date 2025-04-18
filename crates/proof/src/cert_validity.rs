use alloy_primitives::B256;
use eigenda_v2_struct_rust::EigenDAV2Cert;
use serde::{Deserialize, Serialize};

//use risc0_zkvm::Receipt;

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
        _eigenda_cert: &EigenDAV2Cert,
        _validity_call_verifier_id: B256,
    ) {
        /*
        use crate::journal::CertValidityJournal;
        use alloy_rlp::Decodable;
        use risc0_zkvm::sha::Digest;

        // if not in dev mode, the receipt must be non empty
        assert!(self.receipt.is_some());
        let receipt = self.receipt.as_ref().unwrap();

        let journal = CertValidityJournal::decode(&mut receipt.journal.bytes.as_ref()).unwrap();
        // ensure journal attests the same outcome
        assert!(journal.is_valid == self.claimed_validity);

        // ensure journal contains the correct cert
        assert!(journal.cert_digest == eigenda_cert.digest());
        let fpvm_image_id = Digest::from(validity_call_verifier_id.0);

        // so far, we have ensure the data is right, now verify the proof with respect to the data
        assert!(self.receipt.as_ref().unwrap().verify(fpvm_image_id).is_ok())
         */
    }
}
