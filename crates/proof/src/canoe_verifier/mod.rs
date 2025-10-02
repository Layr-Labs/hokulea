pub mod address_fetcher;
pub mod errors;
pub mod noop;
#[cfg(feature = "steel")]
pub mod steel;

#[cfg(feature = "sp1-cc")]
pub mod sp1_cc;

use crate::cert_validity::CertValidity;
use alloc::vec::Vec;
use alloy_sol_types::SolValue;
use canoe_bindings::Journal;

use eigenda_cert::AltDACommitment;

pub trait CanoeVerifier: Clone + Send + 'static {
    fn validate_cert_receipt(
        &self,
        _cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        _canoe_proof: Option<Vec<u8>>,
    ) -> Result<(), errors::HokuleaCanoeVerificationError>;

    /// The function converts validity and altda commitment into journals.
    /// Journals are concatenated in a serialized byte array. The output of
    /// the serialization must be identical to one committed by zkVM.
    /// Those bytes are never expected to be deserialized.
    fn to_journals_bytes(
        &self,
        cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>,
    ) -> Vec<u8> {
        let mut journals: Vec<u8> = Vec::new();
        for (altda_commitment, cert_validity) in &cert_validity_pairs {
            let rlp_bytes = altda_commitment.to_rlp_bytes();

            let journal = Journal {
                certVerifierAddress: cert_validity.verifier_address,
                input: rlp_bytes.into(),
                blockhash: cert_validity.l1_head_block_hash,
                output: cert_validity.claimed_validity,
                l1ChainId: cert_validity.l1_chain_id,
            };

            journals.extend(journal.abi_encode());
        }
        journals
    }
}
