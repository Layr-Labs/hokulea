pub mod errors;
pub mod noop;
#[cfg(feature = "steel")]
pub mod steel;

#[cfg(feature = "sp1-cc")]
pub mod sp1_cc;

use crate::cert_validity::CertValidity;
use alloc::vec::Vec;
use alloy_primitives::{address, Address};
use alloy_sol_types::SolValue;
use canoe_bindings::Journal;
use eigenda_v2_struct::EigenDAV2CertV2;

pub trait CanoeVerifier: Clone + Send + 'static {
    fn validate_cert_receipt(
        &self,
        _cert_validity: CertValidity,
        _eigenda_cert: EigenDAV2CertV2,
    ) -> Result<(), errors::HokuleaCanoeVerificationError>;
}

/// a helper function to convert validity and eigenda_cert into a journal, which can be
/// used to verify canoe proof. The returned type is abi encoded Journal, which is
/// immediately consumable by zkVM
pub fn to_journal_bytes(cert_validity: &CertValidity, eigenda_cert: &EigenDAV2CertV2) -> Vec<u8> {
    let batch_header = eigenda_cert.batch_header_v2.to_sol().abi_encode();
    let blob_inclusion_info = eigenda_cert.blob_inclusion_info.to_sol().abi_encode();
    let non_signer_stakes_and_signature = eigenda_cert
        .nonsigner_stake_and_signature
        .to_sol()
        .abi_encode();
    let signed_quorum_numbers_abi = eigenda_cert.signed_quorum_numbers.abi_encode();

    // ensure inputs are constrained
    let mut buffer = Vec::new();
    buffer.extend(batch_header);
    buffer.extend(blob_inclusion_info);
    buffer.extend(non_signer_stakes_and_signature);
    buffer.extend(signed_quorum_numbers_abi);

    let journal = Journal {
        certVerifierAddress: cert_verifier_v2_address(cert_validity.l1_chain_id),
        input: buffer.into(),
        blockhash: cert_validity.l1_head_block_hash,
        output: cert_validity.claimed_validity,
        l1ChainId: cert_validity.l1_chain_id,
    };
    journal.abi_encode()
}

// V3 cert not supported yet, only v2 cert right now
pub fn cert_verifier_v2_address(chain_id: u64) -> Address {
    // this is kurtosis devnet
    match chain_id {
        // Sepolia V2 cert verifier address
        11155111 => address!("0x73818fed0743085c4557a736a7630447fb57c662"),
        // holesky V2 cert verifier address
        17000 => address!("0xFe52fE1940858DCb6e12153E2104aD0fDFbE1162"),
        // kurtosis l1 chain id => mock contract address
        // This is the cert verifier that canoe provider and verifier are run against.
        // In hokulea repo, there is a mock contract under canoe directory, which can be
        // deployed to generate the address and test functionality.
        // if user uses a different private key, or nonce for deployment are different from
        // the default, the address below would change
        3151908 => address!("0xb4B46bdAA835F8E4b4d8e208B6559cD267851051"),
        chain_id => panic!("chain id {} is unknown", chain_id),
    }
}
