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

use eigenda_cert::{AltDACommitment, EigenDAVersionedCert};

pub trait CanoeVerifier: Clone + Send + 'static {
    fn validate_cert_receipt(
        &self,
        _cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        _canoe_proof: Option<Vec<u8>>,
    ) -> Result<(), errors::HokuleaCanoeVerificationError>;
}

/// A helper function to convert validity and eigenda_cert into journals.
/// Those journals are concatenated in a serialized byte array which is then committed by the zkVM.
/// The zkVM host is expected to provide a zk proof that commites to those serialized bytes array.
/// Those bytes are never expected to be deserialized.
pub fn to_journals_bytes(cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>) -> Vec<u8> {
    let mut journals: Vec<u8> = Vec::new();
    for (altda_commitment, cert_validity) in &cert_validity_pairs {
        let rlp_bytes = altda_commitment.to_rlp_bytes();

        let journal = Journal {
            certVerifierAddress: cert_verifier_address(cert_validity.l1_chain_id, altda_commitment),
            input: rlp_bytes.into(),
            blockhash: cert_validity.l1_head_block_hash,
            output: cert_validity.claimed_validity,
            l1ChainId: cert_validity.l1_chain_id,
        };

        journals.extend(journal.abi_encode());
    }
    journals
}

/// get cert verifier address based on chain id, and cert version from altda commitment
/// V3 cert uses router address
pub fn cert_verifier_address(chain_id: u64, altda_commitment: &AltDACommitment) -> Address {
    match &altda_commitment.versioned_cert {
        EigenDAVersionedCert::V2(_) => cert_verifier_v2_address(chain_id),
        EigenDAVersionedCert::V3(_) => cert_verifier_router_address(chain_id),
    }
}

pub fn cert_verifier_router_address(chain_id: u64) -> Address {
    // this is kurtosis devnet
    match chain_id {
        // mainnet
        1 => address!("0x61692e93b6B045c444e942A91EcD1527F23A3FB7"),
        // Sepolia router cert verifier address
        11155111 => address!("0x58D2B844a894f00b7E6F9F492b9F43aD54Cd4429"),
        // holesky router cert verifier address
        17000 => address!("0xDD735AFFe77A5ED5b21ED47219f95ED841f8Ffbd"),
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
