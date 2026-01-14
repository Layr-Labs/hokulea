//! [HokuleaRegistry] contains router addresses for customers of EigenDA. The addresses entered
//! must be stable and long usages.
//! If you are using EigenLabs deployed router, please use canoe_verifier_address_fetcher crate,
//! this crate is reserved for router address for router deployed by external teams.
#![no_std]
use alloy_primitives::Address;
use eigenda_cert::EigenDAVersionedCert;
use canoe_verifier_address_fetcher::{CanoeVerifierAddressFetcher, CanoeVerifierAddressFetcherError};

#[derive(Clone)]
pub struct HokuleaRegistry {}

impl CanoeVerifierAddressFetcher for HokuleaRegistry {
    /// fetch address for canoe verifier
    fn fetch_address(
        &self,
        l1_chain_id: u64,
        versioned_cert: &EigenDAVersionedCert,
        l2_chain_id: Option<u64>,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        if l2_chain_id.is_none() {
            panic!("l2 chain id must be specified to use hokulea registry");
        }

        match l1_chain_id {
            1 => Ok(self.fetch_mainnet_address(versioned_cert, l2_chain_id.unwrap())),
            11155111 => Ok(self.fetch_sepolia_address(versioned_cert, l2_chain_id.unwrap())),
            _ => panic!("unknown L1 chain id"),
        }
    }
}

impl HokuleaRegistry {
    fn fetch_mainnet_address(
        &self,
        _versioned_cert: &EigenDAVersionedCert,
        _l2_chain_id: u64,
    ) -> Address {
        unimplemented!()
    }

    fn fetch_sepolia_address(
        &self,
        _versioned_cert: &EigenDAVersionedCert,
        _l2_chain_id: u64,
    ) -> Address {
        unimplemented!()
    }

}