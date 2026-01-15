//! Registry of custom router addresses for rollups deploying their own CertVerifiers.
//! See README.md for contribution guidelines.
#![no_std]
use alloy_primitives::Address;
use canoe_verifier_address_fetcher::{
    CanoeVerifierAddressFetcher, CanoeVerifierAddressFetcherError,
    L2SpecificCanoeVerifierAddressFetcher,
};
use eigenda_cert::EigenDAVersionedCert;

/// Registry mapping L2 chain IDs to custom router addresses. Supports Mainnet and Sepolia.
#[derive(Clone)]
pub struct HokuleaRegistry {}

impl CanoeVerifierAddressFetcher for HokuleaRegistry {
    fn fetch_address(
        &self,
        _l1_chain_id: u64,
        _versioned_cert: &EigenDAVersionedCert,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        Err(CanoeVerifierAddressFetcherError::MissingL2ChainId)
    }
}

impl L2SpecificCanoeVerifierAddressFetcher for HokuleaRegistry {
    fn fetch_address_for_l2(
        &self,
        l1_chain_id: u64,
        versioned_cert: &EigenDAVersionedCert,
        l2_chain_id: u64,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        match l1_chain_id {
            1 => self.fetch_mainnet_address(versioned_cert, l2_chain_id),
            11155111 => self.fetch_sepolia_address(versioned_cert, l2_chain_id),
            _ => Err(CanoeVerifierAddressFetcherError::UnknownL1ChainId(
                l1_chain_id,
            )),
        }
    }
}

impl HokuleaRegistry {
    fn fetch_mainnet_address(
        &self,
        _versioned_cert: &EigenDAVersionedCert,
        l2_chain_id: u64,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        match l2_chain_id {
            // Add L2 router addresses here. Example:
            // 10 => Ok(address!("0x...")),
            _ => Err(CanoeVerifierAddressFetcherError::UnknownL2ChainId(
                l2_chain_id,
                1,
            )),
        }
    }

    fn fetch_sepolia_address(
        &self,
        _versioned_cert: &EigenDAVersionedCert,
        l2_chain_id: u64,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        match l2_chain_id {
            // Add L2 router addresses here. Example:
            // 11155420 => Ok(address!("0x...")),  // OP Sepolia
            _ => Err(CanoeVerifierAddressFetcherError::UnknownL2ChainId(
                l2_chain_id,
                11155111,
            )),
        }
    }
}