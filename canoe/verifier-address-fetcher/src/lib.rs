//! Traits for fetching Canoe verifier contract addresses.
//!
//! - [CanoeVerifierAddressFetcher]: Base trait for implementations that don't need L2 chain ID
//! - [L2SpecificCanoeVerifierAddressFetcher]: Extended trait for L2-specific addressing (compile-time checked)
#![no_std]
use alloy_primitives::{address, Address};
use eigenda_cert::EigenDAVersionedCert;

#[derive(Debug, thiserror::Error)]
pub enum CanoeVerifierAddressFetcherError {
    /// Unknown L1 chain ID - the implementation doesn't support this L1 chain
    #[error("Unknown L1 chain ID: {0}. This L1 chain is not supported.")]
    UnknownL1ChainId(u64),
    /// L2 chain ID is required but not provided (used by HokuleaRegistry and other L2-specific implementations)
    #[error("L2 chain ID is required for this verifier address fetcher but was not provided")]
    MissingL2ChainId,
    /// Unknown L2 chain ID for the given L1 (used by HokuleaRegistry)
    #[error("Unknown L2 chain ID: {0} for L1 chain ID: {1}. This L2 is not registered. Rollup teams should submit a PR to add their router address.")]
    UnknownL2ChainId(u64, u64),
}

/// Trait for fetching verifier addresses. Use when address depends only on L1 chain ID and cert version.
/// For L2-specific addressing, use [L2SpecificCanoeVerifierAddressFetcher] instead.
pub trait CanoeVerifierAddressFetcher: Clone + Send + 'static {
    fn fetch_address(
        &self,
        l1_chain_id: u64,
        versioned_cert: &EigenDAVersionedCert,
    ) -> Result<Address, CanoeVerifierAddressFetcherError>;
}

/// Extended trait for L2-specific addressing. The l2_chain_id parameter is required (compile-time checked).
pub trait L2SpecificCanoeVerifierAddressFetcher: CanoeVerifierAddressFetcher {
    fn fetch_address_for_l2(
        &self,
        l1_chain_id: u64,
        versioned_cert: &EigenDAVersionedCert,
        l2_chain_id: u64,
    ) -> Result<Address, CanoeVerifierAddressFetcherError>;
}

/// No-op implementation that returns a zero address.
#[derive(Clone)]
pub struct CanoeNoOpVerifierAddressFetcher {}

impl CanoeVerifierAddressFetcher for CanoeNoOpVerifierAddressFetcher {
    fn fetch_address(
        &self,
        _chain_id: u64,
        _versioned_cert: &EigenDAVersionedCert,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        Ok(Address::default())
    }
}

/// Fetcher for EigenLabs-deployed router addresses on Mainnet, Sepolia, Holesky, and Kurtosis devnet.
#[derive(Clone)]
pub struct CanoeVerifierAddressFetcherDeployedByEigenLabs {}

impl CanoeVerifierAddressFetcher for CanoeVerifierAddressFetcherDeployedByEigenLabs {
    fn fetch_address(
        &self,
        chain_id: u64,
        versioned_cert: &EigenDAVersionedCert,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        cert_verifier_address(chain_id, versioned_cert)
    }
}

fn cert_verifier_address(
    chain_id: u64,
    versioned_cert: &EigenDAVersionedCert,
) -> Result<Address, CanoeVerifierAddressFetcherError> {
    match &versioned_cert {
        EigenDAVersionedCert::V2(_) => cert_verifier_address_abi_encode_interface(chain_id),
        EigenDAVersionedCert::V3(_) => cert_verifier_address_abi_encode_interface(chain_id),
        EigenDAVersionedCert::V4(_) => cert_verifier_address_abi_encode_interface(chain_id),
    }
}

fn cert_verifier_address_abi_encode_interface(
    chain_id: u64,
) -> Result<Address, CanoeVerifierAddressFetcherError> {
    match chain_id {
        1 => Ok(address!("0x1be7258230250Bc6a4548F8D59d576a87D216C12")), // Mainnet
        11155111 => Ok(address!("0x17ec4112c4BbD540E2c1fE0A49D264a280176F0D")), // Sepolia
        17000 => Ok(address!("0xDD735AFFe77A5ED5b21ED47219f95ED841f8Ffbd")), // Holesky
        3151908 => Ok(address!("0xb4B46bdAA835F8E4b4d8e208B6559cD267851051")), // Kurtosis devnet
        chain_id => Err(CanoeVerifierAddressFetcherError::UnknownL1ChainId(chain_id)),
    }
}

/// Static address implementation - always returns the same address regardless of parameters.
impl CanoeVerifierAddressFetcher for Address {
    fn fetch_address(
        &self,
        _chain_id: u64,
        _versioned_cert: &EigenDAVersionedCert,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        Ok(*self)
    }
}
