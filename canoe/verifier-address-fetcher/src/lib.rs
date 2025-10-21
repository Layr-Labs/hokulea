//! create [CanoeVerifierAddressFetcher] trait which returns contract verifier address, which the
//! CanoeVerifier and CanoeProvider relies on to verify and prove the smart contract logic against.
//! EigenLabs deploys CertVerifier and CertVerifier router contracts on each chains. However, a
//! rollup has the option to deployed their own CertVerifier or router, if the rollup has security
//! constraint.
#![no_std]
use alloy_primitives::{address, Address};
use eigenda_cert::EigenDAVersionedCert;

#[derive(Debug, thiserror::Error)]
pub enum CanoeVerifierAddressFetcherError {
    /// Cannot fetch address for chainID
    #[error("Unable to fetch contract address with chain id {0} for abi encode interface, available for router and at least V3 certificate")]
    UnknownChainIDForABIEncodeInterface(u64),
}

pub trait CanoeVerifierAddressFetcher: Clone + Send + 'static {
    /// fetch address for canoe verifier
    fn fetch_address(
        &self,
        chain_id: u64,
        versioned_cert: &EigenDAVersionedCert,
    ) -> Result<Address, CanoeVerifierAddressFetcherError>;
}

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

#[derive(Clone)]
pub struct CanoeVerifierAddressFetcherDeployedByEigenLabs {}

impl CanoeVerifierAddressFetcher for CanoeVerifierAddressFetcherDeployedByEigenLabs {
    // From V3 certificate and forward, Eigenlabs uses the address router implementation, which automatically picks the right
    // verification logics inside the smart contract based on reference block number(rbn) stored inside the Abi encoded cert.
    // For users that does not want a router, you can still implements the routing logics offchain by inspecting the rbn within
    // the EigenDAVersionedCert
    fn fetch_address(
        &self,
        chain_id: u64,
        versioned_cert: &EigenDAVersionedCert,
    ) -> Result<Address, CanoeVerifierAddressFetcherError> {
        cert_verifier_address(chain_id, versioned_cert)
    }
}

/// get cert verifier address based on chain id, and cert version from altda commitment
/// V3 cert uses router address
fn cert_verifier_address(
    chain_id: u64,
    versioned_cert: &EigenDAVersionedCert,
) -> Result<Address, CanoeVerifierAddressFetcherError> {
    // all cert version use the new interface
    // https://github.com/Layr-Labs/eigenda/blob/e51dcc5f2919c952bc8f603d1269528ee5373ad1/contracts/src/integrations/cert/interfaces/IEigenDACertVerifierBase.sol#L11
    match &versioned_cert {
        EigenDAVersionedCert::V2(_) => cert_verifier_address_abi_encode_interface(chain_id),
        EigenDAVersionedCert::V3(_) => cert_verifier_address_abi_encode_interface(chain_id),
    }
}

/// for smart contract functions that only accepts bytes
/// this pattern is adopted since V3 certificate and address router implementation
/// <https://github.com/Layr-Labs/eigenda/blob/bf714cb07fc2dee8b8c8ad7fb6043f9a030f7550/contracts/src/integrations/cert/interfaces/IEigenDACertVerifierBase.sol#L11>
fn cert_verifier_address_abi_encode_interface(
    chain_id: u64,
) -> Result<Address, CanoeVerifierAddressFetcherError> {
    // this is kurtosis devnet
    match chain_id {
        // mainnet
        1 => Ok(address!("0x1be7258230250Bc6a4548F8D59d576a87D216C12")),
        // Sepolia router cert verifier address
        11155111 => Ok(address!("0x17ec4112c4BbD540E2c1fE0A49D264a280176F0D")),
        // holesky router cert verifier address
        17000 => Ok(address!("0xDD735AFFe77A5ED5b21ED47219f95ED841f8Ffbd")),
        // kurtosis l1 chain id => mock contract address
        // This is the cert verifier that canoe provider and verifier are run against.
        // In hokulea repo, there is a mock contract under canoe directory, which can be
        // deployed to generate the address and test functionality.
        // if user uses a different private key, or nonce for deployment are different from
        // the default, the address below would change
        3151908 => Ok(address!("0xb4B46bdAA835F8E4b4d8e208B6559cD267851051")),
        chain_id => {
            Err(CanoeVerifierAddressFetcherError::UnknownChainIDForABIEncodeInterface(chain_id))
        }
    }
}
