//! security critical verification for zkVm integration

extern crate alloc;
use core::fmt::Debug;
use kona_derive::ChainProvider;
use kona_preimage::CommsClient;
use kona_proof::{
    errors::OracleProviderError, l1::OracleL1ChainProvider, BootInfo, FlushableCache,
};

use hokulea_proof::{
    eigenda_witness::EigenDAWitness, preloaded_eigenda_provider::PreloadedEigenDAPreimageProvider,
};

use canoe_verifier::CanoeVerifier;
use canoe_verifier_address_fetcher::CanoeVerifierAddressFetcher;

use alloc::sync::Arc;

/// The function adds trusted information to [EigenDAWitness] for verifying claimed validity of DA certificate.
/// All the information comes from the provided BootInfo and Header for l1_head from the oracle.
/// Then it converts [EigenDAWitness] into [PreloadedEigenDAPreimageProvider] which contains all the
/// EigenDA preimage data in order to run the eigenda blob derivation. All the data from
/// [PreloadedEigenDAPreimageProvider] are considered safe to use.
///
/// The caller is responsible for loading the [BootInfo] using the appropriate method for their chain
/// (e.g., `kona_proof::BootInfo::load()` or `celo_proof::CeloBootInfo::load()`).
#[allow(clippy::type_complexity)]
pub async fn eigenda_witness_to_preloaded_provider<O>(
    oracle: Arc<O>,
    boot_info: &BootInfo,
    canoe_verifier: impl CanoeVerifier,
    canoe_address_fetcher: impl CanoeVerifierAddressFetcher,
    witness: EigenDAWitness,
) -> Result<PreloadedEigenDAPreimageProvider, OracleProviderError>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
{
    let l1_head = boot_info.l1_head;

    // fetch timestamp and block number corresponding to l1_head for determining activation fork.
    let mut l1_oracle_provider = OracleL1ChainProvider::new(l1_head, oracle);
    let header = l1_oracle_provider
        .header_by_hash(l1_head)
        .await
        .expect("should be able to get header for l1 header using oracle");

    // It is critical that the L1 context passed to from_witness is populated inside the zkVM
    // from already-verified oracle truth. All data from the oracle has been verified by the
    // respective zkVM host (Kailua: stateless.rs#L61, op-succinct: range/eigenda/src/main.rs#L32).
    // Supplying incorrect values would allow accepting invalid DA certificates or rejecting valid ones.
    Ok(PreloadedEigenDAPreimageProvider::from_witness(
        witness,
        l1_head,
        header.number,
        header.timestamp,
        boot_info.rollup_config.l1_chain_id,
        canoe_verifier,
        canoe_address_fetcher,
    ))
}
