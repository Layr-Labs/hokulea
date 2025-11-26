//! security critical verification for zkVm integration

extern crate alloc;
use core::fmt::Debug;
use kona_derive::ChainProvider;
use kona_preimage::CommsClient;
use kona_proof::{
    errors::OracleProviderError, l1::OracleL1ChainProvider, BootInfo, FlushableCache,
};

use hokulea_proof::{
    eigenda_witness::{EigenDAWitness, EigenDAWitnessWithTrustedData},
    preloaded_eigenda_provider::PreloadedEigenDAPreimageProvider,
};

use canoe_verifier::CanoeVerifier;
use canoe_verifier_address_fetcher::CanoeVerifierAddressFetcher;

use alloc::sync::Arc;

/// The function adds trusted information to [EigenDAWitness] for verifying claimed validity of DA certificate.
/// All the information comes from the loaded oracle: those includes BootInfo and Header for l1_head from the
/// bootInfo. Then it converts [EigenDAWitness] into [PreloadedEigenDAPreimageProvider] which contains all the
/// EigenDA preimage data in order to run the eigenda blob derivation. All the date from
/// [PreloadedEigenDAPreimageProvider] are considered safe to use.
#[allow(clippy::type_complexity)]
pub async fn eigenda_witness_to_preloaded_provider<O>(
    oracle: Arc<O>,
    canoe_verifier: impl CanoeVerifier,
    canoe_address_fetcher: impl CanoeVerifierAddressFetcher,
    witness: EigenDAWitness,
) -> Result<PreloadedEigenDAPreimageProvider, OracleProviderError>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
{
    let boot_info = BootInfo::load(oracle.as_ref()).await?;
    let l1_head = boot_info.l1_head;

    // fetch timestamp and block number corresponding to l1_head for determining activation fork.
    let mut l1_oracle_provider = OracleL1ChainProvider::new(l1_head, oracle);
    let header = l1_oracle_provider
        .header_by_hash(l1_head)
        .await
        .expect("should be able to get header for l1 header using oracle");

    // it is critical that some field of the witness is populated inside the zkVM using known truth within the zkVM.
    // All the data from the oracle has been verified, by Kailua and OP-succincts
    // For kailua, the check is at https://github.com/boundless-xyz/kailua/blob/2414297a5f9feb98365ef6d88634bcd181a1934b/crates/kona/src/client/stateless.rs#L61
    // For op-succinct, the check is at https://github.com/succinctlabs/op-succinct/blob/b0f190e634ab5b03a3028d4ef88e207186b48337/programs/range/eigenda/src/main.rs#L32
    let witness_with_trusted_data = EigenDAWitnessWithTrustedData {
        l1_head_block_hash: l1_head,
        l1_head_block_number: header.number,
        l1_head_block_timestamp: header.timestamp,
        l1_chain_id: boot_info.rollup_config.l1_chain_id,
        witness,
    };

    Ok(PreloadedEigenDAPreimageProvider::from_witness(
        witness_with_trusted_data,
        canoe_verifier,
        canoe_address_fetcher,
    ))
}
