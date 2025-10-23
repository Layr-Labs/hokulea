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

// The function overwrites information from bootInfo into EigenDAWitness, because information inside
// bootInfo is secured. It uses all the secure information to verify against the canoe proof to ensure the
// validity of the cert. Then it checks the consistency between kzg commitment from the cert and the encoded payload.
// The function takes an oracle at whole, and assume what is inside the oracle will be or already been verified
// by kona or upstream secure integration
#[allow(clippy::type_complexity)]
pub async fn eigenda_witness_to_preloaded_provider<O>(
    oracle: Arc<O>,
    canoe_verifier: impl CanoeVerifier,
    canoe_address_fetcher: impl CanoeVerifierAddressFetcher,
    mut witness: EigenDAWitness,
) -> Result<PreloadedEigenDAPreimageProvider, OracleProviderError>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
{
    let boot_info = BootInfo::load(oracle.as_ref()).await?;
    let boot_info_chain_id = boot_info.rollup_config.l1_chain_id;
    let l1_head = boot_info.l1_head;

    // fetch timestamp and block number info useful for determining activation fork
    let mut l1_oracle_provider = OracleL1ChainProvider::new(l1_head, oracle);
    let header = l1_oracle_provider
        .header_by_hash(l1_head)
        .await
        .expect("should be able to get header for l1 header using oracle");
    let l1_header_timestamp = header.timestamp;
    let l1_header_block_number = header.number;

    // it is critical that some field of the witness is populated inside the zkVM using known truth within the zkVM
    // force canoe verifier to use l1 chain id from rollup config.
    // it assumes the l1_chain_id from boot_info is trusted or verifiable at early or later stage
    //
    // Note, the chain_config_hash is not provided by via boot info. The l1 boot info is included only after
    // kona 1.1.3 release. For backward compatibility, we accept the hash returned from the certValidity but
    // verify it inside Canoe Verifier
    witness
        .validities
        .iter_mut()
        .for_each(|(altda_commitment, cert_validity)| {
            cert_validity.l1_head_block_hash = boot_info.l1_head;
            cert_validity.l1_chain_id = boot_info_chain_id;
            cert_validity.l1_head_block_number = l1_header_block_number;
            cert_validity.l1_head_block_timestamp = l1_header_timestamp;
            cert_validity.verifier_address = canoe_address_fetcher
                .fetch_address(boot_info_chain_id, &altda_commitment.versioned_cert)
                .expect("should be able to get verifier address");
        });

    witness
        .recencies
        .iter_mut()
        .for_each(|(_, recency)| *recency = boot_info.rollup_config.seq_window_size);

    Ok(PreloadedEigenDAPreimageProvider::from_witness(
        witness,
        canoe_verifier,
    ))
}
