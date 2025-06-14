//! security critical verification for zkVm integration

extern crate alloc;
use core::fmt::Debug;
use kona_preimage::CommsClient;
use kona_proof::{errors::OracleProviderError, BootInfo, FlushableCache};

use hokulea_proof::{
    canoe_verifier::CanoeVerifier, eigenda_blob_witness::EigenDABlobWitnessData,
    preloaded_eigenda_provider::PreloadedEigenDABlobProvider,
};

use alloc::sync::Arc;

// The function overwrites information from bootInfo into EigenDABlobWitnessData, because information inside
// bootInfo is secured. It uses all the secure information to verify against the canoe proof to ensure the
// validity of the cert. Then it checks the consistency between kzg commitment from the cert and the blob.
// The function takes an oracle at whole, and assume what is inside the oracle will be or already been verified
// by kona or upstream secure integration
#[allow(clippy::type_complexity)]
pub async fn eigenda_witness_to_preloaded_provider<O>(
    oracle: Arc<O>,
    canoe_verifier: impl CanoeVerifier,
    mut witness: EigenDABlobWitnessData,
) -> Result<PreloadedEigenDABlobProvider, OracleProviderError>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
{
    let boot_info = BootInfo::load(oracle.as_ref()).await?;

    // it is critical that some field of the witness is populated inside the zkVM using known truth within the zkVM
    // force canoe verifier to use l1 chain id from rollup config.
    // it assumes the l1_chain_id from boot_info is trusted or verifiable at early or later stage
    witness.validity.iter_mut().for_each(|(_, cert_validity)| {
        cert_validity.l1_head_block_hash = boot_info.l1_head;
        cert_validity.l1_chain_id = boot_info.rollup_config.l1_chain_id;
    });

    witness.recency.iter_mut().for_each(|(_, recency)| {
        // ToDo (bx) fix the hack at eigenda-proxy. For now + 100_000_000 to avoid recency failure
        // currently, proxy only returns a rbn < 32
        *recency = boot_info.rollup_config.seq_window_size + 100_000_000;
    });

    Ok(PreloadedEigenDABlobProvider::from_witness(
        witness,
        canoe_verifier,
    ))
}
