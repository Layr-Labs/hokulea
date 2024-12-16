extern crate alloc;
use alloy_consensus::{Header, Sealed};
use hokulea_proof::pipeline::OraclePipeline;
use kona_client::FaultProofProgramError;
use kona_driver::Driver;
use kona_preimage::{
    CommsClient, HintWriterClient, PreimageKey, PreimageKeyType, PreimageOracleClient,
};

use alloc::sync::Arc;
use core::fmt::Debug;
use kona_executor::TrieDBProvider;
use kona_proof::{
    errors::OracleProviderError,
    executor::KonaExecutor,
    l1::{OracleBlobProvider, OracleL1ChainProvider},
    l2::OracleL2ChainProvider,
    sync::new_pipeline_cursor,
    BootInfo, CachingOracle, HintType,
};
use tracing::{error, info};

use hokulea_proof::eigenda_provider::OracleEigenDAProvider;

#[inline]
pub async fn run<P, H>(oracle_client: P, hint_client: H) -> Result<(), FaultProofProgramError>
where
    P: PreimageOracleClient + Send + Sync + Debug + Clone,
    H: HintWriterClient + Send + Sync + Debug + Clone,
{
    const ORACLE_LRU_SIZE: usize = 1024;

    ////////////////////////////////////////////////////////////////
    //                          PROLOGUE                          //
    ////////////////////////////////////////////////////////////////

    let oracle = Arc::new(CachingOracle::new(
        ORACLE_LRU_SIZE,
        oracle_client,
        hint_client,
    ));
    let boot = match BootInfo::load(oracle.as_ref()).await {
        Ok(boot) => Arc::new(boot),
        Err(e) => {
            error!(target: "client", "Failed to load boot info: {:?}", e);
            return Err(e.into());
        }
    };
    let mut l1_provider = OracleL1ChainProvider::new(boot.clone(), oracle.clone());
    let mut l2_provider = OracleL2ChainProvider::new(boot.clone(), oracle.clone());
    let beacon = OracleBlobProvider::new(oracle.clone());
    let eigenda_blob_provider = OracleEigenDAProvider::new(oracle.clone());

    // If the claimed L2 block number is less than the safe head of the L2 chain, the claim is
    // invalid.
    let safe_head = fetch_safe_head(oracle.as_ref(), boot.as_ref(), &mut l2_provider).await?;
    if boot.claimed_l2_block_number < safe_head.number {
        error!(
            target: "client",
            "Claimed L2 block number {claimed} is less than the safe head {safe}",
            claimed = boot.claimed_l2_block_number,
            safe = safe_head.number
        );
        return Err(FaultProofProgramError::InvalidClaim(
            boot.agreed_l2_output_root,
            boot.claimed_l2_output_root,
        ));
    }

    // In the case where the agreed upon L2 output root is the same as the claimed L2 output root,
    // trace extension is detected and we can skip the derivation and execution steps.
    if boot.agreed_l2_output_root == boot.claimed_l2_output_root {
        info!(
            target: "client",
            "Trace extension detected. State transition is already agreed upon.",
        );
        return Ok(());
    }

    ////////////////////////////////////////////////////////////////
    //                   DERIVATION & EXECUTION                   //
    ////////////////////////////////////////////////////////////////

    // Create a new derivation driver with the given boot information and oracle.
    let cursor = new_pipeline_cursor(&boot, safe_head, &mut l1_provider, &mut l2_provider).await?;
    let cfg = Arc::new(boot.rollup_config.clone());
    let pipeline = OraclePipeline::new(
        cfg.clone(),
        cursor.clone(),
        oracle.clone(),
        beacon,
        l1_provider.clone(),
        l2_provider.clone(),
        eigenda_blob_provider.clone(),
    );
    let executor = KonaExecutor::new(&cfg, l2_provider.clone(), l2_provider, None, None);
    let mut driver = Driver::new(cursor, executor, pipeline);

    // Run the derivation pipeline until we are able to produce the output root of the claimed
    // L2 block.
    let (number, output_root) = driver
        .advance_to_target(&boot.rollup_config, Some(boot.claimed_l2_block_number))
        .await?;

    ////////////////////////////////////////////////////////////////
    //                          EPILOGUE                          //
    ////////////////////////////////////////////////////////////////

    if output_root != boot.claimed_l2_output_root {
        error!(
            target: "client",
            "Failed to validate L2 block #{number} with output root {output_root}",
            number = number,
            output_root = output_root
        );
        return Err(FaultProofProgramError::InvalidClaim(
            output_root,
            boot.claimed_l2_output_root,
        ));
    }

    info!(
        target: "client",
        "Successfully validated L2 block #{number} with output root {output_root}",
        number = number,
        output_root = output_root
    );

    Ok(())
}

/// Fetches the safe head of the L2 chain based on the agreed upon L2 output root in the
/// [BootInfo].
async fn fetch_safe_head<O>(
    caching_oracle: &O,
    boot_info: &BootInfo,
    l2_chain_provider: &mut OracleL2ChainProvider<O>,
) -> Result<Sealed<Header>, OracleProviderError>
where
    O: CommsClient,
{
    caching_oracle
        .write(&HintType::StartingL2Output.encode_with(&[boot_info.agreed_l2_output_root.as_ref()]))
        .await
        .map_err(OracleProviderError::Preimage)?;
    let mut output_preimage = [0u8; 128];
    caching_oracle
        .get_exact(
            PreimageKey::new(*boot_info.agreed_l2_output_root, PreimageKeyType::Keccak256),
            &mut output_preimage,
        )
        .await
        .map_err(OracleProviderError::Preimage)?;

    let safe_hash = output_preimage[96..128]
        .try_into()
        .map_err(OracleProviderError::SliceConversion)?;
    l2_chain_provider
        .header_by_hash(safe_hash)
        .map(|header| Sealed::new_unchecked(header, safe_hash))
}
