extern crate alloc;
use alloc::sync::Arc;
use core::fmt::Debug;

use alloy_consensus::Sealed;
use tracing::{error, info};

use hokulea_eigenda::{EigenDADataSource, EigenDAPreimageProvider, EigenDAPreimageSource};

use kona_client::single::{fetch_safe_head_hash, FaultProofProgramError};
use kona_derive::traits::BlobProvider;
use kona_driver::Driver;
use kona_executor::TrieDBProvider;
use kona_preimage::CommsClient;
use kona_proof::{
    executor::KonaExecutor, l1::OracleL1ChainProvider, l1::OraclePipeline,
    l2::OracleL2ChainProvider, sync::new_oracle_pipeline_cursor, BootInfo, FlushableCache,
};

use kona_derive::sources::EthereumDataSource;

use alloy_evm::{EvmFactory, FromRecoveredTx, FromTxWithEncoded};
use op_alloy_consensus::OpTxEnvelope;
use op_revm::OpSpecId;

// The core client takes both beacon and eigenda struct, this is
pub async fn run_fp_client<
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    E: EigenDAPreimageProvider + Send + Sync + Debug + Clone,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
>(
    oracle: Arc<O>,
    beacon: B,
    eigenda: E,
    evm_factory: Evm,
) -> Result<(), FaultProofProgramError>
where
    <B as BlobProvider>::Error: Debug,
    <E as EigenDAPreimageProvider>::Error: Debug,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    ////////////////////////////////////////////////////////////////
    //                          PROLOGUE                          //
    ////////////////////////////////////////////////////////////////

    let boot = BootInfo::load(oracle.as_ref()).await?;
    let rollup_config = Arc::new(boot.rollup_config);

    let safe_head_hash = fetch_safe_head_hash(oracle.as_ref(), boot.agreed_l2_output_root).await?;

    let mut l1_provider = OracleL1ChainProvider::new(boot.l1_head, oracle.clone());
    let mut l2_provider =
        OracleL2ChainProvider::new(safe_head_hash, rollup_config.clone(), oracle.clone());

    // If the claimed L2 block number is less than the safe head of the L2 chain, the claim is
    // invalid.
    // Fetch the safe head's block header.
    let safe_head = l2_provider
        .header_by_hash(safe_head_hash)
        .map(|header| Sealed::new_unchecked(header, safe_head_hash))?;

    // If the claimed L2 block number is less than the safe head of the L2 chain, the claim is
    // invalid.
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

    // Create a new derivation driver with the given boot information and oracle.
    let cursor = new_oracle_pipeline_cursor(
        rollup_config.as_ref(),
        safe_head,
        &mut l1_provider,
        &mut l2_provider,
    )
    .await?;
    l2_provider.set_cursor(cursor.clone());

    let dap = EthereumDataSource::new_from_parts(l1_provider.clone(), beacon, &rollup_config);
    let eigenda_preimage_source = EigenDAPreimageSource::new(eigenda);
    let dap = EigenDADataSource::new(dap, eigenda_preimage_source);

    let pipeline = OraclePipeline::new(
        rollup_config.clone(),
        cursor.clone(),
        oracle.clone(),
        dap,
        l1_provider.clone(),
        l2_provider.clone(),
    )
    .await?;

    let executor = KonaExecutor::new(
        rollup_config.as_ref(),
        l2_provider.clone(),
        l2_provider,
        evm_factory,
        None,
    );

    let mut driver = Driver::new(cursor, executor, pipeline);

    // Run the derivation pipeline until we are able to produce the output root of the claimed
    // L2 block.
    let (safe_head, output_root) = driver
        .advance_to_target(rollup_config.as_ref(), Some(boot.claimed_l2_block_number))
        .await?;

    ////////////////////////////////////////////////////////////////
    //                          EPILOGUE                          //
    ////////////////////////////////////////////////////////////////

    if output_root != boot.claimed_l2_output_root {
        error!(
            target: "client",
            "Failed to validate L2 block #{number} with output root {output_root}",
            number = safe_head.block_info.number,
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
        number = safe_head.block_info.number,
        output_root = output_root
    );

    Ok(())
}
