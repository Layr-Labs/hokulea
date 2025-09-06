extern crate alloc;

use alloc::sync::Arc;
use core::fmt::Debug;

use kona_client::single::FaultProofProgramError;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use kona_proof::{l1::OracleBlobProvider, CachingOracle};

use hokulea_client::fp_client;
use hokulea_proof::eigenda_provider::OracleEigenDAPreimageProvider;

use alloy_evm::{EvmFactory, FromRecoveredTx, FromTxWithEncoded};
use op_alloy_consensus::OpTxEnvelope;
use op_revm::OpSpecId;

/// The function uses the identical function signature as the kona client
/// This is the basic hokulea client containing the minimal layer between kona client and hokulea host
#[allow(clippy::type_complexity)]
#[inline]
pub async fn run_direct_client<P, H, Evm>(
    oracle_client: P,
    hint_client: H,
    evm_factory: Evm,
) -> Result<(), FaultProofProgramError>
where
    P: PreimageOracleClient + Send + Sync + Debug + Clone,
    H: HintWriterClient + Send + Sync + Debug + Clone,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    const ORACLE_LRU_SIZE: usize = 1024;

    let oracle = Arc::new(CachingOracle::new(
        ORACLE_LRU_SIZE,
        oracle_client,
        hint_client,
    ));
    let beacon = OracleBlobProvider::new(oracle.clone());
    let eigenda_preimage_provider = OracleEigenDAPreimageProvider::new(oracle.clone());

    fp_client::run_fp_client(oracle, beacon, eigenda_preimage_provider, evm_factory).await
}
