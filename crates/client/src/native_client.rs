extern crate alloc;
use alloy_consensus::Sealed;
use hokulea_proof::pipeline::OraclePipeline;
use kona_client::single::{fetch_safe_head_hash, FaultProofProgramError};
use kona_driver::Driver;
use kona_preimage::{HintWriterClient, PreimageOracleClient};

use hokulea_proof::eigenda_provider::OracleEigenDAProvider;
use alloc::sync::Arc;

use core::fmt::Debug;
use kona_executor::{KonaHandleRegister, TrieDBProvider};
use kona_proof::{
    executor::KonaExecutor,
    l1::{OracleBlobProvider, OracleL1ChainProvider},
    l2::OracleL2ChainProvider,
    sync::new_pipeline_cursor,
    BootInfo, CachingOracle,
};
use tracing::{error, info};

use crate::core_client::run_core_client;

// kona uses the same function signature
#[allow(clippy::type_complexity)]
#[inline]
pub async fn run_native_client<P, H>(
    oracle_client: P,
    hint_client: H,
    handle_register: Option<
        KonaHandleRegister<
            OracleL2ChainProvider<CachingOracle<P, H>>,
            OracleL2ChainProvider<CachingOracle<P, H>>,
        >,
    >,
) -> Result<(), FaultProofProgramError>
where
    P: PreimageOracleClient + Send + Sync + Debug + Clone,
    H: HintWriterClient + Send + Sync + Debug + Clone,
{
    const ORACLE_LRU_SIZE: usize = 1024;

    let oracle = Arc::new(CachingOracle::new(
        ORACLE_LRU_SIZE,
        oracle_client,
        hint_client,
    ));
    let beacon = OracleBlobProvider::new(oracle.clone());
    let eigenda_blob_provider = OracleEigenDAProvider::new(oracle.clone());

    run_core_client(oracle, beacon, eigenda_blob_provider, None).await
}
