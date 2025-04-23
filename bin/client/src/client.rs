extern crate alloc;

use alloc::sync::Arc;
use core::fmt::Debug;

use kona_client::single::FaultProofProgramError;
use kona_executor::KonaHandleRegister;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use kona_proof::{l1::OracleBlobProvider, l2::OracleL2ChainProvider, CachingOracle};

use hokulea_client::fp_client;
use hokulea_proof::eigenda_provider::OracleEigenDAProvider;

/// The function uses the identical function signature as the kona client
/// This is the basic hokulea client containing the minimal layer between kona client and hokulea host
#[allow(clippy::type_complexity)]
#[inline]
pub async fn run_direct_client<P, H>(
    oracle_client: P,
    hint_client: H,
    _handle_register: Option<
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

    fp_client::run_fp_client(oracle, beacon, eigenda_blob_provider, None).await
}
