extern crate alloc;
use kona_client::single::FaultProofProgramError;
use kona_preimage::{HintWriterClient, PreimageOracleClient};

use alloc::sync::Arc;
use hokulea_proof::eigenda_provider::OracleEigenDAProvider;

use core::fmt::Debug;
use kona_executor::KonaHandleRegister;
use kona_proof::{l1::OracleBlobProvider, l2::OracleL2ChainProvider, CachingOracle};

use crate::witgen_client;
use hokulea_client::fp_client;
use hokulea_proof::preloaded_eigenda_provider::PreloadedEigenDABlobProvider;
use tracing::info;

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

/// The function uses a variation of kona client function signature
/// A preloaded client runs derivation twice
/// The first round runs run_witgen_client only to populate the witness. This produces an artifact
/// that contains all the necessary preimage to run the derivation.
/// The second round uses the populated witness to run against
#[allow(clippy::type_complexity)]
pub async fn run_preloaded_eigenda_client<P, H>(
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
    info!("run_preloaded_eigenda_client: generating witness");
    let wit =
        witgen_client::run_witgen_client(oracle_client.clone(), hint_client.clone(), None).await?;
    const ORACLE_LRU_SIZE: usize = 1024;

    info!("done generating the witness");

    // Generate view proof by calling compute_view_proof(), and pass it into wit
    // When securely verify the eigenda integration, PreloadedEigenDABlobProvider::from shall be run inside the ZKVM in the
    // form of ELF. It is important to pass it to witness before calling PreloadedEigenDABlobProvider::from. Because the
    // verification is checked within the elf

    let oracle = Arc::new(CachingOracle::new(
        ORACLE_LRU_SIZE,
        oracle_client,
        hint_client,
    ));
    let beacon = OracleBlobProvider::new(oracle.clone());

    info!("convert eigenda blob witness into preloaded blob provider");

    // preloaded_blob_provider does not use oracle
    let preloaded_blob_provider = PreloadedEigenDABlobProvider::from(wit);

    info!("run preloaded provider");
    fp_client::run_fp_client(oracle, beacon, preloaded_blob_provider, None).await?;

    Ok(())
}
