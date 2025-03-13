use hokulea_eigenda::EigenDABlobProvider;
use kona_proof::{
    executor::KonaExecutor,
    l1::{OracleBlobProvider, OracleL1ChainProvider},
    l2::OracleL2ChainProvider,
    sync::new_pipeline_cursor,
    BootInfo, CachingOracle,
};
use kona_executor::{KonaHandleRegister, TrieDBProvider};
use kona_client::single::{fetch_safe_head_hash, FaultProofProgramError};
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use core::fmt::Debug;

use crate::witness::OracleEigenDAWitnessProvider;
use hokulea_proof::{eigenda_blob_witness::EigenDABlobWitnessData, preloaded_eigenda_provider::PreloadedEigenDABlobProvider};
use hokulea_client::core_client;
use std::{ops::{Deref, DerefMut}, sync::{Arc, Mutex}};
use hokulea_proof::eigenda_provider::OracleEigenDAProvider;
use tracing::info;

pub async fn run_witgen_client<P, H>(
    oracle_client: P,
    hint_client: H,
    handle_register: Option<
        KonaHandleRegister<
            OracleL2ChainProvider<CachingOracle<P, H>>,
            OracleL2ChainProvider<CachingOracle<P, H>>,
        >,
    >,
) -> Result<EigenDABlobWitnessData, FaultProofProgramError>
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
    let eigenda_blobs_witness = Arc::new(Mutex::new(EigenDABlobWitnessData::default()));

    let eigenda_blob_and_witness_provider = OracleEigenDAWitnessProvider {
        provider: eigenda_blob_provider,
        witness: eigenda_blobs_witness.clone(),
    };

    core_client::run_core_client(oracle, beacon, eigenda_blob_and_witness_provider, None).await?;

    let wit = core::mem::take(eigenda_blobs_witness.lock().unwrap().deref_mut());
    

    Ok(wit)
}

pub async fn run_preloaded_eigenda_client<P, H>(
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
    info!("run_preloaded_eigenda_client"); 
    let wit = run_witgen_client(oracle_client.clone(), hint_client.clone(), None).await?;
    const ORACLE_LRU_SIZE: usize = 1024;

    info!("done generating the wintess");
    info!("eigenda_certs {}", wit.eigenda_certs.len());
    info!("eigenda_blobs {}", wit.eigenda_blobs.len());

    let oracle = Arc::new(CachingOracle::new(
        ORACLE_LRU_SIZE,
        oracle_client,
        hint_client,
    ));
    let beacon = OracleBlobProvider::new(oracle.clone());

    info!("preloaded conversion");

    // preloaded_blob_provider does not use oracle
    let preloaded_blob_provider = PreloadedEigenDABlobProvider::from(wit);

    info!("run preloaded provider");
    info!("preloaded_blob_provider.entries {}", preloaded_blob_provider.entries.len());

    core_client::run_core_client(oracle, beacon, preloaded_blob_provider, None).await?;

    
    Ok(())
}
