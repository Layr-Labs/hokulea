use core::fmt::Debug;
use kona_client::single::FaultProofProgramError;
use kona_executor::KonaHandleRegister;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use kona_proof::{l1::OracleBlobProvider, l2::OracleL2ChainProvider, CachingOracle};

use crate::witness::OracleEigenDAWitnessProvider;
use hokulea_client::fp_client;
use hokulea_proof::eigenda_blob_witness::EigenDABlobWitnessData;
use hokulea_proof::eigenda_provider::OracleEigenDAProvider;
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};

/// A run_witgen_client calls [fp_client] functopm to run kona derivation.
/// This client uses a special [OracleEigenDAWitnessProvider] that wraps around ][OracleEigenDAProvider]
/// It returns the eigenda blob witness to the caller, those blob witnesses can be used to prove
/// used only at the preparation phase. Its usage is contained in the crate hokulea-client-bin
/// 1. a KZG commitment is consistent to the retrieved eigenda blob
/// 2. the cert is correct
#[allow(clippy::type_complexity)]
pub async fn run_witgen_client<P, H>(
    oracle_client: P,
    hint_client: H,
    _handle_register: Option<
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

    fp_client::run_fp_client(oracle, beacon, eigenda_blob_and_witness_provider, None).await?;

    let wit = core::mem::take(eigenda_blobs_witness.lock().unwrap().deref_mut());

    Ok(wit)
}
