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

/*

pub async fn run_witgen_client<P, H>(
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


    hokulea_client::run(
        OracleReader::new(preimage.client),
        HintWriter::new(hint.client),
        None,
    )
}
 */