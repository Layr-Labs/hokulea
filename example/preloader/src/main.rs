//! Main entrypoint for the example binary, which runs both host and client

use clap::Parser;
use hokulea_host_bin::{cfg::SingleChainHostWithEigenDA, init_tracing_subscriber};
use hokulea_zkvm_verification::eigenda_witness_to_preloaded_provider;
use kona_client::fpvm_evm::FpvmOpEvmFactory;
use kona_client::single::FaultProofProgramError;
use kona_preimage::{
    BidirectionalChannel, CommsClient, HintWriter, HintWriterClient, OracleReader,
    PreimageOracleClient,
};
use kona_proof::CachingOracle;
use tokio::task;

use core::fmt::Debug;

use alloy_evm::{EvmFactory, FromRecoveredTx, FromTxWithEncoded};
use op_alloy_consensus::OpTxEnvelope;
use op_revm::OpSpecId;

use kona_proof::{l1::OracleBlobProvider, BootInfo, FlushableCache};

use canoe_provider::CanoeProvider;
use hokulea_client::fp_client;
use hokulea_proof::{
    canoe_verifier::CanoeVerifier, eigenda_blob_witness::EigenDABlobWitnessData,
    eigenda_provider::OracleEigenDAProvider,
};
use hokulea_witgen::witness_provider::OracleEigenDAWitnessProvider;
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};
use tracing::info;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cfg = SingleChainHostWithEigenDA::try_parse()?;
    init_tracing_subscriber(cfg.verbose)?;

    let hint = BidirectionalChannel::new()?;
    let preimage = BidirectionalChannel::new()?;

    let server_task = cfg.start_server(hint.host, preimage.host).await?;

    cfg_if::cfg_if! {
        if #[cfg(feature = "steel")] {
            use canoe_steel_apps::apps::CanoeSteelProvider;
            use hokulea_proof::canoe_verifier::steel::CanoeSteelVerifier;
            let canoe_provider = CanoeSteelProvider{
                eth_rpc_url: cfg.kona_cfg.l1_node_address.clone().unwrap(),
            };
            let canoe_verifier = CanoeSteelVerifier{};
        } else if #[cfg(feature = "sp1-cc")] {
            // Note that in order to run hokulea in zkVM with the sp1-cc proof verified within
            // the zkVM, the program input to zkVM (i.e SP1Stdin) must also contain sp1-cc compressed
            // proof using a method called write_proof(..). By doing so, the canoe verification logic
            // can pick up the compressed stark proof automatically. See more information at https://docs.succinct.xyz/docs/sp1/writing-programs/proof-aggregation
            // This is not included as a part of example, because the example does use SP1 zkVM to verify proof.
            // Particularly, op-succinct integration needs to use write_proof() to supply compressed proof
            // into SP1 zkvm when using hokulea as an ELF.
            use canoe_sp1_cc_host::CanoeSp1CCProvider;
            use hokulea_proof::canoe_verifier::sp1_cc::CanoeSp1CCVerifier;
            let canoe_provider = CanoeSp1CCProvider{
                eth_rpc_url: cfg.kona_cfg.l1_node_address.clone().unwrap(),
            };
            let canoe_verifier = CanoeSp1CCVerifier{};
        } else {
            use canoe_provider::CanoeNoOpProvider;
            use hokulea_proof::canoe_verifier::noop::CanoeNoOpVerifier;
            let canoe_provider = CanoeNoOpProvider{};
            let canoe_verifier = CanoeNoOpVerifier{};
        }
    }

    // Spawn the client logic as a concurrent task
    let client_task = task::spawn(run_witgen_and_zk_verification(
        OracleReader::new(preimage.client.clone()),
        HintWriter::new(hint.client.clone()),
        FpvmOpEvmFactory::new(
            HintWriter::new(hint.client),
            OracleReader::new(preimage.client),
        ),
        canoe_provider,
        canoe_verifier,
    ));

    let (_, client_result) = tokio::try_join!(server_task, client_task)?;

    // Bubble up the exit status of the client program if execution completes.
    std::process::exit(client_result.is_err() as i32)
}

/// The function uses a variation of kona client function signature
/// A preloaded client runs derivation twice
/// The first round runs run_witgen_client only to populate the witness. This produces an artifact
/// that contains all the necessary preimage to run the derivation.
/// The second round uses the populated witness to run against
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
pub async fn run_witgen_and_zk_verification<P, H, Evm>(
    oracle_client: P,
    hint_client: H,
    evm_factory: Evm,
    canoe_provider: impl CanoeProvider,
    canoe_verifier: impl CanoeVerifier,
) -> anyhow::Result<()>
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

    let wit = prepare_witness(oracle.clone(), evm_factory.clone(), canoe_provider).await?;

    run_within_zkvm(oracle, evm_factory, canoe_verifier, wit).await
}

/// used internal
#[allow(clippy::type_complexity)]
pub async fn prepare_witness<O, Evm>(
    oracle: Arc<O>,
    evm_factory: Evm,
    canoe_provider: impl CanoeProvider,
) -> anyhow::Result<EigenDABlobWitnessData>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    // Run derivation for the first time to populate the witness data
    let mut wit: EigenDABlobWitnessData =
        run_witgen_client(oracle.clone(), evm_factory.clone()).await?;

    if wit.require_canoe_proof() {
        // get l1 header, does not have to come from oracle directly, it is for convenience
        let boot_info = BootInfo::load(oracle.as_ref()).await?;

        // generate one canoe proof for all DA certs
        let canoe_proof = hokulea_witgen::from_boot_info_to_canoe_proof(
            &boot_info,
            &wit,
            oracle.clone(),
            canoe_provider,
        )
        .await?;

        // populate canoe proof for this example, in general canoe_proof are used differently depending on
        // where it is verified
        // for verification within zkVM, canoe_proof should be passed in to zkVM via its stdin by a special
        // function depending on zkVM framework. More see CanoeVerifier
        // For Sp1cc, use CanoeSp1CCReducedProofProvider to produce proof that is verifiable within zkVM
        // For Steel, use CanoeSteelProvider to generate such proof
        // For verification in non zkVM context,  can be passed as part of serialized bytes
        // along with other
        wit.canoe_proof_bytes = Some(serde_json::to_vec(&canoe_proof).expect("serde error"));
    }
    Ok(wit)
}

/// A run_witgen_client calls [fp_client] functopm to run kona derivation.
/// This client uses a special [OracleEigenDAWitnessProvider] that wraps around [OracleEigenDAProvider]
/// It returns the eigenda blob witness to the caller, those blob witnesses can be used to prove
/// used only at the preparation phase. Its usage is contained in the crate hokulea-client-bin
/// 1. a KZG commitment is consistent to the retrieved eigenda blob
/// 2. the cert is correct
#[allow(clippy::type_complexity)]
pub async fn run_witgen_client<O, Evm>(
    oracle: Arc<O>,
    evm_factory: Evm,
) -> Result<EigenDABlobWitnessData, FaultProofProgramError>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    let beacon = OracleBlobProvider::new(oracle.clone());

    let eigenda_blob_provider = OracleEigenDAProvider::new(oracle.clone());
    let eigenda_blobs_witness = Arc::new(Mutex::new(EigenDABlobWitnessData::default()));

    let eigenda_blob_and_witness_provider = OracleEigenDAWitnessProvider {
        provider: eigenda_blob_provider,
        witness: eigenda_blobs_witness.clone(),
    };

    fp_client::run_fp_client(
        oracle,
        beacon,
        eigenda_blob_and_witness_provider,
        evm_factory,
    )
    .await?;

    let wit = core::mem::take(eigenda_blobs_witness.lock().unwrap().deref_mut());

    Ok(wit)
}

// By this time,both Oracle and EigenDABlobWitnessData are generated by some party that runs run_witgen_client.
// This party now needs to send both of them as inputs to ZKVM. So imagine wit and oracle are sent away, and
// the code region below are some codes that runs inside ZKVM. The ZKVM will convert EigenDABlobWitnessData into
// a preloaded eigenda provider, that implements the trait get_blob. The run_fp_client are also run inside zkVM
#[allow(clippy::type_complexity)]
pub async fn run_within_zkvm<O, Evm>(
    oracle: Arc<O>,
    evm_factory: Evm,
    canoe_verifier: impl CanoeVerifier,
    witness: EigenDABlobWitnessData,
) -> anyhow::Result<()>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    info!("start the code supposed to run inside zkVM");
    let beacon = OracleBlobProvider::new(oracle.clone());
    let preloaded_blob_provider =
        eigenda_witness_to_preloaded_provider(oracle.clone(), canoe_verifier, witness).await?;

    // this is replaced by fault proof client developed by zkVM team
    fp_client::run_fp_client(oracle, beacon, preloaded_blob_provider, evm_factory).await?;

    Ok(())
}
