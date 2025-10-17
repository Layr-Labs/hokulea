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
use canoe_verifier::CanoeVerifier;
use canoe_verifier_address_fetcher::{
    CanoeVerifierAddressFetcher, CanoeVerifierAddressFetcherDeployedByEigenLabs,
};

use hokulea_client::fp_client;
use hokulea_proof::{
    eigenda_provider::OracleEigenDAPreimageProvider, eigenda_witness::EigenDAWitness,
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
            use canoe_steel_verifier::CanoeSteelVerifier;
            //use hokulea_proof::canoe_verifier::steel::CanoeSteelVerifier;
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
            use canoe_sp1_cc_host::CanoeSp1CCReducedProofProvider;
            use canoe_sp1_cc_verifier::CanoeSp1CCVerifier;
            use sp1_sdk::{ProverClient, HashableKey};
            use std::env;

            const CANOE_SP1CC_ELF: &[u8] = canoe_sp1_cc_host::ELF;
            let client = ProverClient::from_env();
            let (_pk, canoe_vk) = client.setup(CANOE_SP1CC_ELF);

            println!("canoe sp1cc v_key {:?}", canoe_vk.vk.hash_u32() );

            let mock_mode = env::var("OP_SUCCINCT_MOCK")
                .map(|v| v.to_ascii_lowercase())
                .ok()
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(false);

            let canoe_provider = CanoeSp1CCReducedProofProvider{
                eth_rpc_url: cfg.kona_cfg.l1_node_address.clone().unwrap(),
                mock_mode,
            };
            let canoe_verifier = CanoeSp1CCVerifier{};
        } else {
            use canoe_provider::CanoeNoOpProvider;
            use canoe_verifier::CanoeNoOpVerifier;
            let canoe_provider = CanoeNoOpProvider{};
            let canoe_verifier = CanoeNoOpVerifier{};
        }
    }

    let canoe_address_fetcher = CanoeVerifierAddressFetcherDeployedByEigenLabs {};

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
        canoe_address_fetcher,
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
    canoe_address_fetcher: impl CanoeVerifierAddressFetcher,
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

    let wit = prepare_witness(
        oracle.clone(),
        evm_factory.clone(),
        canoe_provider,
        canoe_address_fetcher.clone(),
    )
    .await?;

    run_within_zkvm(
        oracle,
        evm_factory,
        canoe_verifier,
        canoe_address_fetcher,
        wit,
    )
    .await
}

/// used internal
#[allow(clippy::type_complexity)]
pub async fn prepare_witness<O, Evm>(
    oracle: Arc<O>,
    evm_factory: Evm,
    canoe_provider: impl CanoeProvider,
    canoe_address_fetcher: impl CanoeVerifierAddressFetcher,
) -> anyhow::Result<EigenDAWitness>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    // Run derivation for the first time to populate the witness data
    let mut wit: EigenDAWitness = run_witgen_client(oracle.clone(), evm_factory.clone()).await?;

    // get l1 header, does not have to come from oracle directly, it is for convenience
    let boot_info = BootInfo::load(oracle.as_ref()).await?;

    // generate one canoe proof for all DA certs
    let canoe_proof = hokulea_witgen::from_boot_info_to_canoe_proof(
        &boot_info,
        &wit,
        oracle.clone(),
        canoe_provider.clone(),
        canoe_address_fetcher,
    )
    .await?;

    // populate canoe proof only if there are validity to be proven against
    //
    // for verification within zkVM, canoe_proof should be passed into zkVM via its stdin by a special
    // function depending on zkVM framework. More see CanoeVerifier
    // For Sp1cc, use CanoeSp1CCReducedProofProvider to produce proof that is verifiable within zkVM
    // For Steel, use CanoeSteelProvider to generate such proof
    // For verification in non zkVM context, the proof can be passed as part of serialized bytes
    if let Some(proof) = canoe_proof {
        // chain_config_hash will be verified later within zkVM
        match canoe_provider.get_config_hash(&proof) {
            // for sp1-cc that requires verification of chain config hash
            Some(chain_config_hash) => wit
                .validities
                .iter_mut()
                .for_each(|j| j.1.chain_config_hash = Some(chain_config_hash)),
            // for steel that does not requires verification of chain config hash
            None => wit
                .validities
                .iter_mut()
                .for_each(|j| j.1.chain_config_hash = None),
        };
        wit.canoe_proof_bytes = Some(serde_json::to_vec(&proof).expect("serde error"));
    }

    Ok(wit)
}

/// A run_witgen_client calls [fp_client] function to run kona derivation.
/// This client uses an [OracleEigenDAWitnessProvider] that wraps around [OracleEigenDAPreimageProvider]
/// It returns the eigenda witness to the caller, those witnesses can be used to prove
/// used only at the preparation phase. Its usage is contained in the crate hokulea-client-bin
/// 1. a KZG commitment is consistent to the retrieved encoded payload (i.e. after taking IFFT, the KZG commitment
///    with monomial SRS basis yields to the same KZG commitment)
/// 2. the cert is correct
#[allow(clippy::type_complexity)]
pub async fn run_witgen_client<O, Evm>(
    oracle: Arc<O>,
    evm_factory: Evm,
) -> Result<EigenDAWitness, FaultProofProgramError>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    let beacon = OracleBlobProvider::new(oracle.clone());

    let eigenda_preimage_provider = OracleEigenDAPreimageProvider::new(oracle.clone());
    let eigenda_witness = Arc::new(Mutex::new(EigenDAWitness::default()));

    let eigenda_witness_provider = OracleEigenDAWitnessProvider {
        provider: eigenda_preimage_provider,
        witness: eigenda_witness.clone(),
    };

    fp_client::run_fp_client(oracle, beacon, eigenda_witness_provider, evm_factory).await?;

    let wit = core::mem::take(eigenda_witness.lock().unwrap().deref_mut());

    Ok(wit)
}

// By this time,both Oracle and EigenDAWitness are generated by some party that runs run_witgen_client.
// This party now needs to send both of them as inputs to ZKVM. So imagine wit and oracle are sent away, and
// the code region below are some codes that runs inside ZKVM. The ZKVM will convert EigenDAWitness into
// a preloaded eigenda provider, that implements the trait get_encoded_payload. The run_fp_client are also run inside zkVM
#[allow(clippy::type_complexity)]
pub async fn run_within_zkvm<O, Evm>(
    oracle: Arc<O>,
    evm_factory: Evm,
    canoe_verifier: impl CanoeVerifier,
    canoe_address_fetcher: impl CanoeVerifierAddressFetcher,
    witness: EigenDAWitness,
) -> anyhow::Result<()>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    info!("start the code supposed to run inside zkVM");

    let beacon = OracleBlobProvider::new(oracle.clone());
    let preloaded_preimage_provider = eigenda_witness_to_preloaded_provider(
        oracle.clone(),
        canoe_verifier,
        canoe_address_fetcher,
        witness,
    )
    .await?;

    // this is replaced by fault proof client developed by zkVM team
    fp_client::run_fp_client(oracle, beacon, preloaded_preimage_provider, evm_factory).await?;

    Ok(())
}
