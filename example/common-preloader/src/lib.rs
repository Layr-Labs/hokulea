//! Common libary for all preloaders

use core::fmt::Debug;
use kona_client::single::FaultProofProgramError;
use kona_preimage::{CommsClient, HintWriterClient, PreimageKey, PreimageOracleClient};
use kona_proof::{l1::OracleBlobProvider, BootInfo, CachingOracle, FlushableCache};

use hokulea_client::fp_client;
use hokulea_proof::{
    canoe_verifier::CanoeVerifier, eigenda_blob_witness::EigenDABlobWitnessData,
    eigenda_provider::OracleEigenDAProvider,
    preloaded_eigenda_provider::PreloadedEigenDABlobProvider,
};
use hokulea_witgen::witness_provider::OracleEigenDAWitnessProvider;
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};
use tracing::info;

use alloy_consensus::Header;
use alloy_evm::{EvmFactory, FromRecoveredTx, FromTxWithEncoded};
use alloy_rlp::Decodable;
use op_alloy_consensus::OpTxEnvelope;
use op_revm::OpSpecId;

use canoe_provider::CanoeProvider;


#[allow(clippy::type_complexity)]
pub async fn prepare_witness<O, Evm>(
    oracle: Arc<O>,
    evm_factory: Evm,
    canoe_provider: impl CanoeProvider,
) -> Result<EigenDABlobWitnessData, FaultProofProgramError>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    // Run derivation for the first time to populate the witness data
    let mut wit: EigenDABlobWitnessData =
        run_witgen_client(oracle.clone(), evm_factory.clone()).await?;
    info!("done generating the witness");

    // get l1 header, does not have to come from oracle directly, it is for convenience
    let boot_info = BootInfo::load(oracle.as_ref()).await?;
    let header_rlp = oracle
        .get(PreimageKey::new_keccak256(*boot_info.l1_head))
        .await
        .expect("get l1 header based on l1 head");
    // Decode the header RLP into a Header.
    let l1_head_header = Header::decode(&mut header_rlp.as_slice()).expect("rlp decode l1 header");

    let num_cert = wit.validity.len();
    for i in 0..num_cert {
        wit.validity[i].l1_head_block_hash = boot_info.l1_head;
        wit.validity[i].l1_head_block_number = l1_head_header.number;

        let cert = &wit.eigenda_certs[i];

        let canoe_proof = canoe_provider
            .create_cert_validity_proof(cert.clone(), wit.validity[i].clone())
            .await
            .expect("must be able generate a canoe zk proof attesting eth state");

        let canoe_proof_bytes = serde_json::to_vec(&canoe_proof).expect("serde error");
        wit.validity[i].receipt = canoe_proof_bytes;
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
