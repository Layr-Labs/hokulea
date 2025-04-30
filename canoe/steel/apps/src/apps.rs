//! This is a crate for generating a steel proof for an eigenda blob.
use std::str::FromStr;

use alloy_primitives::Address;
use eigenda_v2_struct;
use eigenda_v2_struct::sol_struct::IEigenDACertVerifier;

use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_HOLESKY_CHAIN_SPEC},
    host::BlockNumberOrTag,
    Contract,
};
use tokio::task;

use alloy_provider::ProviderBuilder;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};

use canoe_steel_methods::DACERT_V2_VERIFIER_ELF;

use alloy_sol_types::SolValue;

use anyhow::{Context, Result};
use risc0_zkvm::Receipt;
use url::Url;

use clap::Parser;

/// Necessary data to run steel
#[derive(Parser, Clone, Debug)]
pub struct SteelArgs {
    /// Ethereum private key
    //#[clap(long, env)]
    //eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum RPC endpoint URL
    #[clap(long, env)]
    eth_rpc_url: Url,
}

/// The function takes EigenDA v2 cert and generate a validity or invality proof
pub async fn create_cert_validity_proof(
    batch_header: eigenda_v2_struct::BatchHeaderV2,
    non_signer: eigenda_v2_struct::NonSignerStakesAndSignature,
    blob_inclusion: eigenda_v2_struct::BlobInclusionInfo,
    claimed_validity: bool,
    l1_node_address: String,
) -> Result<Receipt> {

    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    //tracing_subscriber::fmt()
    //    .with_env_filter(EnvFilter::from_default_env())
    //    .init();
    // Parse the command line arguments.
    //let args = SteelArgs::try_parse()?;
    let eth_rpc_url = Url::from_str(&l1_node_address).unwrap();

    // Create an alloy provider for that private key and URL.
    //let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()        
    //    .wallet(wallet)
        .on_http(eth_rpc_url);

    let builder = EthEvmEnv::builder()
        .provider(provider.clone())
        .block_number_or_tag(BlockNumberOrTag::Parent);    

    let mut env = builder.build().await?;
    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ETH_HOLESKY_CHAIN_SPEC);

    let blobInclusionInfo_sol = blob_inclusion.clone().to_sol();

    // Prepare the function call
    let call = IEigenDACertVerifier::alwaysReturnsTrueCall {
        batchHeader: batch_header.to_sol(),
        blobInclusionInfo: blobInclusionInfo_sol.clone(),
        nonSignerStakesAndSignature: non_signer.to_sol(),
        signedQuorumNumbers: blobInclusionInfo_sol.blobCertificate.blobHeader.quorumNumbers,
    };    

    let batch_header_abi = batch_header.to_sol().abi_encode();
    let non_signer_abi = non_signer.to_sol().abi_encode();
    let blob_inclusion_abi = blob_inclusion.to_sol().abi_encode();

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.

    // TODO make it configurable
    let verifier_contract = Address::from_str("0x422A3492e218383753D8006C7Bfa97815B44373F").unwrap();

    let mut contract = Contract::preflight(verifier_contract, &mut env);
   
    let returns = contract.call_builder(&call).call().await?._0;
    assert!(claimed_validity == returns);

    // Finally, construct the input from the environment.
    // There are two options: Use EIP-4788 for verification by providing a Beacon API endpoint,
    // or use the regular `blockhash' opcode.
    let evm_input = env.into_input().await?;

    // Create the steel proof.
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&verifier_contract)?
            .write(&batch_header_abi)?
            .write(&non_signer_abi)?
            .write(&blob_inclusion_abi)?
            .write(&claimed_validity)?
            .build()
            .unwrap();

        default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            DACERT_V2_VERIFIER_ELF,
            &ProverOpts::groth16(),
        )
    })
    .await?
    .context("failed to create proof")?;
    let receipt = prove_info.receipt;


    Ok(receipt)
}
