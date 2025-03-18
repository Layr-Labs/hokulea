//! This is a crate for generating a steel proof for an eigenda blob.
use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use alloy_primitives::Address;
use anyhow::{Context, Result};
use clap::Parser;
use dacert_v2_verifier_methods::DACERT_V2_VERIFIER_ELF;
use eigenda_v2_struct_rust::EigenDAV2Cert;
use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_HOLESKY_CHAIN_SPEC},
    host::BlockNumberOrTag,
    Contract,
};
use risc0_zkvm::Receipt;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::task;
use url::Url;

use eigenda_v2_struct_rust;
use eigenda_v2_struct_rust::sol_struct::IEigenDACertVerifier;

/// Simple program to create a proof to increment the Counter contract.
#[derive(Parser, Debug)]
pub struct SteelArgs {
    /// Ethereum private key
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum RPC endpoint URL
    #[clap(long, env)]
    eth_rpc_url: Url,

    /// Beacon API endpoint URL
    ///
    /// Steel uses a beacon block commitment instead of the execution block.
    /// This allows proofs to be validated using the EIP-4788 beacon roots contract.
    #[clap(long, env)]
    #[cfg(any(feature = "beacon"))]
    beacon_api_url: Url,

    /// Ethereum block to use as the state for the contract call
    #[clap(long, env, default_value_t = BlockNumberOrTag::Parent)]
    execution_block: BlockNumberOrTag,

    /// Address of the Counter verifier contract
    #[clap(long)]
    counter_address: Address,

    /// Address of the EigenDA verifier contract
    /// used to preflight the contract only
    #[clap(long)]
    cert_verifier_contract: Address,
}

/// This function returns steel receipt
pub async fn compute_view_proof_steel(
    args: SteelArgs,
    cert: &EigenDAV2Cert,
    expected_return: bool,
) -> Result<Receipt> {
    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.eth_rpc_url);

    let view_at_execution_block = args.execution_block;

    let builder = EthEvmEnv::builder()
        .provider(provider.clone())
        .block_number_or_tag(view_at_execution_block);

    let mut env = builder.build().await?;
    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ETH_HOLESKY_CHAIN_SPEC);

    let batch_header = cert.batch_header_v2.to_sol();
    let non_signer = cert.nonsigner_stake_and_signature.to_sol();
    let mut blob_inclusion = cert.blob_inclusion_info.to_sol();
    blob_inclusion.blobIndex = blob_inclusion.blobIndex + 1;

    let batch_header_abi = batch_header.abi_encode();
    let non_signer_abi = non_signer.abi_encode();
    let blob_inclusion_abi = blob_inclusion.abi_encode();

    let expected_result_abi = expected_return.abi_encode();

    // Prepare the function call
    let call = IEigenDACertVerifier::verifyDACertV2ForZKProofCall {
        batchHeader: batch_header,
        blobInclusionInfo: blob_inclusion,
        nonSignerStakesAndSignature: non_signer,
    };

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(args.cert_verifier_contract, &mut env);
    let return_value = contract.call_builder(&call).call().await?._0;
    assert!(return_value == expected_return);

    // Finally, construct the input from the environment.
    // There are two options: Use EIP-4788 for verification by providing a Beacon API endpoint,
    // or use the regular `blockhash' opcode.
    let evm_input = env.into_input().await?;

    // Create the steel proof.
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&args.cert_verifier_contract)?
            .write(&batch_header_abi)?
            .write(&non_signer_abi)?
            .write(&blob_inclusion_abi)?
            .write(&expected_result_abi)?
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
    /*
    let journal = &receipt.journal.bytes;

    // Decode and log the commitment
    let journal = Journal::abi_decode(journal, true).context("invalid journal")?;
    log::debug!("Steel commitment: {:?}", journal.commitment);

    // ABI encode the seal.
    let seal = encode_seal(&receipt).context("invalid receipt")?;
     */
    Ok(receipt)
}
