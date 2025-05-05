//! This is a crate for generating a steel proof for an eigenda blob.
use std::str::FromStr;

use alloy_primitives::Address;
use eigenda_v2_struct;
use canoe_bindings::IEigenDACertMockVerifier;

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
use async_trait::async_trait;

use canoe_provider::CanoeProvider;
use risc0_zkvm;

use hokulea_proof::canoe_verifier::VERIFIER_ADDRESS;

/// A canoe provider implementation with steel
#[derive(Debug, Clone)]
pub struct CanoeSteelProvider {
    /// rpc to l1 geth node
    pub l1_node_address: String,
}

#[async_trait]
impl CanoeProvider for CanoeSteelProvider {
    type Receipt = risc0_zkvm::Receipt;

    async fn create_cert_validity_proof(
        &self,
        eigenda_cert: eigenda_v2_struct::EigenDAV2Cert,
        claimed_validity: bool,        
    ) -> Result<Self::Receipt> {
        create_cert_validity_proof(
            eigenda_cert.batch_header_v2.clone(),
            eigenda_cert.nonsigner_stake_and_signature.clone(),
            eigenda_cert.blob_inclusion_info.clone(),
            claimed_validity,
            self.get_l1_address(),
            VERIFIER_ADDRESS,
        ).await
    }

    fn get_l1_address(&self) -> String {
        self.l1_node_address.clone()
    }
}

/// The function takes EigenDA v2 cert and generate a validity or invality proof
pub async fn create_cert_validity_proof(
    batch_header: eigenda_v2_struct::BatchHeaderV2,
    non_signer: eigenda_v2_struct::NonSignerStakesAndSignature,
    blob_inclusion: eigenda_v2_struct::BlobInclusionInfo,
    claimed_validity: bool,
    l1_node_address: String,
    verifier_contract: Address,
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

    let blob_inclusion_info_sol = blob_inclusion.clone().to_sol();

    // Prepare the function call
    let call = IEigenDACertMockVerifier::alwaysReturnsTrueCall {
        batchHeader: batch_header.to_sol(),
        blobInclusionInfo: blob_inclusion_info_sol.clone(),
        nonSignerStakesAndSignature: non_signer.to_sol(),
        signedQuorumNumbers: blob_inclusion_info_sol.blobCertificate.blobHeader.quorumNumbers,
    };    

    let batch_header_abi = batch_header.to_sol().abi_encode();
    let non_signer_abi = non_signer.to_sol().abi_encode();
    let blob_inclusion_abi = blob_inclusion.to_sol().abi_encode();

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.    

    let mut contract = Contract::preflight(verifier_contract, &mut env);
   
    let returns = contract.call_builder(&call).call().await?;
    assert!(claimed_validity == returns);

    // Finally, construct the input from the environment.
    // There are two options: Use EIP-4788 for verification by providing a Beacon API endpoint,
    // or use the regular `blockhash' opcode.
    let evm_input: risc0_steel::EvmInput<risc0_steel::ethereum::EthEvmFactory> = env.into_input().await?;

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
