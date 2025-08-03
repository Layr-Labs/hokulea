//! This is a crate for generating a steel proof for an eigenda blob.
use std::str::FromStr;
use std::time::Instant;

use canoe_bindings::StatusCode;

use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_HOLESKY_CHAIN_SPEC, ETH_MAINNET_CHAIN_SPEC, ETH_SEPOLIA_CHAIN_SPEC},
    host::BlockNumberOrTag,
    Contract,
};
use tokio::task;

use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};

use canoe_steel_methods::CERT_VERIFICATION_ELF;

use anyhow::{Context, Result};
use async_trait::async_trait;
use url::Url;

use canoe_provider::{CanoeInput, CanoeProvider, CertVerifierCall};
use risc0_steel::alloy::providers::ProviderBuilder;
use risc0_steel::ethereum::EthChainSpec;
use risc0_zkvm;

use hokulea_proof::canoe_verifier::cert_verifier_address;
use tracing::info;

/// A canoe provider implementation with steel
#[derive(Debug, Clone)]
pub struct CanoeSteelProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
}

#[async_trait]
impl CanoeProvider for CanoeSteelProvider {
    /// The receipt can be used for both mock proof and verification within zkVM
    type Receipt = risc0_zkvm::Receipt;

    async fn create_cert_validity_proof(&self, canoe_input: CanoeInput) -> Result<Self::Receipt> {
        info!(
            "begin to generate a steel proof invoked at l1 bn {}",
            canoe_input.l1_head_block_number
        );
        let start = Instant::now();

        let eth_rpc_url = Url::from_str(&self.eth_rpc_url).unwrap();

        // Create an alloy provider for that private key and URL.
        let provider = ProviderBuilder::new().connect_http(eth_rpc_url); //.await?;

        let chain_spec = match canoe_input.l1_chain_id {
            1 => ETH_MAINNET_CHAIN_SPEC.clone(),
            11155111 => ETH_SEPOLIA_CHAIN_SPEC.clone(),
            17000 => ETH_HOLESKY_CHAIN_SPEC.clone(),
            _ => EthChainSpec::new_single(canoe_input.l1_chain_id, Default::default()),
        };

        let mut env = EthEvmEnv::builder()
            .chain_spec(&chain_spec)
            .provider(provider.clone())
            .block_number_or_tag(BlockNumberOrTag::Number(canoe_input.l1_head_block_number))
            .build()
            .await?;

        let verifier_address =
            cert_verifier_address(canoe_input.l1_chain_id, &canoe_input.altda_commitment);

        // Preflight the call to prepare the input that is required to execute the function in
        // the guest without RPC access. It also returns the result of the call.
        let mut contract = Contract::preflight(verifier_address, &mut env);

        // Prepare the function call
        let returns = match CertVerifierCall::build(&canoe_input.altda_commitment) {
            CertVerifierCall::V2(call) => contract.call_builder(&call).call().await?,
            CertVerifierCall::Router(call) => {
                let status = contract.call_builder(&call).call().await?;
                status == StatusCode::SUCCESS as u8
            }
        };

        //let returns = contract.call_builder(&call).call().await?;
        if canoe_input.claimed_validity != returns {
            panic!("in the preflight part, zkvm arrives to a different answer than claime. Something consistent in the view of eigenda-proxy and zkVM");
        }

        // Finally, construct the input from the environment.
        let evm_input: risc0_steel::EvmInput<risc0_steel::ethereum::EthEvmFactory> =
            env.into_input().await?;

        // Create the steel proof.
        let prove_info = task::spawn_blocking(move || {
            let env = ExecutorEnv::builder()
                .write(&evm_input)?
                .write(&verifier_address)?
                .write(&canoe_input)?
                .build()
                .unwrap();

            default_prover().prove_with_ctx(
                env,
                &VerifierContext::default(),
                CERT_VERIFICATION_ELF,
                &ProverOpts::composite(),
            )
        })
        .await?
        .context("failed to create proof")?;
        let receipt = prove_info.receipt;
        let elapsed = start.elapsed();
        info!("finish a steel proof generation spent {:?}", elapsed);

        Ok(receipt)
    }

    fn get_eth_rpc_url(&self) -> String {
        self.eth_rpc_url.clone()
    }
}
