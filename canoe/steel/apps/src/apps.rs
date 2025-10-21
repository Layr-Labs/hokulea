//! This is a crate for generating a steel proof for an eigenda blob.
use std::str::FromStr;
use std::time::Instant;

use alloy_primitives::B256;
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

    async fn create_certs_validity_proof(
        &self,
        canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>> {
        if canoe_inputs.is_empty() {
            return None;
        }

        Some(get_steel_proof(canoe_inputs, &self.eth_rpc_url).await)
    }

    // steel does not require config hash to pin l1 chain config
    fn get_config_hash(&self, _receipt: &Self::Receipt) -> Option<B256> {
        None
    }
}

async fn get_steel_proof(
    canoe_inputs: Vec<CanoeInput>,
    eth_rpc_url: &str,
) -> Result<risc0_zkvm::Receipt> {
    // ensure chain id and l1 block number across all DAcerts are identical
    let l1_chain_id = canoe_inputs[0].l1_chain_id;
    let l1_head_block_number = canoe_inputs[0].l1_head_block_number;
    for canoe_input in canoe_inputs.iter() {
        assert!(canoe_input.l1_chain_id == l1_chain_id);
        assert!(canoe_input.l1_head_block_number == l1_head_block_number);
    }
    let start = Instant::now();
    info!(
        "begin to generate a steel proof for {} number of altda commitment at l1 block number {} with chainID {}",
        canoe_inputs.len(),
        l1_head_block_number,
        l1_chain_id,
    );

    let eth_rpc_url = Url::from_str(eth_rpc_url)?;

    // Create an alloy provider for that private key and URL.
    let provider = ProviderBuilder::new().connect_http(eth_rpc_url);

    let chain_spec = match l1_chain_id {
        1 => ETH_MAINNET_CHAIN_SPEC.clone(),
        11155111 => ETH_SEPOLIA_CHAIN_SPEC.clone(),
        17000 => ETH_HOLESKY_CHAIN_SPEC.clone(),
        _ => EthChainSpec::new_single(l1_chain_id, Default::default()),
    };

    let mut env = EthEvmEnv::builder()
        .chain_spec(&chain_spec)
        .provider(provider.clone())
        .block_number_or_tag(BlockNumberOrTag::Number(l1_head_block_number))
        .build()
        .await?;

    for canoe_input in canoe_inputs.iter() {
        // Preflight the call to prepare the input that is required to execute the function in
        // the guest without RPC access. It also returns the result of the call.
        let mut contract = Contract::preflight(canoe_input.verifier_address, &mut env);

        // calls the function
        let is_valid = match CertVerifierCall::build(&canoe_input.altda_commitment) {
            CertVerifierCall::ABIEncodeInterface(call) => {
                let status = contract.call_builder(&call).call().await?;
                status == StatusCode::SUCCESS as u8
            }
        };

        // sanity check about the validity, abort early if not
        if canoe_input.claimed_validity != is_valid {
            panic!(
                "in the preflight part, zkvm arrives to a different answer than claimed value.
                There is something inconsistent in the view of eigenda-proxy and zkVM"
            );
        }
    }
    // Finally, construct the input from the environment.
    let evm_input: risc0_steel::EvmInput<risc0_steel::ethereum::EthEvmFactory> =
        env.into_input().await?;

    // Create the steel proof.
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&canoe_inputs)?
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
