//! This is a crate for generating a steel proof for an eigenda blob.
use std::str::FromStr;
use std::time::Instant;

use canoe_bindings::IEigenDACertMockVerifier;
use eigenda_v2_struct;

use risc0_steel::{ethereum::EthEvmEnv, host::BlockNumberOrTag, Contract};
use tokio::task;

use alloy_provider::ProviderBuilder;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};

use canoe_steel_methods::V2CERT_VERIFICATION_ELF;

use alloy_sol_types::SolValue;

use anyhow::{Context, Result};
use async_trait::async_trait;
use url::Url;

use canoe_provider::CanoeProvider;
use risc0_zkvm;

use hokulea_proof::{canoe_verifier::VERIFIER_ADDRESS, cert_validity::CertValidity};
use tracing::info;

/// A canoe provider implementation with steel
#[derive(Debug, Clone)]
pub struct CanoeSteelProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
}

#[async_trait]
impl CanoeProvider for CanoeSteelProvider {
    type Receipt = risc0_zkvm::Receipt;

    async fn create_cert_validity_proof(
        &self,
        eigenda_cert: eigenda_v2_struct::EigenDAV2Cert,
        cert_validity: CertValidity,
    ) -> Result<Self::Receipt> {
        info!(
            "begin to generate a steel proof invoked at l1 bn {}",
            cert_validity.l1_head_block_number
        );
        let start = Instant::now();

        let eth_rpc_url = Url::from_str(&self.eth_rpc_url).unwrap();

        // Create an alloy provider for that private key and URL.
        let provider = ProviderBuilder::new().on_http(eth_rpc_url); //.await?;

        let builder = EthEvmEnv::builder()
            .provider(provider.clone())
            .block_number_or_tag(BlockNumberOrTag::Number(cert_validity.l1_head_block_number));

        let mut env = builder.build().await?;
        //  The `with_chain_spec` method is used to specify the chain configuration.
        //env = env.with_chain_spec(&ETH_HOLESKY_CHAIN_SPEC);

        // Prepare the function call
        let call = IEigenDACertMockVerifier::verifyDACertV2ForZKProofCall {
            batchHeader: eigenda_cert.batch_header_v2.to_sol(),
            blobInclusionInfo: eigenda_cert.blob_inclusion_info.clone().to_sol(),
            nonSignerStakesAndSignature: eigenda_cert.nonsigner_stake_and_signature.to_sol(),
            signedQuorumNumbers: eigenda_cert.signed_quorum_numbers,
        };

        let batch_header_abi = call.batchHeader.abi_encode();
        let non_signer_abi = call.nonSignerStakesAndSignature.abi_encode();
        let blob_inclusion_abi = call.blobInclusionInfo.abi_encode();
        let signed_quorum_numbers_abi = call.signedQuorumNumbers.abi_encode();

        // Preflight the call to prepare the input that is required to execute the function in
        // the guest without RPC access. It also returns the result of the call.
        let mut contract = Contract::preflight(VERIFIER_ADDRESS, &mut env);

        let returns = contract.call_builder(&call).call().await?;
        assert!(cert_validity.claimed_validity == returns);

        // Finally, construct the input from the environment.
        let evm_input: risc0_steel::EvmInput<risc0_steel::ethereum::EthEvmFactory> =
            env.into_input().await?;

        // Create the steel proof.
        let prove_info = task::spawn_blocking(move || {
            let env = ExecutorEnv::builder()
                .write(&evm_input)?
                .write(&VERIFIER_ADDRESS)?
                .write(&batch_header_abi)?
                .write(&non_signer_abi)?
                .write(&blob_inclusion_abi)?
                .write(&signed_quorum_numbers_abi)?
                .build()
                .unwrap();

            default_prover().prove_with_ctx(
                env,
                &VerifierContext::default(),
                V2CERT_VERIFICATION_ELF,
                &ProverOpts::groth16(),
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
