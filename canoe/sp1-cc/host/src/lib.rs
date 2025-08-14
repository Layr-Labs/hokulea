use alloy_primitives::Address;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::{sol_data::Bool, SolType};
use anyhow::Result;
use async_trait::async_trait;
use canoe_bindings::StatusCode;
use canoe_provider::{CanoeInput, CanoeProvider, CanoeProviderError, CertVerifierCall};
use eigenda_cert::EigenDAVersionedCert;
use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::{EvmSketch, Genesis};
use sp1_sdk::{ProverClient, SP1Proof, SP1Stdin};
use std::str::FromStr;
use std::time::Instant;
use tracing::{info, warn};
use url::Url;

/// The ELF we want to execute inside the zkVM.
pub const ELF: &[u8] = include_bytes!("../../elf/canoe-sp1-cc-client");
/// A canoe provider implementation with Sp1 contract call
/// CanoeSp1CCProvider produces the receipt of type SP1ProofWithPublicValues,
/// SP1ProofWithPublicValues contains a Stark proof which can be verified in
/// native program using sp1-sdk. However, if you requires Stark verification
/// within zkVM, please use [CanoeSp1CCReducedProofProvider]
#[derive(Debug, Clone)]
pub struct CanoeSp1CCProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCProvider {
    type Receipt = sp1_sdk::SP1ProofWithPublicValues;

    async fn create_certs_validity_proof(
        &self,
        canoe_inputs: Vec<CanoeInput>,
    ) -> Result<Self::Receipt> {
        get_sp1_cc_proof(canoe_inputs, &self.eth_rpc_url).await
    }

    fn get_eth_rpc_url(&self) -> String {
        self.eth_rpc_url.clone()
    }
}

/// A canoe provider implementation with Sp1 contract call
/// The receipt only contains the stark proof from the SP1ProofWithPublicValues, which is produced
/// by the implementation CanoeSp1CCProvider.
/// CanoeSp1CCReducedProofProvider is needs when the proof verification takes place within
/// zkVM. If you don't require verification within zkVM, please consider using [CanoeSp1CCProvider].
#[derive(Debug, Clone)]
pub struct CanoeSp1CCReducedProofProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCReducedProofProvider {
    type Receipt = sp1_core_executor::SP1ReduceProof<sp1_prover::InnerSC>;

    async fn create_certs_validity_proof(
        &self,
        canoe_inputs: Vec<CanoeInput>,
    ) -> Result<Self::Receipt> {
        let proof = get_sp1_cc_proof(canoe_inputs, &self.eth_rpc_url).await?;
        let SP1Proof::Compressed(proof) = proof.proof else {
            panic!("cannot get Sp1ReducedProof")
        };
        Ok(*proof)
    }

    fn get_eth_rpc_url(&self) -> String {
        self.eth_rpc_url.clone()
    }
}

async fn get_sp1_cc_proof(
    canoe_inputs: Vec<CanoeInput>,
    eth_rpc_url: &str,
) -> Result<sp1_sdk::SP1ProofWithPublicValues> {
    if canoe_inputs.is_empty() {
        return Err(CanoeProviderError::EmptyCanoeInput.into());
    }
    // ensure chain id and l1 block number across all DAcerts are identical
    let l1_chain_id = canoe_inputs[0].l1_chain_id;
    let l1_head_block_number = canoe_inputs[0].l1_head_block_number;
    for canoe_input in canoe_inputs.iter() {
        assert!(canoe_input.l1_chain_id == l1_chain_id);
        assert!(canoe_input.l1_head_block_number == l1_head_block_number);
    }
    let start = Instant::now();
    info!(
        "begin to generate a sp1-cc proof for {} number of altda commitment at l1 block number {} with chainID {}",
        canoe_inputs.len(),
        l1_head_block_number,
        l1_chain_id,
    );

    // Which block VerifyDACert eth-calls are executed against.
    let block_number = BlockNumberOrTag::Number(l1_head_block_number);

    let rpc_url = Url::from_str(eth_rpc_url).unwrap();

    let sketch = match Genesis::try_from(l1_chain_id) {
        Ok(genesis) => {
            EvmSketch::builder()
                .at_block(block_number)
                .with_genesis(genesis)
                .el_rpc_url(rpc_url)
                .build()
                .await?
        }
        // if genesis is not available in the sp1-cc library, the code uses the default Genesis, which currently in
        // sp1-cc is the mainnet. Ideally, Sp1-cc should make it easier to use a custom genesis config.
        Err(_) => {
            warn!("Only use for testing environment");
            EvmSketch::builder()
                .at_block(block_number)
                .el_rpc_url(rpc_url)
                .build()
                .await?
        }
    };

    // pre populate the state
    for canoe_input in canoe_inputs.iter() {
        let contract_input = match CertVerifierCall::build(&canoe_input.altda_commitment) {
            CertVerifierCall::V2(call) => {
                ContractInput::new_call(canoe_input.verifier_address, Address::default(), call)
            }
            CertVerifierCall::Router(call) => {
                ContractInput::new_call(canoe_input.verifier_address, Address::default(), call)
            }
        };

        let returns_bytes = sketch
            .call_raw(&contract_input)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        // If the view call reverts within EVM, the output is empty. Therefore abi_decode can correctly
        // catch such case. But ideally, the sp1-cc should handle the type conversion for its users.
        // Talked to sp1-cc developer already, and it is agreed.
        let is_valid = match &canoe_input.altda_commitment.versioned_cert {
            EigenDAVersionedCert::V2(_) => {
                Bool::abi_decode(&returns_bytes).expect("deserialize returns_bytes")
            }
            EigenDAVersionedCert::V3(_) => {
                let returns = <StatusCode as SolType>::abi_decode(&returns_bytes)
                    .expect("deserialize returns_bytes");
                returns == StatusCode::SUCCESS
            }
        };

        if is_valid != canoe_input.claimed_validity {
            panic!("in the host executor part, executor arrives to a different answer than the claimed answer. Something inconsistent in the view of eigenda-proxy and zkVM");
        }
    }

    let evm_state_sketch = sketch
        .finalize()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Feed the sketch into the client.
    let input_bytes = bincode::serialize(&evm_state_sketch)
        .expect("bincode should have serialized the EVM sketch");
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes);
    stdin.write(&canoe_inputs);

    // Create a `ProverClient`.
    let client = ProverClient::from_env();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client
        .execute(ELF, &stdin)
        .run()
        .expect("sp1-cc should have executed the ELF");
    info!(
        "executed program with {} cycles",
        report.total_instruction_count()
    );

    // Generate the proof for the given program and input.
    let (pk, _vk) = client.setup(ELF);
    let proof = client
        .prove(&pk, &stdin)
        .compressed()
        .run()
        .expect("sp1-cc should have produced a compressed proof");

    let elapsed = start.elapsed();
    info!(
        action = "sp1_cc_proof_generation",
        status = "completed",
        "sp1-cc commited: in elapsed_time {:?}",
        elapsed,
    );

    Ok(proof)
}
