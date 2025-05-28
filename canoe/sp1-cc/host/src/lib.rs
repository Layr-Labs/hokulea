use alloy_primitives::Address;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::{sol_data::Bool, SolType, SolValue};
use anyhow::Result;
use async_trait::async_trait;
use canoe_bindings::{IEigenDACertMockVerifier, Journal};
use canoe_provider::{CanoeInput, CanoeProvider};
use hokulea_proof::canoe_verifier::VERIFIER_ADDRESS;
use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::{EvmSketch, Genesis};
use sp1_sdk::{ProverClient, SP1Proof, SP1Stdin};
use std::str::FromStr;
use std::time::Instant;
use tracing::info;
use url::Url;

/// The ELF we want to execute inside the zkVM.
pub const ELF: &[u8] = include_bytes!("../../elf/canoe-sp1-cc-client");

/// A canoe provider implementation with Sp1 contract call
#[derive(Debug, Clone)]
pub struct CanoeSp1CCProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCProvider {
    type Receipt = sp1_sdk::SP1ProofWithPublicValues;

    async fn create_cert_validity_proof(&self, canoe_input: CanoeInput) -> Result<Self::Receipt> {
        get_sp1_cc_proof(canoe_input, &self.eth_rpc_url).await
    }

    fn get_eth_rpc_url(&self) -> String {
        self.eth_rpc_url.clone()
    }
}

/// A canoe provider implementation with Sp1 contract call
/// The receipt only contains the proof part from CanoeSp1CCReducedProofProvider
/// which can be verified within zkVM
#[derive(Debug, Clone)]
pub struct CanoeSp1CCReducedProofProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCReducedProofProvider {
    type Receipt = sp1_core_executor::SP1ReduceProof<sp1_prover::InnerSC>;

    async fn create_cert_validity_proof(&self, canoe_input: CanoeInput) -> Result<Self::Receipt> {
        let proof = get_sp1_cc_proof(canoe_input, &self.eth_rpc_url).await?;
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
    canoe_input: CanoeInput,
    eth_rpc_url: &str,
) -> Result<sp1_sdk::SP1ProofWithPublicValues> {
    info!(
        "begin to generate a sp1-cc proof invoked at l1 bn {}",
        canoe_input.l1_head_block_number
    );
    let start = Instant::now();

    // Which block VerifyDACert eth-calls are executed against.
    let block_number = BlockNumberOrTag::Number(canoe_input.l1_head_block_number);

    let rpc_url = Url::from_str(eth_rpc_url).unwrap();

    let sketch = match Genesis::try_from(canoe_input.l1_chain_id) {
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
            EvmSketch::builder()
                .at_block(block_number)
                .el_rpc_url(rpc_url)
                .build()
                .await?
        }
    };
    // Keep track of the block hash. Later, validate the client's execution against this.
    // let block_hash = host_executor.header.hash_slow();

    // Make the call
    let call = IEigenDACertMockVerifier::verifyDACertV2ForZKProofCall {
        batchHeader: canoe_input.eigenda_cert.batch_header_v2.to_sol(),
        blobInclusionInfo: canoe_input
            .eigenda_cert
            .blob_inclusion_info
            .clone()
            .to_sol(),
        nonSignerStakesAndSignature: canoe_input
            .eigenda_cert
            .nonsigner_stake_and_signature
            .to_sol(),
        signedQuorumNumbers: canoe_input.eigenda_cert.signed_quorum_numbers,
    };

    let returns_bytes = sketch
        .call(ContractInput::new_call(
            VERIFIER_ADDRESS,
            Address::default(),
            call.clone(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Empirically if the function reverts, the output is empty. OTOH, the guest code aborts when an evm revert takes place.
    let returns = Bool::abi_decode(&returns_bytes).expect("deserialize returns_bytes");

    if returns != canoe_input.claimed_validity {
        panic!("in the host executor part, executor arrives to a different answer than the claimed answer. Something inconsistent in the view of eigenda-proxy and zkVM");
    }

    // Now that we've executed all of the calls, get the `EVMStateSketch` from the host executor.
    let evm_state_sketch = sketch
        .finalize()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let batch_header_abi = call.batchHeader.abi_encode();
    let non_signer_abi = call.nonSignerStakesAndSignature.abi_encode();
    let blob_inclusion_abi = call.blobInclusionInfo.abi_encode();
    let signed_quorum_numbers = call.signedQuorumNumbers.abi_encode();

    // Feed the sketch into the client.
    let input_bytes = bincode::serialize(&evm_state_sketch)?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes);
    stdin.write(&VERIFIER_ADDRESS);
    stdin.write(&batch_header_abi);
    stdin.write(&non_signer_abi);
    stdin.write(&blob_inclusion_abi);
    stdin.write(&signed_quorum_numbers);

    // Create a `ProverClient`.
    let client = ProverClient::from_env();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    info!(
        "executed program with {} cycles",
        report.total_instruction_count()
    );

    // Generate the proof for the given program and input.
    let (pk, _vk) = client.setup(ELF);
    let proof = client.prove(&pk, &stdin).compressed().run().unwrap();

    let journal = <Journal as SolType>::abi_decode(proof.public_values.as_slice())
        .expect("deserialize journal");

    info!(
        "sp1-cc commited: blockHash {:?} contractOutput {:?}, chainID {:?}",
        journal.blockhash, journal.output, journal.l1ChainId,
    );

    let elapsed = start.elapsed();
    info!(action = "sp1_cc_proof_generation", status = "completed", elapsed_time = ?elapsed);

    Ok(proof)
}
