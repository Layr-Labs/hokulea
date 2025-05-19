use alloy_primitives::Address;
use alloy_provider::RootProvider;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::{sol_data::Bool, SolType, SolValue};
use anyhow::Result;
use async_trait::async_trait;
use canoe_bindings::{IEigenDACertMockVerifier, Journal};
use canoe_provider::{CanoeInput, CanoeProvider};
use hokulea_proof::canoe_verifier::VERIFIER_ADDRESS;
use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::{Genesis, HostExecutor};
use sp1_sdk::{ProverClient, SP1Stdin};
use std::str::FromStr;
use std::time::Instant;
use tracing::info;
use url::Url;

/// The ELF we want to execute inside the zkVM.
pub const ELF: &[u8] = include_bytes!("../../elf/canoe-sp1-cc-client");

/// A canoe provider implementation with steel
#[derive(Debug, Clone)]
pub struct CanoeSp1CCProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCProvider {
    type Receipt = sp1_sdk::SP1ProofWithPublicValues;

    async fn create_cert_validity_proof(&self, canoe_input: CanoeInput) -> Result<Self::Receipt> {
        info!(
            "begin to generate a sp1-cc proof invoked at l1 bn {}",
            canoe_input.l1_head_block_number
        );
        let start = Instant::now();

        // Which block transactions are executed on.
        let block_number = BlockNumberOrTag::Number(canoe_input.l1_head_block_number);

        let rpc_url = Url::from_str(&self.eth_rpc_url).unwrap();

        let provider = RootProvider::new_http(rpc_url);

        let host_executor = match Genesis::try_from(canoe_input.l1_chain_id) {
            Ok(genesis) => HostExecutor::new_with_genesis(provider.clone(), block_number, genesis)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            // if genesis is not available in the sp1-cc library, the code uses the default Genesis, which currently in
            // sp1-cc is the mainnet. Ideally, Sp1-cc should make it easier to use the custom id genesis.
            Err(_) => HostExecutor::new(provider.clone(), block_number)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
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

        let returns_bytes = host_executor
            .execute(ContractInput::new_call(
                VERIFIER_ADDRESS,
                Address::default(),
                call.clone(),
            ))
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        // empricially if the function reverts, the output is empty, the guest code abort when evm revert takes place
        let returns = Bool::abi_decode(&returns_bytes).expect("deserialize returns_bytes");

        if returns != canoe_input.claimed_validity {
            panic!("in the host executor part, executor arrives to a different answer than the claimed answer. Something consistent in the view of eigenda-proxy and zkVM");
        }

        // Now that we've executed all of the calls, get the `EVMStateSketch` from the host executor.
        let evm_state_sketch = host_executor
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

    fn get_eth_rpc_url(&self) -> String {
        self.eth_rpc_url.clone()
    }
}
