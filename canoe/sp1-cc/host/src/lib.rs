use alloy_primitives::{Address, B256};
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::{sol_data::Bool, SolType};
use anyhow::Result;
use async_trait::async_trait;
use canoe_bindings::{Journal, StatusCode};
use canoe_provider::{CanoeInput, CanoeProvider, CertVerifierCall};
use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::{EvmSketch, Genesis};
use sp1_sdk::{
    network::FulfillmentStrategy, Prover, ProverClient, SP1Proof, SP1ProofMode,
    SP1ProofWithPublicValues, SP1Stdin, SP1_CIRCUIT_VERSION,
};
use std::{
    env,
    str::FromStr,
    time::{Duration, Instant},
};
use tracing::{info, warn};
use url::Url;

use rsp_primitives::genesis::genesis_from_json;

/// The ELF we want to execute inside the zkVM.
pub const ELF: &[u8] = include_bytes!("../../elf/canoe-sp1-cc-client");

const DEFAULT_NETWORK_PRIVATE_KEY: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000001";
const SP1_CC_PROOF_STRATEGY_ENV: &str = "SP1_CC_PROOF_STRATEGY";

/// Get the fulfillment strategy from the environment variable
fn env_fulfillment_strategy(var_name: &str) -> FulfillmentStrategy {
    match env::var(var_name) {
        Ok(value) => {
            let value_lower = value.to_ascii_lowercase();
            match value_lower.as_str() {
                "hosted" => FulfillmentStrategy::Hosted,
                "reserved" => FulfillmentStrategy::Reserved,
                _ => {
                    warn!(
                        "Unknown `{}` value `{}`; defaulting to reserved fulfillment strategy",
                        var_name, value_lower
                    );
                    FulfillmentStrategy::Reserved
                }
            }
        }
        Err(_) => FulfillmentStrategy::Reserved,
    }
}

pub const KURTOSIS_DEVNET_GENESIS: &str = include_str!("./kurtosis_devnet_genesis.json");
pub const HOLESKY_GENESIS: &str = include_str!("./holesky_genesis.json");
/// A canoe provider implementation with Sp1 contract call
/// CanoeSp1CCProvider produces the receipt of type SP1ProofWithPublicValues,
/// SP1ProofWithPublicValues contains a Stark proof which can be verified in
/// native program using sp1-sdk. However, if you requires Stark verification
/// within zkVM, please use [CanoeSp1CCReducedProofProvider]
#[derive(Debug, Clone)]
pub struct CanoeSp1CCProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
    /// if true, execute and return a mock proof
    pub mock_mode: bool,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCProvider {
    type Receipt = sp1_sdk::SP1ProofWithPublicValues;

    async fn create_certs_validity_proof(
        &self,
        canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>> {
        // if there is nothing to prove against return early
        if canoe_inputs.is_empty() {
            return None;
        }

        Some(get_sp1_cc_proof(canoe_inputs, &self.eth_rpc_url, self.mock_mode).await)
    }

    fn get_config_hash(&self, receipt: &Self::Receipt) -> Option<B256> {
        let journals: Vec<Journal> = bincode::deserialize(receipt.public_values.as_slice())
            .expect("should be able to deserialize to journals");
        assert!(!journals.is_empty());
        let chain_config_hash = journals[0].chainConfigHash;
        for journal in journals {
            assert_eq!(chain_config_hash, journal.chainConfigHash);
        }
        Some(chain_config_hash)
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
    /// if true, execute and return a mock proof
    pub mock_mode: bool,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCReducedProofProvider {
    type Receipt = (
        sp1_core_executor::SP1ReduceProof<sp1_prover::InnerSC>,
        Vec<u8>,
    );

    async fn create_certs_validity_proof(
        &self,
        canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>> {
        // if there is nothing to prove against return early
        if canoe_inputs.is_empty() {
            return None;
        }

        match get_sp1_cc_proof(canoe_inputs, &self.eth_rpc_url, self.mock_mode).await {
            Ok(proof) => {
                let journals_bytes = proof.public_values.to_vec();
                let SP1Proof::Compressed(proof) = proof.proof else {
                    panic!("cannot get Sp1ReducedProof")
                };
                Some(Ok((*proof, journals_bytes)))
            }
            Err(e) => Some(Err(e)),
        }
    }

    fn get_config_hash(&self, receipt: &Self::Receipt) -> Option<B256> {
        let journals: Vec<Journal> = bincode::deserialize(receipt.1.as_slice())
            .expect("should be able to deserialize to journals");
        assert!(!journals.is_empty());
        let chain_config_hash = journals[0].chainConfigHash;
        // all chainConfigHash must be identical
        for journal in journals {
            assert_eq!(chain_config_hash, journal.chainConfigHash);
        }
        Some(chain_config_hash)
    }
}

async fn get_sp1_cc_proof(
    canoe_inputs: Vec<CanoeInput>,
    eth_rpc_url: &str,
    mock_mode: bool,
) -> Result<sp1_sdk::SP1ProofWithPublicValues> {
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
        // if genesis is not available in the sp1-cc library, the code uses custom genesis config
        Err(_) => {
            let chain_config = match l1_chain_id {
                17000 => genesis_from_json(HOLESKY_GENESIS).expect("genesis from json"),
                3151908 => genesis_from_json(KURTOSIS_DEVNET_GENESIS).expect("genesis from json"),
                _ => panic!("chain id {l1_chain_id} is not supported by canoe sp1 cc"),
            };

            let genesis = Genesis::Custom(chain_config.config);

            EvmSketch::builder()
                .at_block(block_number)
                .with_genesis(genesis)
                .el_rpc_url(rpc_url)
                .build()
                .await
                .expect("evm sketch builder")
        }
    };

    // pre populate the state
    for canoe_input in canoe_inputs.iter() {
        match CertVerifierCall::build(&canoe_input.altda_commitment) {
            CertVerifierCall::LegacyV2Interface(call) => {
                let contract_input =
                    ContractInput::new_call(canoe_input.verifier_address, Address::default(), call);
                let returns_bytes = sketch
                    .call_raw(&contract_input)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

                let is_valid = Bool::abi_decode(&returns_bytes).expect("deserialize returns_bytes");
                if is_valid != canoe_input.claimed_validity {
                    panic!("in the host executor part, executor arrives to a different answer than the claimed answer. Something inconsistent in the view of eigenda-proxy and zkVM");
                }
            }
            CertVerifierCall::ABIEncodeInterface(call) => {
                let contract_input =
                    ContractInput::new_call(canoe_input.verifier_address, Address::default(), call);
                let returns_bytes = sketch
                    .call_raw(&contract_input)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

                let returns = <StatusCode as SolType>::abi_decode(&returns_bytes)
                    .expect("deserialize returns_bytes");
                let is_valid = returns == StatusCode::SUCCESS;
                if is_valid != canoe_input.claimed_validity {
                    panic!("in the host executor part, executor arrives to a different answer than the claimed answer. Something inconsistent in the view of eigenda-proxy and zkVM");
                }
            }
        };
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

    // Create a `NetworkProver`.
    let network_private_key = env::var("NETWORK_PRIVATE_KEY").unwrap_or_else(|_| {
        warn!("NETWORK_PRIVATE_KEY is not set, using default network private key");
        DEFAULT_NETWORK_PRIVATE_KEY.to_string()
    });
    let client = ProverClient::builder()
        .network()
        .private_key(&network_private_key)
        .build();
    let (pk, _vk) = client.setup(ELF);

    let proof = if mock_mode {
        // Execute the program using the `ProverClient.execute` method, without generating a proof.
        let (public_values, report) = client
            .execute(ELF, &stdin)
            .run()
            .expect("sp1-cc should have executed the ELF");
        info!(
            "executed program in mock mode with {} cycles and {} prover gas",
            report.total_instruction_count(),
            report
                .gas
                .expect("gas calculation is enabled by default in the executor")
        );

        // Create a mock aggregation proof with the public values.
        SP1ProofWithPublicValues::create_mock_proof(
            &pk,
            public_values,
            SP1ProofMode::Compressed,
            SP1_CIRCUIT_VERSION,
        )
    } else {
        let sp1_cc_proof_strategy = env_fulfillment_strategy(SP1_CC_PROOF_STRATEGY_ENV);

        // Generate the proof for the given program and input.
        let proof = client
            .prove(&pk, &stdin)
            .compressed()
            .strategy(sp1_cc_proof_strategy)
            .skip_simulation(true)
            .cycle_limit(1_000_000_000_000)
            .gas_limit(1_000_000_000_000)
            .timeout(Duration::from_secs(4 * 60 * 60))
            .run()
            .expect("sp1-cc should have produced a compressed proof");

        info!("generated sp1-cc proof in non-mock mode");

        proof
    };

    let elapsed = start.elapsed();
    info!(
        action = "sp1_cc_proof_generation",
        status = "completed",
        "sp1-cc commited: in elapsed_time {:?}",
        elapsed,
    );
    Ok(proof)
}
