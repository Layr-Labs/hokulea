use alloy_provider::RootProvider;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::SolValue;
use sp1_cc_host_executor::HostExecutor;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use url::Url;
use async_trait::async_trait;
use eigenda_v2_struct;
use canoe_provider::CanoeProvider;
use anyhow::Result;
use hokulea_proof::{canoe_verifier::VERIFIER_ADDRESS, cert_validity::CertValidity};
use std::str::FromStr;
use std::time::Instant;
use tracing::info;
use canoe_bindings::IEigenDACertMockVerifier;

/// The ELF we want to execute inside the zkVM.
pub const ELF: &[u8] = include_elf!("canoe-sp1-cc-client");

// To get vKey of ELF above
// cargo prove vkey --elf target/elf-compilation/riscv32im-succinct-zkvm-elf/release/canoe-sp1-cc-client

/// A canoe provider implementation with steel
#[derive(Debug, Clone)]
pub struct CanoeSp1CCProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: String,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCProvider {
    type Receipt = sp1_sdk::SP1ProofWithPublicValues;

    async fn create_cert_validity_proof(
        &self,
        eigenda_cert: eigenda_v2_struct::EigenDAV2Cert,
        cert_validity: CertValidity,
    ) -> Result<Self::Receipt> {
        info!(
            "begin to generate a sp1-cc proof invoked at l1 bn {}",
            cert_validity.l1_head_block_number
        );
        let start = Instant::now();

        // Which block transactions are executed on.
        let block_number = BlockNumberOrTag::Number(cert_validity.l1_head_block_number);
        
        let rpc_url = Url::from_str(&self.eth_rpc_url).unwrap();

        let provider = RootProvider::new_http(rpc_url);
        let host_executor = HostExecutor::new(provider.clone(), block_number).await.map_err(|e| anyhow::anyhow!(e.to_string()))?;

        // Keep track of the block hash. Later, validate the client's execution against this.
        // let block_hash = host_executor.header.hash_slow();

        // Make the call
        let call = IEigenDACertMockVerifier::verifyDACertV2ForZKProofCall {
            batchHeader: eigenda_cert.batch_header_v2.to_sol(),
            blobInclusionInfo: eigenda_cert.blob_inclusion_info.clone().to_sol(),
            nonSignerStakesAndSignature: eigenda_cert.nonsigner_stake_and_signature.to_sol(),
            signedQuorumNumbers: eigenda_cert.signed_quorum_numbers,
        };
        // Now that we've executed all of the calls, get the `EVMStateSketch` from the host executor.
        let input = host_executor.finalize().await.map_err(|e| anyhow::anyhow!(e.to_string())).map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let batch_header_abi = call.batchHeader.abi_encode();
        let non_signer_abi = call.nonSignerStakesAndSignature.abi_encode();
        let blob_inclusion_abi = call.blobInclusionInfo.abi_encode();
        let signed_quorum_numbers = call.signedQuorumNumbers.abi_encode();

        // Feed the sketch into the client.
        let input_bytes = bincode::serialize(&input)?;
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
        println!("executed program with {} cycles", report.total_instruction_count());

        // Generate the proof for the given program and input.
        let (pk, _vk) = client.setup(ELF);
        let proof = client.prove(&pk, &stdin).plonk().run().unwrap();

        let elapsed = start.elapsed();
        info!("finish a sp1-cc proof generation spent {:?}", elapsed);
        
        Ok(proof)
    }

    fn get_eth_rpc_url(&self) -> String {
        self.eth_rpc_url.clone()
    }
}