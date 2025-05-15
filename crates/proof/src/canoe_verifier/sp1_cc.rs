use crate::canoe_verifier::{CanoeVerifier, VERIFIER_ADDRESS};
use crate::cert_validity::CertValidity;

use eigenda_v2_struct::EigenDAV2Cert;
use sp1_sdk::SP1ProofWithPublicValues;

use alloc::vec::Vec;
use alloy_primitives::B256;
use alloy_sol_types::SolValue;
use canoe_bindings::Journal;

use tracing::info;

// ToDo(bx) how to automtically update it from ELF directly as oppose to hard code it
// To get vKey of ELF
// cargo prove vkey --elf target/elf-compilation/riscv32im-succinct-zkvm-elf/release/canoe-sp1-cc-client
pub const VKEYHEXSTRING: &str = "0039b09c4f5cfc58ca7cbabd5eb5997de2cfdfa336a5ced1b640084c165718fa";
pub const ELF: &[u8] = include_bytes!("../../../../canoe/sp1-cc/elf/canoe-sp1-cc-client");

#[derive(Clone)]
pub struct CanoeSp1CCVerifier {}

impl CanoeVerifier for CanoeSp1CCVerifier {
    fn validate_cert_receipt(&self, cert_validity: CertValidity, eigenda_cert: EigenDAV2Cert) {
        info!("using CanoeSp1CCVerifier");
        // if not in dev mode, the receipt must be non empty
        let receipt_bytes = cert_validity.canoe_proof.as_ref();

        // Because we have the sp1-cc dependancy issue, we cannot deserialize the bytes into SContractPublicValues
        // So instead we define custom struct Journal and compare opaque bytes array to ensure inputs are identical
        let canoe_receipt: SP1ProofWithPublicValues =
            serde_json::from_slice(receipt_bytes).expect("serde error");

        cfg_if::cfg_if! {
            if #[cfg(target_os = "zkvm")] {
                use sha2::{Digest, Sha256};
                use sp1_lib::verify::verify_sp1_proof;

                // used within zkVM
                let public_values_digest = Sha256::digest(canoe_receipt.public_values.clone());
                let v_key_b256 = B256::from_str(VKEYHEXSTRING).expect("Invalid hex string");
                let v_key = b256_to_u32_array(v_key_b256);
                verify_sp1_proof(&v_key, &public_values_digest.into());
            } else {
                // in host mode
                use sp1_sdk::ProverClient;
                let client = ProverClient::from_env();
                let (_, vk) = client.setup(ELF);
                client.verify(&canoe_receipt, &vk).expect("verification failed");
            }
        }

        let public_values_vec = canoe_receipt.public_values.to_vec();

        let batch_header = eigenda_cert.batch_header_v2.to_sol().abi_encode();
        let blob_inclusion_info = eigenda_cert.blob_inclusion_info.to_sol().abi_encode();
        let non_signer_stakes_and_signature = eigenda_cert
            .nonsigner_stake_and_signature
            .to_sol()
            .abi_encode();
        let signed_quorum_numbers_abi = eigenda_cert.signed_quorum_numbers.abi_encode();

        // ensure inputs are constrained
        let mut buffer = Vec::new();
        buffer.extend(batch_header);
        buffer.extend(blob_inclusion_info);
        buffer.extend(non_signer_stakes_and_signature);
        buffer.extend(signed_quorum_numbers_abi);

        let journal = Journal {
            contractAddress: VERIFIER_ADDRESS,
            input: buffer.into(),
            blockhash: cert_validity.l1_head_block_hash,
            output: cert_validity.claimed_validity,
        };
        let journal_bytes = journal.abi_encode();
        assert!(journal_bytes == public_values_vec);
    }
}

pub fn b256_to_u32_array(b: B256) -> [u32; 8] {
    let bytes: [u8; 32] = b.into();

    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        let start = i * 4;
        // sp1 zkvm is little endian
        out[i] = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        i += 1;
    }
    out
}
