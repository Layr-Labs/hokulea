#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{sol_data::Bool, SolType, SolValue};
use canoe_bindings::{
    BatchHeaderV2, BlobInclusionInfo, IEigenDACertMockVerifier, Journal,
    NonSignerStakesAndSignature,
};
use sp1_cc_client_executor::{io::EVMStateSketch, ClientExecutor, ContractInput};

pub fn main() {
    // Read the state sketch from stdin. Use this during the execution in order to
    // access Ethereum state.
    let state_sketch_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let state_sketch = bincode::deserialize::<EVMStateSketch>(&state_sketch_bytes).unwrap();

    let verifier_address = sp1_zkvm::io::read::<Address>();
    let batch_header_abi = sp1_zkvm::io::read::<Vec<u8>>();
    let non_signer_stakes_and_signature_abi = sp1_zkvm::io::read::<Vec<u8>>();
    let blob_inclusion_info_abi = sp1_zkvm::io::read::<Vec<u8>>();
    let signed_quorum_numbers_abi = sp1_zkvm::io::read::<Vec<u8>>();

    // Initialize the client executor with the state sketch.
    // This step also validates all of the storage against state root provided by the host
    let executor = ClientExecutor::new(&state_sketch).unwrap();

    // Execute the slot0 call using the client executor.
    let batch_header = <BatchHeaderV2 as SolType>::abi_decode(&batch_header_abi)
        .expect("deserialize BatchHeaderV2");
    let blob_inclusion_info = <BlobInclusionInfo as SolType>::abi_decode(&blob_inclusion_info_abi)
        .expect("deserialize BlobInclusionInfo");
    let non_signer_stakes_and_signature =
        <NonSignerStakesAndSignature as SolType>::abi_decode(&non_signer_stakes_and_signature_abi)
            .expect("deserialize NonSignerStakesAndSignature");

    let signed_quorum_numbers = Bytes::abi_decode(&signed_quorum_numbers_abi)
        .expect("deserialize signed_quorum_numbers_abi");

    let mock_call = IEigenDACertMockVerifier::verifyDACertV2ForZKProofCall {
        batchHeader: batch_header,
        blobInclusionInfo: blob_inclusion_info.clone(),
        nonSignerStakesAndSignature: non_signer_stakes_and_signature,
        signedQuorumNumbers: signed_quorum_numbers,
    };

    let call = ContractInput::new_call(verifier_address, Address::default(), mock_call);
    let public_vals = executor.execute(call).unwrap();

    // empricially if the function reverts, the output is empty, the guest code abort when evm revert takes place
    let returns = Bool::abi_decode(&public_vals.contractOutput)
        .expect("deserialize NonSignerStakesAndSignature");

    let mut buffer = Vec::new();
    buffer.extend(batch_header_abi);
    buffer.extend(blob_inclusion_info_abi);
    buffer.extend(non_signer_stakes_and_signature_abi);
    buffer.extend(signed_quorum_numbers_abi);

    let journal = Journal {
        contractAddress: verifier_address,
        input: buffer.into(),
        blockhash: public_vals.blockHash,
        output: returns,
    };

    // Commit the abi-encoded output.
    // We can't use ContractPublicValues because sp1_cc_client_executor currently has deps issue.
    // Instead we define custom struct to commit
    sp1_zkvm::io::commit_slice(&journal.abi_encode());
}
