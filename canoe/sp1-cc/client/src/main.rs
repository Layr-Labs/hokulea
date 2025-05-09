#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use sp1_cc_client_executor::{io::EVMStateSketch, ClientExecutor, ContractInput};
use canoe_bindings::{
    Journal, BatchHeaderV2, BlobInclusionInfo, NonSignerStakesAndSignature, IEigenDACertMockVerifier,
};

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
    // This step also validates all of the storage against the provided state root.
    let executor = ClientExecutor::new(&state_sketch).unwrap();

    // Execute the slot0 call using the client executor.
    let batch_header = BatchHeaderV2::abi_decode(&batch_header_abi).expect("deserialize BatchHeaderV2");
    let blob_inclusion_info = BlobInclusionInfo::abi_decode(&blob_inclusion_info_abi).expect("deserialize BlobInclusionInfo");
    let non_signer_stakes_and_signature = NonSignerStakesAndSignature::abi_decode(&non_signer_stakes_and_signature_abi).expect("deserialize NonSignerStakesAndSignature");    

    let mock_call = IEigenDACertMockVerifier::verifyDACertV2ForZKProofCall {        
        batchHeader: batch_header,
        blobInclusionInfo: blob_inclusion_info.clone(),
        nonSignerStakesAndSignature: non_signer_stakes_and_signature,
        signedQuorumNumbers: signed_quorum_numbers_abi.clone().into(),
    };

    let call = ContractInput::new_call(verifier_address, Address::default(), mock_call);
    let public_vals = executor.execute(call).unwrap();
    let output = public_vals.contractOutput.to_vec();    

    let mut buffer = Vec::new();
    buffer.extend(batch_header_abi);
    buffer.extend(blob_inclusion_info_abi);
    buffer.extend(non_signer_stakes_and_signature_abi);
    buffer.extend(signed_quorum_numbers_abi);

    // TODO(bx) check if this is true
    //let returns = match output[0] {
    //    0 => true,
    //    _ => false,
    //};

    //let journal = Journal {
    //    contractAddress: verifier_address,
    //    input: buffer.into(),
    //    blockhash: public_vals.blockHash,
    //    output: public_vals.contractOutput.is_empty(),
    //    test: public_vals.contractOutput.to_ascii_lowercase().into(),
    //};

    // Commit the abi-encoded output.
    // We can't use ContractPublicValues because sp1_cc_client_executor currently has deps issue.
    // Instead we define custom struct to commit
    //sp1_zkvm::io::commit_slice(&journal.abi_encode());
    sp1_zkvm::io::commit_slice(&public_vals.abi_encode());
}