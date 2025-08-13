#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::Address;
use alloy_sol_types::{sol_data::Bool, SolType, SolValue};
use canoe_bindings::Journal;
use canoe_provider::{CanoeInput, CertVerifierCall};
use reth_chainspec::ChainSpec;
use sp1_cc_client_executor::{io::EvmSketchInput, ClientExecutor, ContractInput};

pub fn main() {
    // Read the state sketch from stdin. Use this during the execution in order to
    // access Ethereum state.
    let state_sketch_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let state_sketch = bincode::deserialize::<EvmSketchInput>(&state_sketch_bytes).unwrap();

    // read a list of canoe inputs and prove them all together in one sp1-cc proof
    let canoe_inputs = sp1_zkvm::io::read::<Vec<CanoeInput>>();

    // ensure all canoe_proof uses identical l1 chain id and l1 head block number
    assert!(!canoe_inputs.is_empty());
    let l1_chain_id = canoe_inputs[0].l1_chain_id;
    let l1_head_block_number = canoe_inputs[0].l1_head_block_number;
    let l1_head_block_hash = canoe_inputs[0].l1_head_block_hash;
    // require all canoe input share a common l1_chain_id
    for canoe_input in canoe_inputs.iter() {
        assert!(canoe_input.l1_chain_id == l1_chain_id);
        assert!(canoe_input.l1_head_block_number == l1_head_block_number);
        assert!(canoe_input.l1_head_block_hash == l1_head_block_hash);
    }

    // Initialize the client executor with the state sketch.
    // This step also validates all of the storage against state root provided by the host
    let executor = ClientExecutor::new(&state_sketch).unwrap();

    let chain_sepc: ChainSpec = executor
        .genesis
        .try_into()
        .expect("convert sp1 genesis into chain spec");

    // Those journals are concatenated in a serialized byte array which can be committed
    // by the zkVM. The hokulea program independently reproduce the serialized journals, and verify
    // if zkVM has produced the proof for the exact serialized journals.
    // Those bytes are never expected to be deserialized.
    let mut journals: Vec<u8> = vec![];
    // executes all calls, then combines and commits all journals
    for canoe_input in canoe_inputs.iter() {
        // TODO, are there no better way to reduce this duplicate code.
        // known constraint, new_call takes SolCall trait, which is Sized so not dyn trait
        // also impl SolCall seems too much
        // V2 will be deprecated once router is released and no user depends on it, will remove V2 call then
        let call = match CertVerifierCall::build(&canoe_input.altda_commitment) {
            CertVerifierCall::V2(call) => {
                ContractInput::new_call(canoe_input.verifier_address, Address::default(), call)
            }
            CertVerifierCall::Router(call) => {
                ContractInput::new_call(canoe_input.verifier_address, Address::default(), call)
            }
        };

        let public_vals = executor.execute(call).unwrap();

        // empricially if the function reverts, the output is empty, the guest code abort when evm revert takes place
        let returns = Bool::abi_decode(&public_vals.contractOutput).expect("deserialize returns");

        // TODO might be using a better serialization format
        let rlp_bytes = canoe_input.altda_commitment.to_rlp_bytes();

        assert!(public_vals.anchorHash == l1_head_block_hash);

        let journal = Journal {
            certVerifierAddress: canoe_input.verifier_address,
            input: rlp_bytes.into(),
            blockhash: public_vals.anchorHash,
            output: returns,
            l1ChainId: chain_sepc.chain.id(),
        };
        journals.extend(journal.abi_encode());
    }

    // Commit journals altogether
    sp1_zkvm::io::commit_slice(&journals);
}
