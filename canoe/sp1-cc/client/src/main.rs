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

    let verifier_address = sp1_zkvm::io::read::<Address>();
    let canoe_input = sp1_zkvm::io::read::<CanoeInput>();

    // Initialize the client executor with the state sketch.
    // This step also validates all of the storage against state root provided by the host
    let executor = ClientExecutor::new(&state_sketch).unwrap();

    // TODO, are there no better way to reduce this duplicate code.
    // known constraint, new_call takes SolCall trait, which is Sized so not dyn trait
    // also impl SolCall seems too much
    // V2 will be deprecated once router is released, will remove V2 call then
    let call = match CertVerifierCall::build(&canoe_input.altda_commitment) {
        CertVerifierCall::V2(call) => {
            ContractInput::new_call(verifier_address, Address::default(), call)
        }
        CertVerifierCall::Router(call) => {
            ContractInput::new_call(verifier_address, Address::default(), call)
        }
    };

    let public_vals = executor.execute(call).unwrap();

    // empricially if the function reverts, the output is empty, the guest code abort when evm revert takes place
    let returns = Bool::abi_decode(&public_vals.contractOutput).expect("deserialize returns");

    let rlp_bytes = canoe_input.altda_commitment.to_rlp_bytes();

    let chain_sepc: ChainSpec = executor
        .genesis
        .try_into()
        .expect("convert sp1 genesis into chain spec");

    let journal = Journal {
        certVerifierAddress: verifier_address,
        input: rlp_bytes.into(),
        blockhash: public_vals.anchorHash,
        output: returns,
        l1ChainId: chain_sepc.chain.id(),
    };

    // Commit the abi-encoded output.
    sp1_zkvm::io::commit_slice(&journal.abi_encode());
}
