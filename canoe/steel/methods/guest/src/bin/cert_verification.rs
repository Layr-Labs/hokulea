// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(unused_doc_comments)]
#![no_main]

extern crate alloc;

use alloc::string::ToString;

use risc0_steel::{
    ethereum::{EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC, ETH_HOLESKY_CHAIN_SPEC, ETH_MAINNET_CHAIN_SPEC},    
    Contract,
};
use risc0_steel::ethereum::EthChainSpec;
use risc0_zkvm::guest::env;
use canoe_bindings::{
    Journal, StatusCode
};
use canoe_provider::{CanoeInput, CertVerifierCall};
use alloy_primitives::{keccak256, B256};

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read the input from the guest environment.
    let input: EthEvmInput = env::read();
    let canoe_inputs: Vec<CanoeInput> = env::read();

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
    
    // Converts the input into a `EvmEnv` for execution. The `with_chain_spec` method is used
    // to specify the chain configuration. It checks that the state matches the state root in the
    // header provided in the input.
    let env = match l1_chain_id {
        1 => input.into_env(&ETH_MAINNET_CHAIN_SPEC),
        11155111 => input.into_env(&ETH_SEPOLIA_CHAIN_SPEC),
        17000 => input.into_env(&ETH_HOLESKY_CHAIN_SPEC),
        3151908 => input.into_env(&EthChainSpec::new_single(l1_chain_id, Default::default())),
        _ => panic!("unsupported chain id by canoe steel"),
    };

    // current release of steel does not expose active_fork function, but it is already included in the latest
    // commit. (ToDo) once release is updated, call the function on env
    let active_fork_string = match l1_chain_id {
        1 => ETH_MAINNET_CHAIN_SPEC.active_fork(l1_head_block_number, env.header().timestamp).expect("should be able to get active fork on mainnet with steel").to_string(),
        11155111 => ETH_SEPOLIA_CHAIN_SPEC.active_fork(l1_head_block_number, env.header().timestamp).expect("should be able to get active fork on sepolia with steel").to_string(),
        17000 => ETH_HOLESKY_CHAIN_SPEC.active_fork(l1_head_block_number, env.header().timestamp).expect("should be able to get active fork on holesky with steel").to_string(),
        3151908 => EthChainSpec::new_single(l1_chain_id, Default::default()).active_fork(l1_head_block_number, env.header().timestamp).expect("should be able to get active fork on kurtosis with steel").to_string(),
        _ => panic!("unsupported chain id by canoe steel"),
    };

    let chain_config_hash = keccak256(active_fork_string);

    assert_eq!(l1_head_block_number, env.header().number);
    // Those journals are pushed into a vector and later serialized in a byte array which can be committed
    // by the zkVM. To verify if zkVM has produced the proof for the exact serialized journals, canoe verifier
    // verifies the zkVM proof against the commited journals.
    let mut journals: Vec<Journal> = vec![];
    for canoe_input in canoe_inputs.iter() {
        // Prepare the function call and call the function
        let is_valid = match CertVerifierCall::build(&canoe_input.altda_commitment) {
            CertVerifierCall::LegacyV2Interface(call) => Contract::new(canoe_input.verifier_address, &env).call_builder(&call).call(),
            CertVerifierCall::ABIEncodeInterface(call) => {
                let status = Contract::new(canoe_input.verifier_address, &env).call_builder(&call).call();
                status == StatusCode::SUCCESS as u8
            }
        };

        let rlp_bytes = canoe_input.altda_commitment.to_rlp_bytes();

        assert!(env.header().seal() == l1_head_block_hash);

        // check the claimed validity equals to the evaluation result from steel
        assert!(canoe_input.claimed_validity == is_valid);

        // Commit the block hash and number used when deriving `view_call_env` to the journal.
        let journal = Journal {
            blockNumber: l1_head_block_number,
            certVerifierAddress: canoe_input.verifier_address,
            input: rlp_bytes.into(),
            blockhash: l1_head_block_hash,
            output: is_valid,
            l1ChainId: l1_chain_id,
            chainConfigHash: chain_config_hash,
            chainSpecHash:  B256::default(), // steel does not have the problem to pin chain Config
        };
        journals.push(journal);
    }

    let journals_bytes = bincode::serialize(&journals).expect("should be able to serialize");
    env::commit_slice(&journals_bytes);
}
