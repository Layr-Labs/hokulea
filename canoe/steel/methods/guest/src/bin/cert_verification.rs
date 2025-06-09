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

use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use risc0_steel::{
    ethereum::{EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC, ETH_HOLESKY_CHAIN_SPEC, ETH_MAINNET_CHAIN_SPEC},    
    Contract,
};
use risc0_zkvm::guest::env;
use canoe_bindings::{
    Journal, StatusCode
};
use canoe_provider::{CanoeInput, CertVerifierCall};

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read the input from the guest environment.
    let input: EthEvmInput = env::read();
    let verifier_address: Address = env::read();
    let canoe_input: CanoeInput = env::read();
    let l1_chain_id = canoe_input.l1_chain_id;
    
    // Converts the input into a `EvmEnv` for execution. The `with_chain_spec` method is used
    // to specify the chain configuration. It checks that the state matches the state root in the
    // header provided in the input.
    let env = match l1_chain_id {
        1 => input.into_env().with_chain_spec(&ETH_MAINNET_CHAIN_SPEC),
        11155111 => input.into_env().with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC),
        17000 => input.into_env().with_chain_spec(&ETH_HOLESKY_CHAIN_SPEC),
        _ => input.into_env(),
    }; 

    // Prepare the function call and call the function
    let returns = match CertVerifierCall::build(&canoe_input.altda_commitment) {
        CertVerifierCall::V2(call) => Contract::new(verifier_address, &env).call_builder(&call).call(),
        CertVerifierCall::Router(call) => {
            let status = Contract::new(verifier_address, &env).call_builder(&call).call();
            status == StatusCode::SUCCESS as u8
        }
    };

    let rlp_bytes = canoe_input.altda_commitment.to_rlp_bytes();

    // Commit the block hash and number used when deriving `view_call_env` to the journal.
    let journal = Journal {
        certVerifierAddress: verifier_address,
        input: rlp_bytes.into(),
        blockhash: env.header().seal(),
        output: returns,
        l1ChainId: l1_chain_id,
    };
    env::commit_slice(&journal.abi_encode());
}
