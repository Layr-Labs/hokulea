# Canoe on Sepolia

Canoe-on-Sepolia is an example that generates and verifies a zk validity proof on sepolia. It serves to provide an easy entry for
the proof generation and verification of DA certificate validity when running on native host (not in zkvm).

## Certificate Characteristics
This example already includes an EigenDA v2 certificate in the data folder. This file is a valid v2 certificate attested by 
EigenDA Sepolia operators for the Sepolia contract 0x73818fed0743085c4557a736a7630447fb57c662, generated on June 2 at 16:33 PST.

After a certificate is issued, you can generate a valid Canoe proof for it at any later date (whether days or months afterward)
because EigenLayer records a snapshot of the EigenDA operator stakes on EVM state, and that historical state remains permanently accessible.

## Anchor Block of a zk validity proof

A zk validity proof requires an anchor block from L1 where the proof is based upon. See [steel](https://docs.beboundless.xyz/developers/steel/commitments#steels-trust-anchor-the-blockhash) and [sp1-contract-call](https://github.com/succinctlabs/sp1-contract-call/blob/8e1c03f360d791fb2a5b9b9a836a33cc3cfba9b7/crates/client-executor/src/anchor.rs#L23).

In hokulea, the anchor block takes the value of `l1_head` which is the same variable for starting a derivation in kona. It is assumed by the
canoe-hokulea integration that `l1_head` is a part of canonical L1 chain. For fault proof (OP interactive or zk fault proof), the `l1_head` is
recorded in EVM state when a game is created. For validity proof(zk) rollup, typically a history Ethereum blockhash is recorded to ensure `l1_head`
is a part of L1 canonical chain.

## Limitation

Currently, this example can only be run against Risc0 Steel.

## Run preloader

User must provide sepolia eth rpc url
```bash
cargo run --bin hokulea-example-canoe-on-sepolia -- --eth-rpc-url <eth-rpc-url>
```

