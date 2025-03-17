# `hokulea-client`

hokulea-client provides building blocks for higher levels clients.

The building blocks contains
- core-client: just basic kona-client with eigenda
- witgen-client: run basic 1. kona-client with eigenda, 2. returns EigenDABlobWitnessData which can be used to prepare proofs for the correctness. This is usually run in the preparation phase. The resulting proof will be supplied to the final run that shows the entire derivation is correct.

## usage pattern
For ZK fault proof,
1. use witgen-client to record all (eigenda cert and blob)
2. populate the witness for all (eigenda cert and blob) with kzg library and zk view proof proving the cert itself is valid (the view call returns true)
3. supply the witness to the preimage oracle