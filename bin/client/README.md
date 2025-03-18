# `hokulea-client-bin`

This binary contains the client program for executing the Optimism rollup state transition that contains eigenda logics.

Two types of clients can be called
1. run_direct_client - kona-client with eigenda
2. run_preloaded_eigenda_client - kona-client with eigenda but returns (cert, eigenda blob) as witness

## usage pattern of preloaded_eigenda_client
run_preloaded_eigenda_client requires running witgen-client. It run in two steps
1. use witgen-client to record all (eigenda cert and blob)
2. populate the witness for all (eigenda cert and blob) with kzg library and zk view proof proving the cert itself is valid (the view call returns true). They are captured in the EigenDABlobWitnessData. This is run in the preparation phase. The resulting proof will be supplied to the final run that shows the entire derivation is correct.
