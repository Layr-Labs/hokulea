# Canoe

Securing EigenDA blob bridge to L1 

## Protocol Description

Canoe is a module that securely prove to Ethereum that some EigenDA blobs has been attested by sufficient stake by EigenDA operators across all quorum. 

Canoe is made of three parts:
- a solidity implementation that verifies the amount of attested stake is equal or higher than required stake threshold for all quorum
- an offchain validity (zk) proof generation part that calls the solidity logic above, and produce a zkp attesting the output of calling the solidity function
- an onchain verification part that verifies the zkp and information within the eigenda certificate

Canoe undergoes active development, currently support two backends with [Risc0 Steel](https://risczero.com/steel) and [Succinct Sp1 contract call](https://github.com/succinctlabs/sp1-contract-call)

## EigenDA V2 (Blazar) Upgrade

One of the most notable change is that EigenDA cert is immediately sent back to the blob requester once it is attested by sufficiently stake. This is possible because the EigenDA disperser no longer takes the responsibility of verifying the DA cert on L1. This bears the question, how to securely bridge a blob to L1


## Implementation

### Solidity implementation
Improving upon V1 solidity contract, we develop V2 [certificate verifier](https://github.com/Layr-Labs/eigenda/blob/ee092f345dfbc37fce3c02f99a756ff446c5864a/contracts/src/periphery/cert/v2/EigenDACertVerifierV2.sol#L120) certificate verifier. Contrast to the cert verifier V1 that verifies against a merkle root, the V2 verifier does the bls aggregate signature verification for all quorums. The cost is linearly scaling with the number of non-signers. We can model the function as 

$$ f(S, C) -> O $$

where $f$ is the computation logic implemented by the smart contract, $S$ is the state when the call is made (the state is captured by a block hash with a block number) and $C$ is the calldate (i.e. eigenda certificate). $O$ is a boolean output.

### Validity proof generation
Instead of verifying the bls aggregate signature onchain, an offchain prover created the Ethereum state at some block height $h_i$ that contains all relevant state information pertinant to the smart contract that implementing $f$. And at last the the contract is invoked with input $C$ which is derived from the eigenDA cert, and the output of the call is a boolean signifying if the cert has meet all the requirements set by the computation logic $f$, which checks if there are sufficient stakes for all quorums. Because EVM computation can be proven by zkVM, a zkp $P$ can be generated to prove to Ethereum that $(f, S, C, O)$ is valid.

### Verifying the validity proof on L1
The zkp produced by a zkVM can be verified by its corresponding zkVM verifier onChain. Such verifier is universal in the sense, that all proof can be verified against one verifier. Practically, we offer two implementation of Canoe by Steel (Risc0) and Sp1-contract-call (Succinct); both company deployed the universal verifier on L1 already. Depending on the use case, additional information might be verified on L1. 


## Usage Case 1 - blob validity check within zkVM for hokulea
The Hokulea client itself needs to be run inside a zkVM, such that a zk validity proof implies that the derivation pipeline has safely derive the actual EigenDA blobs based on EigenDA certificate queued on L1 inbox. A crucial step from the EigenDA blob derivation is to filter out EigenDA certificates that are invalid incase they are submitted by malicious op-batcher plotting to steal assets in the withdrawal bridge.

To prevent it from happening, the hokulea client needs to verify the validity proof for all the certificates encountered during the derivation. In practice, a host uses the $f$ determined by the protocol, $C$ be the eigenda cert and $O$ be the expected output. The L1 state $S$ is chosen to be the l1_head typically when L2 output root is posted on L1. Because EigenLayer checkpointed the aggregated operator stake whenever there is an update. The latest block height has the entire history of the total BLS aggregated public key in the past.

Once the proof $P$ is generated, it is sent to the hokulea client, which construct $(f, s, C, O)$ locally, where $s$ is block hash and is a commitment of $S$. The hokulea client verifies against $P$ and aborts otherwise (in which case, no zkp can be generated).

The hokulea client itself is run inside a zkVM, which produces the proof that verifies the validity proof. The hokulea client proof can be submitted to L1 to show the all derivation of eigenda blobs are correct and incorrect eigenda certificates are discarded. 

## Usage Case 2 - blob validity check on L1

Another way to use Canoe is to verify the certificate validity proof on L1 directly. L1 must be able to construct $(f, s, C, O)$ or its equivalent. For instance, if we were to convert a L1 inbox to a smart contract. Let $f$ be the verifier contract, $C$ be eigenda certificate to be queued into the deriviation pipeline, $O$ be true. We need to ensure $s$ is at some block number higher than the L1 block number whose stake is used to disperse the EigenDA blob. It is achieved by checking the reference block number within the eigenda certificate is smaller than the block number with block hash $s$.