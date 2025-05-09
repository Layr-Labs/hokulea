*Securing the EigenDA → Ethereum (L1) Blob Bridge*

## 1 · Protocol Overview  

**Canoe** is a module that proves—on Ethereum—that a given EigenDA blob has been attested by **sufficient stake across every quorum** of EigenDA operators.

| Part | Role |
|-------|------|
| **Solidity Verifier** | Confirms that the total attested stake for *each* quorum meets or exceeds the required threshold. |
| **Off‑chain Validity‑Proof Generator** | Invokes the Solidity verifier off‑chain and produces a zk‑proof attesting to its output. |
| **On‑chain zk‑Proof Verifier** | Checks the zk‑proof and the metadata contained in the EigenDA certificate. |

Canoe is under active development and currently supports two zkVM back‑ends: [RISC Zero Steel](https://risczero.com/steel) and [Succinct SP1 Contract Call](https://github.com/succinctlabs/sp1-contract-call).


## 2 · EigenDA V2 (“Blazar”) Upgrade  

In EigenDA V2 the certificate (DA cert) is returned to the requester immediately after quorum attestation; the disperser no longer verifies it on L1. It bears the question, how to securely bridge a blob to L1


## 3 · Implementation Details  

### 3.1 Solidity Verifier
Building on the V1 contract, the [certificate verifier](https://github.com/Layr-Labs/eigenda/blob/ee092f345dfbc37fce3c02f99a756ff446c5864a/contracts/src/periphery/cert/v2/EigenDACertVerifierV2.sol#L120) now replaces Merkle‑root checks with **BLS aggregate‑signature verification** across all quorums. But its gas cost scales linearly with the number of non‑signers. We can model the smart contract logic as

$$ f(S, C) -> O $$

| Symbol | Meaning |
|--------|---------|
| `f` | Contract logic |
| `S` | Ethereum state at a specific block (hash & number) |
| `C` | Call data (= EigenDA certificate) |
| `O` | Boolean validity result |

### 3.2 Validity‑Proof Generation (Off‑chain)  

1. An off‑chain prover reconstructs Ethereum state `S` at some block height `h_i`.  
2. It invokes `f` with certificate `C` and records output `O`.  
3. A zkVM produces proof `P` attesting that the tuple `(f,S,C,O)` is correct.

### Verifying the validity proof on L1
The proof `P` is verified by a **universal zkVM verifier** already deployed on L1 (Risc0 or SP1).


### 4.1 Blob Validity Inside a zkVM (Hokulea)  

The **Hokulea** rollup client runs inside a zkVM. During blob derivation it must:

1. Receive proof `P` for every EigenDA certificate processed.  
2. Reconstruct `(f,s,C,O)` locally (where `s` commits to state `S`).  
3. Abort if `P` fails; otherwise continue derivation.  

Hokulea then emits its own zk‑proof, which can be posted to L1 to attest that:

* All derived blobs are correct, and  
* Malicious certificates were discarded.

## Usage Case 2 - blob validity check on L1

Another way to use Canoe is to verify the certificate validity proof on L1 directly. L1 must be able to construct $(f, s, C, O)$ or its equivalent. For instance, if we were to convert a L1 inbox to a smart contract. Let $f$ be the verifier contract, $C$ be eigenda certificate to be queued into the deriviation pipeline, $O$ be true. We need to ensure $s$ is at some block number higher than the L1 block number whose stake is used to disperse the EigenDA blob. It is achieved by checking the reference block number within the eigenda certificate is smaller than the block number with block hash $s$.### 4.2 Direct L1 Certificate Verification  

Protocols can also verify `P` **directly on Ethereum**:

* `f`: the on‑chain verifier contract.  
* `C`: the EigenDA certificate to enqueue.  
* `O = true`.  
* `s`: a block *after* the stake snapshot referenced in `C` (enforced by checking the certificate’s reference block number).

This allows L1 contracts to trust EigenDA blobs without verifying the BLS aggregated signature onchain.