# Canoe

*Securing the EigenDA → Ethereum (L1) Blob Bridge*

## 1 · Protocol Overview  

**Canoe** is a framework that proves—on Ethereum—that a given EigenDA blob has been attested by **sufficient stake across every quorum** of EigenDA operators.

| Part | Role |
|-------|------|
| **Smart Contract CertVerifier** | Confirms that the total attested stake for *each* quorum meets or exceeds the required threshold. |
| **Off‑chain Validity‑Proof Generator** | Invokes the Solidity verifier off‑chain and produces a validity‑proof attesting to its output. |
| **On‑chain Validity‑Proof Verifier** | Checks the validity‑proof and the metadata contained in the EigenDA certificate. |

Canoe is under active development and currently supports two zkVM back‑ends: [RISC Zero Steel](https://risczero.com/steel) and [Succinct SP1 Contract Call](https://github.com/succinctlabs/sp1-contract-call).


## 2 · EigenDA V2 (“Blazar”) Upgrade  

In EigenDA V2 the certificate (DA cert) is returned to the requester immediately after quorum attestation; the disperser no longer pessimistically bridges the certs to the L1. Verification is thus left as the responsibility of the rollup, which can do so optimistically to save on gas costs.


## 3 · Implementation Details  

### 3.1 Solidity Verifier
Building on the V1 contract, the new [certificate verifier](https://github.com/Layr-Labs/eigenda/blob/ee092f345dfbc37fce3c02f99a756ff446c5864a/contracts/src/periphery/cert/v2/EigenDACertVerifierV2.sol#L120) can be modeled as

$$ f(S, C; I) -> O $$

| Symbol | Meaning |
|--------|---------|
| `f` | Contract logic |
| `S` | Ethereum state at a specific block (hash & number) |
| `C` | Call data (= EigenDA certificate) |
| `O` | Boolean validity result |
| `I` | L1 Chain Spec |

### 3.2 Validity‑Proof Generation (Off‑chain)  

1. An off‑chain prover reconstructs Ethereum state `S` at some block height `h`.  
2. It invokes `f` with certificate `C` l1 chain `I` and records output `O`.  
3. A zkVM produces proof `P` attesting that the tuple `(f,S,C,O,I)` is correct.

The proof `P` is verified by a **Validity‑Proof Verifier** already deployed on L1 (Risc0 or SP1).

## 4 · Use Cases

### 4.1 Blob Validity Inside a zkVM (Hokulea)

The **Hokulea** rollup client runs inside a zkVM. During blob derivation it must:

1. Receive proof `P` for every EigenDA certificate processed.  
2. Reconstruct `(f,s,C,O,I)` locally (where `s` commits to state `S`).  
3. Abort if `P` fails; otherwise continue derivation.  

Hokulea then emits its own zk‑proof, which can be posted to L1 to attest that:

* All derived blobs are correct, and  
* Malicious certificates were discarded.

### 4.2 Blob Validity In Ethereum

Another way to use Canoe is to verify the certificate validity proof on L1 directly. L1 must be able to construct $(f, s, C, O, I)$ or its equivalent. For instance, if we were to convert a L1 inbox to a smart contract. Let $f$ be the verifier contract, $C$ be eigenda certificate to be queued into the deriviation pipeline, $O$ be true. We need to ensure $s$ is at some block number higher than the L1 block number whose stake is used to disperse the EigenDA blob. It is achieved by checking the reference block number within the eigenda certificate is smaller than the block number with block hash $s$.

### 4.2 Direct L1 Certificate Verification  

Protocols can also verify `P` **directly on Ethereum**:

* `f`: the on‑chain verifier contract.  
* `C`: the EigenDA certificate to enqueue.  
* `O = true`.  
* `s`: a block *after* the stake snapshot referenced in `C` (enforced by checking the certificate’s reference block number).
* `I`: ethereum chain ID.  

This allows L1 contracts to trust EigenDA blobs without verifying the BLS aggregated signature onchain.

## 5 · Remark

The Chain Specification defines the rules of the EVM, which underpin the execution semantics of Solidity contracts. As such, any Ethereum hardfork that introduces changes to EVM behavior necessitates corresponding updates across the proof stack. Specifically, both RISC Zero Steel and SP1 Contract Call backends must be upgraded to align with the new EVM logic. To remain compatible, Hokulea must also integrate an updated version of the zkVM backend that reflects these changes.

Before an Ethereum hardfork is activated, the zkVM backend must audit, prepare, and release an upgraded version to ensure compatibility. Importantly, the universal zkVM verifier deployed on L1 does not require an upgrade with each EVM change, since previously generated contract logic remains valid and backward-compatible across EVM upgrades.

## Canoe and Hokulea Upgrade

Canoe depends on the zkVM back‑end libraries, so every library upgrade forces a rebuild of its execution artifacts—most notably the ELF image. In the Hokulea workflow, the guest program’s fingerprint (an image ID for Steel, or a verification key for SP1‑Contract‑Call) is hard‑coded and verified inside the zkVM, meaning any new Hokulea ELF must also be registered on Ethereum L1: deploy the new image ID for Steel or publish the new verification key for SP1.

For rollups built on the OP Stack, an Ethereum hardfork almost always triggers an accompanying OP protocol upgrade; the refreshed Canoe artifacts should be rolled into that same upgrade package.

If a library change also alters the guest code’s smart‑contract interface, both Canoe and Hokulea need a fresh L1 registration of the new image ID (Risc Zero) or verification key (SP1). To eliminate this extra step, the team is developing a router layer inside the Solidity verifier that will automatically route to the correct image, removing the need for manual updates in the future.
