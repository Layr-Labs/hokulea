#![no_std]

use alloy_sol_types::sol;

sol! {
    /// A data struct committed by zkVM, it is the anchor for the
    /// security of certificate. For every valid DA cert, it must
    /// satisfies some condition defined in the smart contract,
    /// roughly speaking, a cert must have sufficient attestation.
    /// The zkvm guest runs the smart contract locally, with library
    /// like steel and sp1-cc. After computation zkVM must commit
    /// the following struct outline: input, output, compute logic
    /// pinned by the address, blockhash (specifying the state when
    /// execution takes place) and finally the chain id (indicating
    /// the current hardfork of the EVM which might affect rules of
    /// executions).
    /// For Hokulea integration, the hokulea client runs a verifier
    /// for the corresponding proving backend, the client constructs
    /// locally of all the following field. Blockhash uses l1_head,
    /// certVerifierAddress is either built into binary or committed
    /// onchain L1, input is the DA certificate, and l1ChainId can
    /// be found from the bootInfo. All of above are retrievable
    /// from a trusted source from the hokulea client's point. The
    /// output are taken based on claims by the host, therefore it
    /// needs to be verified against. Since the output is a deterministic
    /// function of (blockhash, input, verifierAddress, chain_id),
    /// the hokulea client can use output field of the journal committed
    /// by zkVM, and its trustness is protected by the zk validity proof.
    /// After comparing the supplied output by the host, and the
    /// output from the journal, the client can safely consumes the
    /// DA certificate.
    struct Journal {
        bytes32 blockhash;
        address certVerifierAddress;
        bytes input;
        bool output;
        uint64 l1ChainId;
    }
}

sol! {
    struct BatchHeaderV2 {
        bytes32 batchRoot;
        uint32 referenceBlockNumber;
    }

    struct BlobInclusionInfo {
        BlobCertificate blobCertificate;
        uint32 blobIndex;
        bytes inclusionProof;
    }

    struct BlobCertificate {
        BlobHeaderV2 blobHeader;
        bytes signature;
        uint32[] relayKeys;
    }

    struct BlobHeaderV2 {
        uint16 version;
        bytes quorumNumbers;
        BlobCommitment commitment;
        bytes32 paymentHeaderHash;
    }

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[1] * i + X[0]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    struct BlobCommitment {
        G1Point commitment;
        G2Point lengthCommitment;
        G2Point lengthProof;
        uint32 length;
    }

    struct NonSignerStakesAndSignature {
        uint32[] nonSignerQuorumBitmapIndices;
        G1Point[] nonSignerPubkeys;
        G1Point[] quorumApks;
        G2Point apkG2;
        G1Point sigma;
        uint32[] quorumApkIndices;
        uint32[] totalStakeIndices;
        uint32[][] nonSignerStakeIndices;
    }

    interface IEigenDACertVerifier {
        #[sol(rpc)]
        function verifyDACertV2ForZKProof(
            BatchHeaderV2 calldata batchHeader,
            BlobInclusionInfo calldata blobInclusionInfo,
            NonSignerStakesAndSignature calldata nonSignerStakesAndSignature,
            bytes signedQuorumNumbers
        ) external view returns (bool);
    }

}
