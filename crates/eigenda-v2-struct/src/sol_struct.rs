use alloy_sol_types::sol;

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
        function verifyDACertV2(
            BatchHeaderV2 calldata batchHeader,
            BlobInclusionInfo calldata blobInclusionInfo,
            NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
        ) external view;
        #[sol(rpc)]
        function verifyDACertV2ForZKProof(
            BatchHeaderV2 calldata batchHeader,
            BlobInclusionInfo calldata blobInclusionInfo,
            NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
        ) external view returns (bool);
    }

}
