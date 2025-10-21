use alloy_primitives::Bytes;
use alloy_primitives::{keccak256, B256};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use canoe_bindings;
use serde::{Deserialize, Serialize};

use crate::{BatchHeaderV2, BlobInclusionInfo, EigenDACertV2, NonSignerStakesAndSignature};

extern crate alloc;
use alloc::vec::Vec;

/// EigenDA CertV3
#[derive(Debug, Clone, RlpEncodable, RlpDecodable, PartialEq, Serialize, Deserialize)]
pub struct EigenDACertV3 {
    pub batch_header_v2: BatchHeaderV2,
    pub blob_inclusion_info: BlobInclusionInfo,
    pub nonsigner_stake_and_signature: NonSignerStakesAndSignature,
    pub signed_quorum_numbers: Bytes,
}

impl EigenDACertV3 {
    pub fn to_digest(&self) -> B256 {
        let mut cert_rlp_bytes = Vec::<u8>::new();
        self.encode(&mut cert_rlp_bytes);
        keccak256(&cert_rlp_bytes)
    }

    pub fn to_sol(&self) -> canoe_bindings::EigenDACertV3 {
        canoe_bindings::EigenDACertV3 {
            batchHeaderV2: self.batch_header_v2.to_sol(),
            blobInclusionInfo: self.blob_inclusion_info.to_sol(),
            nonSignerStakesAndSignature: self.nonsigner_stake_and_signature.to_sol(),
            // solidity translate of bytes is alloy-primitives::Bytes
            signedQuorumNumbers: self.signed_quorum_numbers.clone(),
        }
    }
}

// V2 cert is equivalent to the V3 cert, except for swapping field orderings.
// https://github.com/Layr-Labs/eigenda/blob/e51dcc5f2919c952bc8f603d1269528ee5373ad1/api/clients/v2/coretypes/eigenda_cert.go#L341
impl From<&EigenDACertV2> for EigenDACertV3 {
    fn from(v2cert: &EigenDACertV2) -> EigenDACertV3 {
        EigenDACertV3 {
            batch_header_v2: v2cert.batch_header_v2.clone(),
            blob_inclusion_info: v2cert.blob_inclusion_info.clone(),
            nonsigner_stake_and_signature: v2cert.nonsigner_stake_and_signature.clone(),
            signed_quorum_numbers: v2cert.signed_quorum_numbers.clone(),
        }
    }
}
