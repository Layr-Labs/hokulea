use alloy_primitives::Bytes;
use alloy_primitives::{keccak256, B256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use canoe_bindings as sol_struct;
use serde::{Deserialize, Serialize};

use crate::{BatchHeaderV2, BlobInclusionInfo, NonSignerStakesAndSignature};

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
        // rlp encode of cert
        self.encode(&mut cert_rlp_bytes);
        keccak256(&cert_rlp_bytes)
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut slice = data;
        EigenDACertV3::decode(&mut slice)
            .expect("should be able to convert to EigenDACertV2 struct")
    }

    pub fn to_sol(&self) -> sol_struct::EigenDACertV3 {
        sol_struct::EigenDACertV3 {
            batchHeaderV2: self.batch_header_v2.to_sol(),
            blobInclusionInfo: self.blob_inclusion_info.to_sol(),
            nonSignerStakesAndSignature: self.nonsigner_stake_and_signature.to_sol(),
            // solidity translate of bytes is alloy-primitives::Bytes
            signedQuorumNumbers: self.signed_quorum_numbers.clone(),
        }
    }
}
