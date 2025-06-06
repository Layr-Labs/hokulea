use alloy_primitives::Bytes;
use alloy_primitives::{keccak256, B256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

use crate::{BatchHeaderV2, BlobInclusionInfo, NonSignerStakesAndSignature};

extern crate alloc;
use alloc::vec::Vec;

/// EigenDAV2 CertV3
#[derive(Debug, Clone, RlpEncodable, RlpDecodable, PartialEq, Serialize, Deserialize)]
pub struct EigenDAV2CertV3 {
    pub batch_header_v2: BatchHeaderV2,
    pub blob_inclusion_info: BlobInclusionInfo,
    pub nonsigner_stake_and_signature: NonSignerStakesAndSignature,
    pub signed_quorum_numbers: Bytes,
}

impl EigenDAV2CertV3 {
    pub fn digest(&self) -> B256 {
        let mut cert_rlp_bytes = Vec::<u8>::new();
        // rlp encode of cert
        self.encode(&mut cert_rlp_bytes);
        keccak256(&cert_rlp_bytes)
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut slice = data;
        EigenDAV2CertV3::decode(&mut slice)
            .expect("should be able to convert to EigenDAV2CertV2 struct")
    }
}
