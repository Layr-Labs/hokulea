use alloy_primitives::Bytes;
use alloy_primitives::{keccak256, B256};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

use crate::{BatchHeaderV2, BlobInclusionInfo, NonSignerStakesAndSignature};

extern crate alloc;
use alloc::vec::Vec;

/// EigenDA CertV2
#[derive(Debug, Clone, RlpEncodable, RlpDecodable, PartialEq, Serialize, Deserialize)]
pub struct EigenDACertV2 {
    pub blob_inclusion_info: BlobInclusionInfo,
    pub batch_header_v2: BatchHeaderV2,
    pub nonsigner_stake_and_signature: NonSignerStakesAndSignature,
    pub signed_quorum_numbers: Bytes,
}

impl EigenDACertV2 {
    pub fn to_digest(&self) -> B256 {
        let mut cert_rlp_bytes = Vec::<u8>::new();
        // rlp encode of cert
        self.encode(&mut cert_rlp_bytes);
        keccak256(&cert_rlp_bytes)
    }
}
