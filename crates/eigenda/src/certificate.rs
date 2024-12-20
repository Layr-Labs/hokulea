// data struct copied from https://github.com/Layr-Labs/eigenda-client-rs/blob/3ac1f62ae3d99aedf3de7a2fe827fab17db7b874/src/blob_info.rs
use core::fmt;

use alloy_primitives::Bytes;
use alloy_rlp::{RlpDecodable, RlpEncodable};

use alloc::vec::Vec;


#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct G1Commitment {
    pub x: [u8; 32],
    pub y: [u8; 32],
}


#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct BlobQuorumParam {
    pub quorum_number: u32,
    pub adversary_threshold_percentage: u32,
    pub confirmation_threshold_percentage: u32,
    pub chunk_length: u32,
}

impl BlobQuorumParam {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.quorum_number.to_be_bytes());
        bytes.extend(&self.adversary_threshold_percentage.to_be_bytes());
        bytes.extend(&self.confirmation_threshold_percentage.to_be_bytes());
        bytes.extend(&self.chunk_length.to_be_bytes());

        bytes
    }
}


#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct BlobHeader {
    pub commitment: G1Commitment,
    pub data_length: u32,
    pub blob_quorum_params: Vec<BlobQuorumParam>,
}


#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct BatchHeader {
    pub batch_root: Bytes,
    pub quorum_numbers: Bytes,
    pub quorum_signed_percentages: Bytes,
    pub reference_block_number: u32,
}

#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct BatchMetadata {
    pub batch_header: BatchHeader,
    pub signatory_record_hash: Bytes,
    pub fee: Bytes,
    pub confirmation_block_number: u32,
    pub batch_header_hash: Bytes,
}

#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct BlobVerificationProof {
    pub batch_id: u32,
    pub blob_index: u32,
    pub batch_medatada: BatchMetadata,
    pub inclusion_proof: Bytes,
    pub quorum_indexes: Bytes,
}

#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct BlobInfo {
    pub blob_header: BlobHeader,
    pub blob_verification_proof: BlobVerificationProof,
}
