use alloy_primitives::Bytes;
use alloy_rlp::{RlpDecodable, RlpEncodable};

use alloc::vec::Vec;

// TODO: use prost to generate struct from proto file
// see seggestion, https://github.com/Layr-Labs/hokulea/pull/17#discussion_r1901102921

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

/// eigenda v1 blob header
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

/// eigenda v1 blob verification proof
#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct BlobVerificationProof {
    pub batch_id: u32,
    pub blob_index: u32,
    pub batch_medatada: BatchMetadata,
    pub inclusion_proof: Bytes,
    pub quorum_indexes: Bytes,
}

/// eigenda v1 certificate
#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable)]
pub struct BlobInfo {
    /// v1 blob header
    pub blob_header: BlobHeader,
    /// v1 blob verification proof with merkle tree
    pub blob_verification_proof: BlobVerificationProof,
}
