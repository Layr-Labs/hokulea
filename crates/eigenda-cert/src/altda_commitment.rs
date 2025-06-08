use crate::{EigenDACertV2, EigenDACertV3};
use alloc::vec::Vec;
use alloy_primitives::keccak256;
use alloy_primitives::{B256, U256};
use alloy_rlp::Decodable;
use alloy_rlp::Encodable;
use alloy_rlp::Error;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// EigenDACert can be either v1 or v2
/// TODO consider boxing them, since the variant has large size
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum EigenDAVersionedCert {
    /// V2
    V2(EigenDACertV2),
    /// V3
    V3(EigenDACertV3),
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum AltDACommitmentParseError {
    /// Invalid cert metadata
    #[error("Insufficient altda commitment data")]
    InsufficientData,
    /// Unsupported derivation version.
    #[error("Unsupported derivation version")]
    UnsupportedVersion,
    /// Frame data length mismatch.
    #[error("Unsupported da layer type")]
    UnsupportedDaLayerType,
    /// No frames decoded.
    #[error("Unsupported commitment type")]
    UnsupportedCommitmentType,
    /// Only V1 and V2 are supported
    #[error("Unsupported cert version type {0}")]
    UnsupportedCertVersionType(u8),
    /// Only V1 and V2 are supported
    #[error("Unable to decode rlp cert: {0}")]
    InvalidRlpCert(Error),
}

/// AltDACommitment is used as the query key to retrieve eigenda blob from the eigenda proxy
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AltDACommitment {
    /// <https://specs.optimism.io/experimental/alt-da.html#input-commitment-submission>
    /// 0 for keccak, 1 for da-service
    pub commitment_type: u8,
    /// da_layer_byte, eigenda is 0
    pub da_layer_byte: u8,
    /// eigenda versioned cert
    pub versioned_cert: EigenDAVersionedCert,
}

impl TryFrom<&[u8]> for AltDACommitment {
    type Error = AltDACommitmentParseError;
    fn try_from(value: &[u8]) -> Result<AltDACommitment, Self::Error> {
        // at least 3 bytes to indicate the type
        if value.len() <= 4 {
            return Err(AltDACommitmentParseError::InsufficientData);
        }

        // <https://specs.optimism.io/experimental/alt-da.html#input-commitment-submission>
        // 0 for keccak, 1 for da-service
        let commitment_type = value[0];
        if commitment_type != 1 {
            return Err(AltDACommitmentParseError::UnsupportedCommitmentType);
        }

        // da_layer_byte, eigenda is 0
        let da_layer_byte = value[1];
        if da_layer_byte != 0 {
            return Err(AltDACommitmentParseError::UnsupportedDaLayerType);
        }

        let versioned_cert = match value[2] {
            // V2 cert
            1 => {
                let v2_cert =
                    EigenDACertV2::decode(&mut &value[3..]).map_err(Self::Error::InvalidRlpCert)?;
                EigenDAVersionedCert::V2(v2_cert)
            }
            // V3 cert
            2 => {
                let v3_cert =
                    EigenDACertV3::decode(&mut &value[3..]).map_err(Self::Error::InvalidRlpCert)?;
                EigenDAVersionedCert::V3(v3_cert)
            }
            _ => {
                // also filter out non v2 cert since no logics have been implemented
                return Err(AltDACommitmentParseError::UnsupportedCertVersionType(
                    value[2],
                ));
            }
        };
        Ok(AltDACommitment {
            commitment_type,
            da_layer_byte,
            versioned_cert,
        })
    }
}

impl AltDACommitment {
    /// This function preprare a holder for a key used to fetch field elements for
    /// eigenda blob. The analogous code for eth blob can be found
    /// <https://github.com/op-rs/kona/blob/08064c4f464b016dc98671f2b3ea60223cfa11a9/crates/proof/proof/src/l1/blob_provider.rs#L57C9-L57C70>
    ///
    /// A template contains 80 bytes in total
    ///  |  32 bytes | 0 .. 0 | 8 bytes             |
    ///  |cert digest| 0 .. 0 | field element index |
    ///
    /// The template only populates the first 32 bytes, the downstream logics must update
    /// the last 8 bytes for querying each individual the field element.
    ///
    /// We illustrate why we can't use kzg commitment like ethereum blob like the link above.
    /// For instance, an adversary can first provide a (valid cert1, index 0, a correct field element A),
    /// then it uploads another tuple (invalid cert2, index 0, a random field element B). However,
    /// cert1 and cert2 can have the same commitment. Therefore the value A can be overwritten by the empty byte
    ///
    /// By hashing the entire cert, such problem is avoided entirely
    pub fn digest_template(&self) -> [u8; 80] {
        let mut field_element_key = [0u8; 80];
        let digest = self.to_digest();
        field_element_key[..32].copy_from_slice(digest.as_slice());
        field_element_key
    }

    /// get number of field element for a cert
    pub fn get_num_field_element(&self) -> usize {
        match &self.versioned_cert {
            EigenDAVersionedCert::V2(c) => {
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .length as usize
            }
            EigenDAVersionedCert::V3(c) => {
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .length as usize
            }
        }
    }

    /// get reference block number
    pub fn get_rbn(&self) -> u64 {
        match &self.versioned_cert {
            EigenDAVersionedCert::V2(c) => c.batch_header_v2.reference_block_number as u64,
            EigenDAVersionedCert::V3(c) => c.batch_header_v2.reference_block_number as u64,
        }
    }

    /// get kzg commitment g1 point, first U256 is x coordinate, second is y
    pub fn get_kzg_commitment(&self) -> (U256, U256) {
        match &self.versioned_cert {
            EigenDAVersionedCert::V2(c) => (
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment
                    .x,
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment
                    .y,
            ),
            EigenDAVersionedCert::V3(c) => (
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment
                    .x,
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment
                    .y,
            ),
        }
    }

    /// Convert AltdaCommitment into bytes in the same form downloaded from
    /// Ethereum block. The bytes form is used as the key to send http query
    /// to the eigenda proxy
    pub fn to_rlp_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.commitment_type.to_be());
        bytes.push(self.da_layer_byte.to_be());
        let mut cert_rlp_bytes = Vec::<u8>::new();
        match &self.versioned_cert {
            EigenDAVersionedCert::V2(c) => {
                // V2 cert has version byte 1
                bytes.push(1);
                c.encode(&mut cert_rlp_bytes);
            }
            EigenDAVersionedCert::V3(c) => {
                // V3 cert has version byte 2
                bytes.push(2);
                c.encode(&mut cert_rlp_bytes);
            }
        }
        bytes.extend_from_slice(&cert_rlp_bytes);
        bytes
    }

    /// Convert AltDACommitment into hash digest
    pub fn to_digest(&self) -> B256 {
        let rlp_bytes = self.to_rlp_bytes();
        keccak256(&rlp_bytes)
    }
}
