use crate::{EigenDACertV2, EigenDACertV3, G1Point};
use alloc::vec::Vec;
use alloy_primitives::keccak256;
use alloy_primitives::B256;
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
    #[error("Insufficient altda commitment data")]
    InsufficientData,
    #[error("Unsupported commitment type")]
    UnsupportedCommitmentType,
    #[error("Unsupported da layer type")]
    UnsupportedDaLayerType,
    #[error("Unsupported cert version type {0}")]
    UnsupportedCertVersionType(u8),
    #[error("Unable to decode rlp cert: {0}")]
    InvalidRlpCert(Error),
}

/// AltDACommitment contains EigenDA cert, and is used as a part of key to uniquely
/// address the preimage data including: cert validity, field elements, recency window
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
        if value.len() < 4 {
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
    /// eigenda encoded payload. The analogous code for eth blob can be found
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
    pub fn get_kzg_commitment(&self) -> G1Point {
        match &self.versioned_cert {
            EigenDAVersionedCert::V2(c) => G1Point {
                x: c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment
                    .x,
                y: c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment
                    .y,
            },
            EigenDAVersionedCert::V3(c) => G1Point {
                x: c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment
                    .x,
                y: c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment
                    .y,
            },
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

    /// Get Cert Version string
    pub fn cert_version_str(&self) -> &'static str {
        match self.versioned_cert {
            EigenDAVersionedCert::V2(_) => "V2",
            EigenDAVersionedCert::V3(_) => "V3",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::Bytes;

    #[test]
    fn test_try_into_altda_commitment_and_to_rlp_bytes_ok() {
        let calldata: Bytes = alloy_primitives::hex::decode("0x010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001").unwrap().into();
        let altda_commitment: AltDACommitment = calldata[..].try_into().unwrap();
        let calldata_serialized = altda_commitment.to_rlp_bytes();
        assert_eq!(calldata, calldata_serialized);
    }

    #[test]
    fn test_try_into_altda_commitment() {
        let calldata: Bytes = alloy_primitives::hex::decode("0x010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001").unwrap().into();
        let altda_commitment: AltDACommitment = calldata[..].try_into().unwrap();

        struct Case {
            input: Bytes,
            result: Result<AltDACommitment, AltDACommitmentParseError>,
        }

        let cases = vec![
            Case {
                input: vec![0u8; 2].into(),
                result: Err(AltDACommitmentParseError::InsufficientData),
            },
            Case {
                input: calldata.clone(),
                result: Ok(altda_commitment.clone()),
            },
            Case {
                input: {
                    let mut alt = altda_commitment.clone();
                    alt.commitment_type = 255;
                    alt.to_rlp_bytes().into()
                },
                result: Err(AltDACommitmentParseError::UnsupportedCommitmentType),
            },
            Case {
                input: {
                    let mut alt = altda_commitment.clone();
                    alt.da_layer_byte = 1;
                    alt.to_rlp_bytes().into()
                },
                result: Err(AltDACommitmentParseError::UnsupportedDaLayerType),
            },
            Case {
                input: alloy_primitives::hex::decode("0x010003f9").unwrap().into(),
                result: Err(AltDACommitmentParseError::UnsupportedCertVersionType(3)),
            },
            Case {
                input: alloy_primitives::hex::decode("0x010002f9").unwrap().into(),
                result: Err(AltDACommitmentParseError::InvalidRlpCert(
                    Error::InputTooShort,
                )),
            },
        ];

        for case in cases {
            let result: Result<AltDACommitment, AltDACommitmentParseError> =
                case.input.as_ref().try_into();
            assert_eq!(result, case.result);
        }
    }
}
