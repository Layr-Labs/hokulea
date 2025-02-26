use anyhow::Result;

use crate::CertVersion;
/// Cert Metadata specifies the Commitment Mode as documented in 
/// <https://github.com/Layr-Labs/eigenda-proxy?tab=readme-ov-file#optimism-commitment-mode>
/// TODO make enum for each type and define error handle

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertMetaParseError {    
    /// Invalid cert metadata
    #[error("Invalid cert metadata")]
    InvalidCertMetadata,
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
    #[error("Unsupported cert version type")]
    UnsupportedCertVersionType,
}

pub type CertMetaData = [u8; 4];

pub fn parse_cert_metadata(value : &[u8]) -> Result<CertMetaData, CertMetaParseError> {
    if value.len() != 4 {
        return Err(CertMetaParseError::InvalidCertMetadata)
    }
    // <https://specs.optimism.io/protocol/derivation.html#batcher-transaction-format>
    // 1 for AltDA
    if value[0] != 0x1 {
        return Err(CertMetaParseError::UnsupportedVersion)
    }
    // <https://specs.optimism.io/experimental/alt-da.html#input-commitment-submission>
    // 0 for keccak, 1 for da-service
    if value[1] != 0x1 {
        return Err(CertMetaParseError::UnsupportedCommitmentType)
    }

    // da_layer_byte, eigenda is 0
    if value[2] != 0x0 {
        return Err(CertMetaParseError::UnsupportedDaLayerType)
    }

    // accept only two types of cert version 1 and 2
    let _cert_version: CertVersion = value[3].try_into()?;

    let mut cert_metadata = [0u8; 4];
    cert_metadata.copy_from_slice(value);
    Ok(cert_metadata)
}

/*
        Perhaps it is a good idea to make it strongly typed, for now too much work
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct CertMetaData {  
    /// <https://specs.optimism.io/protocol/derivation.html#batcher-transaction-format>
    /// 0 for Frame, 1 for AltDA
    pub transaction_format_version: u8,  
    /// <https://specs.optimism.io/experimental/alt-da.html#input-commitment-submission>
    /// 0 for keccak, 1 for da-service
    pub commitment_type: u8,
    /// da_layer_byte, eigenda is 0
    pub da_layer_byte: u8,
    /// eigenda v1 is 0, eigenda v2 is 1
    pub version: CertVersion,    
}

impl CertMetaData {
    /// parse 4 bytes of metadata and return error if misconfigured
    pub fn parse_cert_metadata(value: &[u8]) -> Result<CertMetaData, anyhow::Error> {
        let meta = CertMetaData {
            transaction_format_version: value[0],
            commitment_type: value[1],
            da_layer_byte: value[2],
            version: value[3].into(),
        };
        Ok(meta)
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        let mut value = [0u8; 4];
        value[0] = self.transaction_format_version;
        value[1] = self.commitment_type;
        value[2] = self.da_layer_byte;
        //value[3] = self.version.into();
        value
    }
}
*/
