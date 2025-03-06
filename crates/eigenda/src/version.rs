use crate::altda_commitment::AltDACommitmentParseError;
#[derive(Debug, PartialEq, Copy, Clone)]
/// Represents the cert version derived from rollup inbox
/// The version is needed to decode the Cert from serialiezd bytes
/// Once a valid blob is retrieved, both versions use the identical
/// logic to derive the rollup channel frame from eigenda blobs
pub enum CertVersion {
    /// eigenda cert v1 version
    Version1 = 0,
    /// eigenda cert v2 version
    Version2,
}

impl TryFrom<u8> for CertVersion {
    type Error = AltDACommitmentParseError;
    fn try_from(value: u8) -> Result<CertVersion, Self::Error> {
        match value {
            0 => Ok(Self::Version1),
            1 => Ok(Self::Version2),
            _ => Err(AltDACommitmentParseError::UnsupportedCertVersionType),
        }
    }
}

impl From<CertVersion> for u8 {
    fn from(version: CertVersion) -> Self {
        version as u8
    }
}
