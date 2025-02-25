#[derive(Debug, PartialEq, Copy, Clone)]
/// Represents the cert version derived from rollup inbox
/// The version is needed to decode the Cert from serialiezd bytes
/// Once a valid blob is retrieved, both versions use the identical
/// logic to derive the rollup channel frame from eigenda blobs
pub enum CertVersion {
    /// existing eigenda cert version
    Version1,
    /// lastest eigenda cert version
    Version2,
}

impl From<u8> for CertVersion {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Version1,
            1 => Self::Version2,
            _ => panic!("unknown version"),
        }
    }
}
