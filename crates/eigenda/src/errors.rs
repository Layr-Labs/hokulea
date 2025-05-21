//! High level Error type defined by hokulea

use crate::altda_commitment::AltDACommitmentParseError;
use alloc::string::{String, ToString};

/// Actionable hokulea error
#[derive(Debug, thiserror::Error)]
pub enum HokuleaErrorKind {
    /// for cert that has violated the rules in hokulea derivation
    #[error("Discard")]
    Discard(String),
    /// for provider violating eigenda properties, invalid field element
    #[error("Critical {0}")]
    Critical(String),
    /// for temporary issue like provider unable to provide data
    #[error("Temporary")]
    Temporary(String),
}

/// A list of error unrelated to the preimage, i.e all of which can be deduced
/// based on available data
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum HokuleaStatelessError {
    /// Data is too short for parsing the altda commitment
    #[error("calldata length is not sufficient")]
    InsufficientEigenDACertLength,
    /// Parse from bytes into Altda commitment containing a DA certificate
    /// use source because eventualy hokulea error will be overwritten into pipeline error
    #[error("parsing error {0}")]
    ParseError(#[source] AltDACommitmentParseError),
    /// field element is out of bn254 field, a critical error
    #[error("field element too large")]
    FieldElementRangeError,
    /// blob decoding error, inbox sender has violated the encoding rule
    #[error("cannot decode a blob")]
    BlobDecodeError(#[from] BlobDecodingError),
}

/// define conversion error
impl From<HokuleaStatelessError> for HokuleaErrorKind {
    fn from(e: HokuleaStatelessError) -> Self {
        match e {
            HokuleaStatelessError::InsufficientEigenDACertLength => {
                HokuleaErrorKind::Discard("Insufficient EigenDA Cert Length".to_string())
            }
            HokuleaStatelessError::ParseError(e) => HokuleaErrorKind::Discard(e.to_string()),
            HokuleaStatelessError::FieldElementRangeError => {
                HokuleaErrorKind::Critical("field element too large".to_string())
            }
            HokuleaStatelessError::BlobDecodeError(e) => HokuleaErrorKind::Discard(e.to_string()),
        }
    }
}

/// List of error can happen during blob decoding
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BlobDecodingError {
    /// the input blob has wrong size
    #[error("invalid blob length {0}")]
    InvalidBlobSizeInBytes(u64),
    /// the input blob has wrong encoding version
    #[error("invalid blob encoding version {0}")]
    InvalidBlobEncodingVersion(u8),
    /// the input blob violates the encoding semantics
    #[error("invalid blob encoding")]
    InvalidBlobEncoding,
    /// the input blob has wrong size
    #[error("invalid content size")]
    InvalidContentSize,
}
