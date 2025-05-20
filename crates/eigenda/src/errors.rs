//! High level Error type defined by hokulea

use crate::altda_commitment::AltDACommitmentParseError;
use alloc::string::ToString;
use alloc::string::String;

/// Actionable hokulea error 
#[derive(Debug, thiserror::Error)]
pub enum HokuleaErrorKind {
    /// for cert that has violated the rules in hokulea derivation
    #[error("Discard")]
    Discard,
    /// for provider violating eigenda properties, invalid field element
    #[error("Critical {0}")]
    Critical(String),
    /// for temporary issue like provider unable to provide data
    #[error("Temporary")]
    Temporary,
}


/// A list of error unrelated to the preimage, i.e all of which can be deduced
/// based on available data
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum HokuleaStatelessError {    
    /// Parse from bytes into Altda commitment containing a DA certificate
    /// use source because eventualy hokulea error will be overwritten into pipeline error
    /// any most of them won't contain data field for reason
    #[error("calldata length is not sufficinet")]
    InsufficientEigenDACertLength,
    #[error("parsing error {0}")]
    ParseError(#[source] AltDACommitmentParseError),    
    /// field element is out of bn254 field, a critical error
    #[error("field element too large")]
    FieldElementRangeError,
    /// blob decoding error, inbox sender has violated the encoding rule
    #[error("cannot decode a blob")]
    BlobDecodeError,
}



// define conversion error
impl From<HokuleaStatelessError> for HokuleaErrorKind {
    fn from(e: HokuleaStatelessError) -> Self {
        match e {
            HokuleaStatelessError::InsufficientEigenDACertLength => HokuleaErrorKind::Discard,            
            HokuleaStatelessError::ParseError(e) => HokuleaErrorKind::Discard,            
            HokuleaStatelessError::FieldElementRangeError => HokuleaErrorKind::Critical("field element too large".to_string()),
            HokuleaStatelessError::BlobDecodeError => HokuleaErrorKind::Discard,
        }
    }
}