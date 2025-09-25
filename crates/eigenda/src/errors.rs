//! High level Error type defined by hokulea

use alloc::string::{String, ToString};
use eigenda_cert::AltDACommitmentParseError;

/// Actionable hokulea error
#[derive(Debug, thiserror::Error)]
pub enum HokuleaErrorKind {
    /// for cert that has violated the rules in hokulea derivation
    #[error("Discard {0}")]
    Discard(String),
    /// for provider violating eigenda properties, invalid field element
    #[error("Critical {0}")]
    Critical(String),
    /// for temporary issue like provider unable to provide data
    #[error("Temporary {0}")]
    Temporary(String),
}

/// A list of Hokulea error purely out of data processing, and is decoupled from
/// the error from error out of the preimage error
#[derive(Debug, thiserror::Error, PartialEq)]
#[error(transparent)]
pub enum HokuleaStatelessError {
    /// Data is too short for parsing the altda commitment
    #[error("calldata length is not sufficient for altda commitment")]
    InsufficientLengthAltDACommimtment,
    /// Parse from bytes into Altda commitment containing a DA certificate
    /// use source because eventualy hokulea error will be overwritten into pipeline error
    #[error("parsing error {0}")]
    ParseError(#[source] AltDACommitmentParseError),
    /// field element is out of bn254 field, a critical error
    #[error("field element too large")]
    FieldElementRangeError,
    /// encoded payload decoding error, inbox sender has violated the encoding rule
    #[error("cannot decode an encoded payload")]
    DecodingError(#[from] EncodedPayloadDecodingError),
}

/// define conversion error
impl From<HokuleaStatelessError> for HokuleaErrorKind {
    fn from(e: HokuleaStatelessError) -> Self {
        match e {
            HokuleaStatelessError::InsufficientLengthAltDACommimtment => {
                HokuleaErrorKind::Discard("Insufficient EigenDA Cert Length".to_string())
            }
            HokuleaStatelessError::ParseError(e) => HokuleaErrorKind::Discard(e.to_string()),
            HokuleaStatelessError::FieldElementRangeError => {
                HokuleaErrorKind::Critical("field element too large".to_string())
            }
            HokuleaStatelessError::DecodingError(e) => HokuleaErrorKind::Discard(e.to_string()),
        }
    }
}

/// List of error can happen during decoding an encoded payload
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum EncodedPayloadDecodingError {
    /// the input encoded payload has wrong size
    #[error("invalid number of bytes in the encoded payload {0}, that is not multiple of bytes per field element")]
    InvalidLengthEncodedPayload(u64),
    /// encoded payload must contain a power of 2 number of field elements
    #[error("encoded payload must be a power of 2 field elements (32 bytes chunks), but got {0} field elements")]
    InvalidPowerOfTwoLength(usize),
    /// encoded payload header validation error
    #[error("encoded payload header first byte must be 0x00, but got {0:#04x}")]
    InvalidHeaderFirstByte(u8),
    /// encoded payload too short for header
    #[error("encoded payload must be at least {expected} bytes long to contain a header, but got {actual} bytes")]
    PayloadTooShortForHeader {
        /// Expected minimum length
        expected: usize,
        /// Actual payload length
        actual: usize,
    },
    /// unknown encoded payload header version
    #[error("unknown encoded payload header version: {0}")]
    UnknownEncodingVersion(u8),
    /// length of unpadded data is less than claimed in header
    #[error("length of unpadded data {actual} is less than length claimed in encoded payload header {claimed}")]
    UnpaddedDataTooShort {
        /// Actual unpadded data length
        actual: usize,
        /// Claimed length from header
        claimed: u32,
    },
}

/// A list of Hokulea error derived from data from preimage oracle
/// This error is intended for application logics, and it is separate from
/// the more basic error type that deals with HokuleaOracleProviderError
/// which hanldes communicates, response format error
#[derive(Debug, thiserror::Error, PartialEq)]
#[error(transparent)]
pub enum HokuleaPreimageError {
    /// EigenDA cert is invalid
    #[error("da cert is invalid")]
    InvalidCert,
    /// EigenDA cert is not recent
    #[error("da cert is not recent enough")]
    NotRecentCert,
}

/// define conversion error
impl From<HokuleaPreimageError> for HokuleaErrorKind {
    fn from(e: HokuleaPreimageError) -> Self {
        match e {
            HokuleaPreimageError::InvalidCert => {
                HokuleaErrorKind::Discard("da cert is invalid".to_string())
            }
            HokuleaPreimageError::NotRecentCert => {
                HokuleaErrorKind::Discard("da cert is not recent enough".to_string())
            }
        }
    }
}
