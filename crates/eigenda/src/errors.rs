//! High level application error type for eigenda blob derivation

use alloc::string::{String, ToString};
use eigenda_cert::AltDACommitmentParseError;

/// Actionable hokulea error
#[derive(Debug, thiserror::Error, PartialEq)]
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

/// Both [HokuleaStatelessError] and [HokuleaPreimageError] defined at the bottom
/// represents all application error for hokulea. The [HokuleaStatelessError] is
/// different that the errors comes from pure data processing of altDA commitment
/// and encoded payload
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

/// The [HokuleaPreimageError] contains application errors, that is directly relates
/// to the preimage returned by the preimage provider. There is no error for
/// EncodedPayload which is also a preimage, because EncodedPayload is only a vector
/// of bytes, but its decoding check is covered by [HokuleaStatelessError] in the data
/// processing stage.
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
