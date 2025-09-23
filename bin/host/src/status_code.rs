use hokulea_eigenda::HokuleaPreimageError;
use serde::Deserialize;

pub const HTTP_RESPONSE_STATUS_CODE_TEAPOT: u16 = 418;

// The derivation error each corresponds to a status code, which is also defined in the core client,
// https://github.com/Layr-Labs/eigenda/blob/4fa89635da76a0dbde6ad48f4de15c6059c7f11a/api/clients/v2/coretypes/derivation_errors.go#L67
pub const STATUS_CODE_CERT_PARSE_ERROR: u8 = 1;
pub const STATUS_CODE_RECENCY_ERROR: u8 = 2;
pub const STATUS_CODE_INVALID_CERT_ERROR: u8 = 3;
pub const STATUS_CODE_BLOB_DECODING_ERROR: u8 = 4;

// When proxy returns a derivation error, the error is returned inside a HTTP TEAPOT json message on 418 error. See also proxy
// code at https://github.com/Layr-Labs/eigenda/blob/4fa89635da76a0dbde6ad48f4de15c6059c7f11a/api/clients/v2/coretypes/derivation_errors.go#L10
//
// https://github.com/Layr-Labs/eigenda/blob/f4ef5cd5/docs/spec/src/integration/spec/6-secure-integration.md#derivation-process
#[derive(Deserialize)]
pub struct DerivationError {
    #[serde(rename = "StatusCode")]
    pub status_code: u8,
    #[serde(rename = "Msg")]
    pub msg: String,
}

// Convert the derivation status code to semantic aware error.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum HostHandlerError {
    // error which hokulea client uses to discard cert
    #[error("hokulea client preimage error {0}")]
    HokuleaPreimageError(#[from] HokuleaPreimageError),
    // error which hokulea client uses to discard cert
    // but the decoding only happens if proxy is queried to return the decoded
    // payload, which is only used by op-node. For hokulea, the proxy returns
    // the encoded payload therefore, we shall not see any Decoding Error.
    #[error("hokulea client encoded payload decoding error {0}")]
    HokuleaEncodedPayloadDecodingError(u8),
    // status code is not defined
    #[error("undefined status code error {0}")]
    UndefinedStatusCodeError(u8),
    // status code that is defined but should not have appeared
    #[error("illogical status code error {0}")]
    IllogicalStatusCodeError(u8),
}

impl From<DerivationError> for HostHandlerError {
    fn from(status: DerivationError) -> Self {
        match status.status_code {
            STATUS_CODE_INVALID_CERT_ERROR => {
                HostHandlerError::HokuleaPreimageError(HokuleaPreimageError::InvalidCert)
            }
            STATUS_CODE_RECENCY_ERROR => {
                HostHandlerError::HokuleaPreimageError(HokuleaPreimageError::NotRecentCert)
            }
            // the hokulea client should have already handled the case
            STATUS_CODE_CERT_PARSE_ERROR => {
                HostHandlerError::IllogicalStatusCodeError(status.status_code)
            }
            STATUS_CODE_BLOB_DECODING_ERROR => {
                HostHandlerError::HokuleaEncodedPayloadDecodingError(status.status_code)
            }
            _ => HostHandlerError::UndefinedStatusCodeError(status.status_code),
        }
    }
}
