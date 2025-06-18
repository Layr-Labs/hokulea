use hokulea_eigenda::HokuleaPreimageError;
use serde::Deserialize;

pub const HTTP_RESPONSE_STATUS_CODE_TEAPOT: u16 = 418;

pub const STATUS_RECENCY_ERROR: u8 = 255;
pub const STATUS_PARSE_ERROR: u8 = 254;

// smart contract status code
pub const STATUS_NULL_ERROR: u8 = 0;
pub const STATUS_SUCCESS: u8 = 1;
pub const STATUS_INVALID_INCLUSION_PROOF: u8 = 2;
pub const STATUS_SECURITY_ASSUMPTIONS_NOT_MET: u8 = 3;
pub const STATUS_BLOB_QUORUMS_NOT_SUBSET: u8 = 4;
pub const STATUS_REQUIRED_QUORUMS_NOT_SUBSET: u8 = 5;

#[derive(Deserialize)]
pub struct EigenDAStatusCode {
    #[serde(rename = "StatusCode")]
    pub status_code: u8,
    #[serde(rename = "Msg")]
    pub msg: String,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum HostHandlerError {
    // error which hokulea client uses to discard cert
    #[error("hokulea client preimage error {0}")]
    HokuleaClientError(#[from] HokuleaPreimageError),
    // status code is not defined
    #[error("undefined status code error {0}")]
    UndefinedStatusCodeError(u8),
    // status code that is defined but should not have appeared
    #[error("illogical status code error {0}")]
    IllogicalStatusCodeError(u8),
}

impl From<EigenDAStatusCode> for HostHandlerError {
    fn from(status: EigenDAStatusCode) -> Self {
        match status.status_code {
            STATUS_NULL_ERROR
            | STATUS_INVALID_INCLUSION_PROOF
            | STATUS_SECURITY_ASSUMPTIONS_NOT_MET
            | STATUS_BLOB_QUORUMS_NOT_SUBSET
            | STATUS_REQUIRED_QUORUMS_NOT_SUBSET => {
                HostHandlerError::HokuleaClientError(HokuleaPreimageError::InvalidCert)
            }
            STATUS_RECENCY_ERROR => {
                HostHandlerError::HokuleaClientError(HokuleaPreimageError::NotRecentCert)
            }
            STATUS_SUCCESS => HostHandlerError::IllogicalStatusCodeError(status.status_code),
            _ => HostHandlerError::UndefinedStatusCodeError(status.status_code),
        }
    }
}
