extern crate alloc;
use alloc::string::String;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KzgError {
    #[error("input length is invalid")]
    InvalidInputLength,
    #[error("blob length is not a multiple of 32 bytes or contains a non-canonical field element")]
    InvalidFieldElement,
    #[error("g1 point not on curve or not in subgroup: {0}")]
    NotOnCurveError(String),
    #[error("commitment failed to deserialize")]
    SerializationError,
    #[error("polynomial domain construction failed")]
    DomainError,
    #[error("inverse does not exist for given input")]
    InvalidDenominator,
    #[error("{0}")]
    GenericError(String),
}
