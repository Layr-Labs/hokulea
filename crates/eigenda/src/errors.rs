use thiserror::Error;

#[derive(Error, Debug)]
pub enum CodecError {
    #[error("blob does not contain 32 header bytes, meaning it is malformed")]
    BlobTooShort,
}
