use crate::errors::HokuleaErrorKind;
use crate::AltDACommitment;
use alloc::{boxed::Box, string::ToString};
use async_trait::async_trait;
use core::fmt::Display;
use rust_kzg_bn254_primitives::blob::Blob;

/// A trait for providing EigenDA blobs.
/// TODO: add explanation for why we need this to be a trait.
#[async_trait]
pub trait EigenDABlobProvider {
    /// The error type for the [EigenDABlobProvider].
    type Error: Display + ToString + Into<HokuleaErrorKind>;

    /// Fetches eigenda blob. The returned blob must contain a number of field elements that is power of 2
    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error>;
}
