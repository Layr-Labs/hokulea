use alloc::{boxed::Box, string::ToString};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use core::fmt::Display;
use kona_derive::errors::PipelineErrorKind;

/// A trait for providing EigenDA blobs.
/// TODO: add explanation for why we need this to be a trait.
#[async_trait]
pub trait EigenDABlobProvider {
    /// The error type for the [EigenDABlobProvider].
    type Error: Display + ToString + Into<PipelineErrorKind>;

    /// Fetches a blob.
    async fn get_blob(&mut self, cert: &Bytes) -> Result<Bytes, Self::Error>;

    /// Fetches an element from a blob.
    async fn get_element(&mut self, cert: &Bytes, element: &Bytes) -> Result<Bytes, Self::Error>;
}
