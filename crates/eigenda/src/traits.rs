use alloc::{boxed::Box, string::ToString};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use core::fmt::Display;
use kona_derive::errors::PipelineErrorKind;

#[async_trait]
pub trait EigenDABlobProvider {
    /// The error type for the [EigenDAProvider].
    type Error: Display + ToString + Into<PipelineErrorKind>;

    async fn get_blob(&mut self, cert: &Bytes) -> Result<Bytes, Self::Error>;

    async fn get_element(&mut self, cert: &Bytes, element: &Bytes) -> Result<Bytes, Self::Error>;
}
