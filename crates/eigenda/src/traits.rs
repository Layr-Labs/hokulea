use alloc::{boxed::Box, string::ToString};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use core::fmt::Display;
use eigenda_v2_struct_rust::EigenDAV2Cert;
use kona_derive::errors::PipelineErrorKind;
use rust_kzg_bn254_primitives::blob::Blob;

/// A trait for providing EigenDA blobs.
/// TODO: add explanation for why we need this to be a trait.
#[async_trait]
pub trait EigenDABlobProvider {
    /// The error type for the [EigenDABlobProvider].
    type Error: Display + ToString + Into<PipelineErrorKind>;

    /// Fetches a blob with v1 cert
    async fn get_blob(&mut self, cert: &Bytes) -> Result<Blob, Self::Error>;

    /// Fetches a blob with v2 cert
    async fn get_blob_v2(&mut self, cert: &EigenDAV2Cert) -> Result<Blob, Self::Error>;
}
