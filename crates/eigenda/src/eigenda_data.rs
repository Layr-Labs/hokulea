use alloy_primitives::Bytes;

use kona_derive::errors::BlobDecodingError;

#[derive(Default, Clone, Debug)]
pub struct EigenDABlobData {
    /// The calldata
    pub(crate) blob: Bytes,
}

impl EigenDABlobData {
    /// Decodes the blob into raw byte data.
    /// Returns a [BlobDecodingError] if the blob is invalid.
    pub(crate) fn decode(&self) -> Result<Bytes, BlobDecodingError> {
        // where we can implement zero bytes etc.
        info!(target: "eigenda-blobdata", "decode {} {:?}", self.blob.len(), self.blob.clone());
        Ok(self.blob.clone())
    }
}
