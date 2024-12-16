use alloy_primitives::Bytes;

use kona_derive::errors::BlobDecodingError;

#[derive(Default, Clone, Debug)]
/// Represents the data structure for EigenDA Blob.
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::Bytes;

    #[test]
    fn test_decode_success() {
        let data = EigenDABlobData {
            blob: Bytes::from(vec![1, 2, 3, 4]),
        };
        let result = data.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_decode_empty_blob() {
        let data = EigenDABlobData {
            blob: Bytes::from(vec![]),
        };
        let result = data.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(vec![]));
    }

    #[test]
    fn test_decode_invalid_blob() {
        // TODO: implement this once decode actually does something
    }
}
