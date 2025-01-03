use crate::codec;
use alloy_primitives::Bytes;
use kona_derive::errors::BlobDecodingError;

use rust_kzg_bn254::helpers;

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
        let rollup_blob = codec::decode_eigenda_blob(&self.blob)?;
        // might insert a FFT here,

        // take data
        Ok(rollup_blob)
    }
}

#[cfg(test)]
mod tests {
    use crate::BLOB_ENCODING_VERSION_0;

    use super::*;
    use alloc::vec;
    use alloy_primitives::Bytes;
    use kona_derive::errors::BlobDecodingError;

    fn generate_blob_data(content: &[u8]) -> EigenDABlobData {
        let mut blob = vec![0; 32];
        blob[1] = BLOB_ENCODING_VERSION_0;
        blob[2..6].copy_from_slice(&(content.len() as u32).to_be_bytes());
        blob.extend_from_slice(&helpers::convert_by_padding_empty_byte(content));
        EigenDABlobData {
            blob: Bytes::from(blob),
        }
    }

    #[test]
    fn test_decode_success() {
        let content = vec![1, 2, 3, 4];
        let data = generate_blob_data(&content);
        let result = data.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(content));
    }

    #[test]
    fn test_decode_success_empty() {
        let content = vec![];
        let data = generate_blob_data(&content);
        let result = data.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(content));
    }

    #[test]
    fn test_decode_error_invalid_length() {
        let data = EigenDABlobData {
            blob: Bytes::from(vec![0; 31]), // one byte short of having a full header
        };
        let result = data.decode();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), BlobDecodingError::InvalidLength);
    }
}
