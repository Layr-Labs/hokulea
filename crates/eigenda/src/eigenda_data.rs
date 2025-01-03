use alloy_primitives::Bytes;
use bytes::buf::Buf;

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
        if self.blob.len() < 32 {
            return Err(BlobDecodingError::InvalidLength);
        }

        info!(target: "eigenda-datasource", "padded_eigenda_blob {:?}", self.blob);

        // see https://github.com/Layr-Labs/eigenda/blob/f8b0d31d65b29e60172507074922668f4ca89420/api/clients/codecs/default_blob_codec.go#L44
        let content_size = self.blob.slice(2..6).get_u32();
        info!(target: "eigenda-datasource", "content_size {:?}", content_size);

        // the first 32 Bytes are reserved as the header field element
        let codec_data = self.blob.slice(32..);

        // rust kzg bn254 impl already
        let blob_content =
            helpers::remove_empty_byte_from_padded_bytes_unchecked(codec_data.as_ref());
        let blob_content: Bytes = blob_content.into();

        if blob_content.len() < content_size as usize {
            return Err(BlobDecodingError::InvalidLength);
        }
        // might insert a FFT here,

        // take data
        Ok(blob_content.slice(..content_size as usize))
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
