use crate::BLOB_ENCODING_VERSION_0;
use alloc::vec;
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
    /// Decodes the blob into raw byte data. Reverse of the encode function below
    /// Returns a [BlobDecodingError] if the blob is invalid.
    pub fn decode(&self) -> Result<Bytes, BlobDecodingError> {
        let blob = &self.blob;
        if blob.len() < 32 {
            return Err(BlobDecodingError::InvalidLength);
        }

        info!(target: "eigenda-datasource", "padded_eigenda_blob {:?}", blob);

        // see https://github.com/Layr-Labs/eigenda/blob/f8b0d31d65b29e60172507074922668f4ca89420/api/clients/codecs/default_blob_codec.go#L44
        let content_size = blob.slice(2..6).get_u32();
        info!(target: "eigenda-datasource", "content_size {:?}", content_size);

        // the first 32 Bytes are reserved as the header field element
        let codec_data = blob.slice(32..);

        // rust kzg bn254 impl already
        let blob_content =
            helpers::remove_empty_byte_from_padded_bytes_unchecked(codec_data.as_ref());
        let blob_content: Bytes = blob_content.into();

        if blob_content.len() < content_size as usize {
            return Err(BlobDecodingError::InvalidLength);
        }
        Ok(blob_content.slice(..content_size as usize))
    }

    /// The encode function accepts an input of opaque rollup data array into an EigenDABlobData.
    /// EigenDABlobData contains a header of 32 bytes and a transformation of input data
    /// The 0 index byte of header is always 0, to comply to bn254 field element constraint
    /// The 1 index byte of header is proxy encoding version.
    /// The 2-4 indices of header are storing the length of the input rollup data in big endien
    /// The payload is prepared by padding an empty byte for every 31 bytes from the rollup data
    /// This matches exactly the eigenda proxy implementation, whose logic is in
    /// https://github.com/Layr-Labs/eigenda/blob/master/encoding/utils/codec/codec.go#L12
    ///
    /// The length of (header + payload) by the encode function is always power of 2
    /// The eigenda proxy does not take such constraint.
    /// TODO it is possible to remove such power of 2 constraint, such that the client is not
    /// relying on the data_length from eigenda cert. It might save some comm rounds between
    /// host and client.
    pub fn encode(rollup_data: &[u8]) -> Self {
        let rollup_data_size = rollup_data.len() as u32;

        // encode to become raw blob
        let codec_rollup_data = helpers::convert_by_padding_empty_byte(rollup_data.as_ref());

        let blob_payload_size = codec_rollup_data.len();

        let blob_size = blob_payload_size + 32;
        let blob_size = blob_size.next_power_of_two();

        let mut raw_blob = vec![0u8; blob_size as usize];

        raw_blob[1] = BLOB_ENCODING_VERSION_0;
        raw_blob[2..6].copy_from_slice(&rollup_data_size.to_be_bytes());

        // encode length as uint32
        raw_blob[32..(32 + blob_payload_size as usize)].copy_from_slice(&codec_rollup_data);

        Self {
            blob: Bytes::from(raw_blob),
        }
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

    #[test]
    fn test_encode_and_decode_success() {
        let rollup_data = vec![1, 2, 3, 4];
        let eigenda_blob = EigenDABlobData::encode(&rollup_data);
        let data_len = eigenda_blob.blob.len();
        assert!(data_len.is_power_of_two());

        let result = eigenda_blob.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(rollup_data));
    }

    #[test]
    fn test_encode_and_decode_success_empty() {
        let rollup_data = vec![];
        let eigenda_blob = EigenDABlobData::encode(&rollup_data);
        let data_len = eigenda_blob.blob.len();
        // 32 is eigenda blob header size
        assert!(data_len == 32);

        let result = eigenda_blob.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(rollup_data));
    }

    #[test]
    fn test_encode_and_decode_error_invalid_length() {
        let rollup_data = vec![1, 2, 3, 4];
        let mut eigenda_blob = EigenDABlobData::encode(&rollup_data);
        eigenda_blob.blob.truncate(33);
        let result = eigenda_blob.decode();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), BlobDecodingError::InvalidLength);
    }
}
