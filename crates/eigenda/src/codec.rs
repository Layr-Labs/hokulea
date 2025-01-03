use alloy_primitives::Bytes;
use bytes::buf::Buf;
use rust_kzg_bn254::helpers;
use crate::BLOB_ENCODING_VERSION_0;
use kona_derive::errors::BlobDecodingError;
use alloc::vec::Vec;

/// encoded data into an eigenda blob. The output is always power of 2
pub fn encode_eigenda_blob(rollup_data: &[u8]) -> Bytes {
    let rollup_data_size = rollup_data.len() as u32;

    // encode to become raw blob
    let codec_rollup_data = helpers::convert_by_padding_empty_byte(rollup_data.as_ref());

    let blob_payload_size = codec_rollup_data.len();

    let blob_size = blob_payload_size + 32;
    let blob_size = blob_size.next_power_of_two();

    let mut raw_blob = Vec::<u8>::with_capacity(blob_size as usize);
    for i in 0..blob_size {
        raw_blob.push(0);
    }

    raw_blob[1] = BLOB_ENCODING_VERSION_0;
    raw_blob[2..6].copy_from_slice(&rollup_data_size.to_be_bytes());

    // encode length as uint32
    raw_blob[32..(32 + blob_payload_size as usize)].copy_from_slice(&codec_rollup_data);

    Bytes::from(raw_blob)
}


/// decode data into an eigenda blob
pub fn decode_eigenda_blob(blob: &Bytes) -> Result<Bytes, BlobDecodingError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::Bytes;
    use kona_derive::errors::BlobDecodingError;

    #[test]
    fn test_decode_success() {
        let content = vec![1, 2, 3, 4];
        let data = encode_eigenda_blob(&content);
        let data_len = data.len();
        assert!(data_len.is_power_of_two());

        let result = decode_eigenda_blob(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(content));
    }

    #[test]
    fn test_decode_success_empty() {
        let content = vec![];
        let data = encode_eigenda_blob(&content);
        let result = decode_eigenda_blob(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(content));
    }

    #[test]
    fn test_decode_error_invalid_length() {
        let content = vec![1, 2, 3, 4];
        let mut data = encode_eigenda_blob(&content);
        data.truncate(33);
        let result = decode_eigenda_blob(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), BlobDecodingError::InvalidLength);
    }
}
