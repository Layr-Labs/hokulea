use crate::{
    errors::{EncodedPayloadDecodingError, HokuleaStatelessError},
    BYTES_PER_FIELD_ELEMENT,
};
use crate::{ENCODED_PAYLOAD_HEADER_LEN_BYTES, PAYLOAD_ENCODING_VERSION_0};
use alloc::vec;
use alloy_primitives::Bytes;
use rust_kzg_bn254_primitives::helpers;

/// Represents raw payload bytes, alias
pub type Payload = Bytes;

#[derive(Default, Clone, Debug)]
/// Represents the data structure for EigenDA Blob
/// intended for deriving rollup channel frame from eigenda blob
pub struct EncodedPayload {
    /// Bytes over Vec because Bytes clone is a shallow copy
    pub encoded_payload: Bytes,
}

impl EncodedPayload {
    /// Constructs an EncodedPayload from bytes array.
    /// Does not validate the bytes, to mimic the Blob.ToEncodedPayloadUnchecked process.
    /// The length, header, and body invariants are checked when calling decode.
    pub fn deserialize(bytes: Bytes) -> Self {
        Self {
            encoded_payload: bytes,
        }
    }

    /// Returns the raw bytes of the encoded payload.
    pub fn serialize(&self) -> &Bytes {
        &self.encoded_payload
    }

    /// Returns the number of symbols in the encoded payload
    pub fn len_symbols(&self) -> u32 {
        (self.encoded_payload.len() / BYTES_PER_FIELD_ELEMENT) as u32
    }

    /// Checks whether the encoded payload satisfies its length invariant.
    /// EncodedPayloads must contain a power of 2 number of Field Elements, each of length 32.
    /// This means the only valid encoded payloads have byte lengths of 32, 64, 128, 256, etc.
    ///
    /// Note that this function only checks the length invariant, meaning that it doesn't check that
    /// the 32 byte chunks are valid bn254 elements.
    fn check_len_invariant(&self) -> Result<(), HokuleaStatelessError> {
        // this check is redundant since 0 is not a valid power of 32, but we keep it for clarity.
        if self.encoded_payload.len() < ENCODED_PAYLOAD_HEADER_LEN_BYTES {
            return Err(EncodedPayloadDecodingError::PayloadTooShortForHeader {
                expected: ENCODED_PAYLOAD_HEADER_LEN_BYTES,
                actual: self.encoded_payload.len(),
            }
            .into());
        }
        // Check encoded payload has a power of two number of field elements
        let num_field_elements = self.encoded_payload.len() / BYTES_PER_FIELD_ELEMENT;
        if !is_power_of_two(num_field_elements) {
            return Err(
                EncodedPayloadDecodingError::InvalidPowerOfTwoLength(num_field_elements).into(),
            );
        }
        Ok(())
    }

    /// Validates the header (first field element = 32 bytes) of the encoded payload,
    /// and returns the claimed length of the payload if the header is valid.
    fn decode_header(&self) -> Result<u32, HokuleaStatelessError> {
        if self.encoded_payload.len() < ENCODED_PAYLOAD_HEADER_LEN_BYTES {
            return Err(EncodedPayloadDecodingError::PayloadTooShortForHeader {
                expected: ENCODED_PAYLOAD_HEADER_LEN_BYTES,
                actual: self.encoded_payload.len(),
            }
            .into());
        }
        if self.encoded_payload[0] != 0x00 {
            return Err(EncodedPayloadDecodingError::InvalidHeaderFirstByte(
                self.encoded_payload[0],
            )
            .into());
        }
        let payload_length = match self.encoded_payload[1] {
            version if version == PAYLOAD_ENCODING_VERSION_0 => u32::from_be_bytes([
                self.encoded_payload[2],
                self.encoded_payload[3],
                self.encoded_payload[4],
                self.encoded_payload[5],
            ]),
            version => {
                return Err(EncodedPayloadDecodingError::UnknownEncodingVersion(version).into());
            }
        };
        Ok(payload_length)
    }

    /// Decodes the payload from the encoded payload bytes.
    /// Removes internal padding and extracts the payload data based on the claimed length.
    fn decode_payload(&self, payload_len: u32) -> Result<Payload, HokuleaStatelessError> {
        let body = self
            .encoded_payload
            .slice(ENCODED_PAYLOAD_HEADER_LEN_BYTES..);

        // Decode the body by removing internal 0 byte padding (0x00 initial byte for every 32 byte chunk)
        // The decodedBody should contain the payload bytes + potentially some external padding bytes.
        let decoded_body = helpers::remove_internal_padding(body.as_ref())
            .map_err(|_| EncodedPayloadDecodingError::InvalidBlobSizeInBytes(body.len() as u64))?;
        let decoded_body: Bytes = decoded_body.into();

        // data length is checked when constructing an encoded payload. If this error is encountered, that means there
        // must be a flaw in the logic at construction time (or someone was bad and didn't use the proper construction methods)
        if (decoded_body.len() as u32) < payload_len {
            return Err(EncodedPayloadDecodingError::UnpaddedDataTooShort {
                actual: decoded_body.len(),
                claimed: payload_len,
            }
            .into());
        }

        Ok(decoded_body.slice(0..payload_len as usize))
    }

    /// Decodes the blob into raw byte data. Reverse of the encode function below
    /// Returns a [EncodedPayloadDecodingError] if the blob is invalid.
    ///
    /// Applies the inverse of PayloadEncodingVersion0 to an EncodedPayload, and returns the decoded payload.
    pub fn decode(&self) -> Result<Payload, HokuleaStatelessError> {
        // Check length invariant
        self.check_len_invariant()?;

        // Decode header to get claimed payload length
        let payload_len_in_header = self.decode_header()?;
        debug!(target: "eigenda-datasource", "rollup payload length in bytes {:?}", payload_len_in_header);

        // Decode payload using the helper method
        self.decode_payload(payload_len_in_header)
    }

    /// The encode function accepts an input of opaque rollup data array into an EigenDABlobData.
    /// EigenDABlobData contains a header of 32 bytes and a transformation of input data
    /// The 0 index byte of header is always 0, to comply to bn254 field element constraint
    /// The 1 index byte of header is proxy encoding version.
    /// The 2-4 indices of header are storing the length of the input rollup data in big endien
    /// The payload is prepared by padding an empty byte for every 31 bytes from the rollup data
    /// This matches exactly the eigenda proxy implementation, whose logic is in
    /// <https://github.com/Layr-Labs/eigenda/blob/master/encoding/utils/codec/codec.go#L12>
    ///
    /// The length of (header + payload) by the encode function is always multiple of 32
    /// The eigenda proxy does not take such constraint.
    ///
    /// (ToDo) with new proxy release, it can return the encoded payload, the encode function can
    /// be moved into test, and no longer used anywhere else
    pub fn encode(rollup_data: &[u8], payload_encoding_version: u8) -> Self {
        let rollup_data_size = rollup_data.len() as u32;

        // encode to become raw blob
        let codec_rollup_data = helpers::pad_payload(rollup_data);

        let blob_payload_size = codec_rollup_data.len();

        // the first field element contains the header
        let blob_size = blob_payload_size + BYTES_PER_FIELD_ELEMENT;

        // round up to the closest multiple of 32
        let blob_size = blob_size.div_ceil(BYTES_PER_FIELD_ELEMENT) * BYTES_PER_FIELD_ELEMENT;

        let mut raw_blob = vec![0u8; blob_size as usize];

        raw_blob[1] = payload_encoding_version;
        raw_blob[2..6].copy_from_slice(&rollup_data_size.to_be_bytes());

        // encode length as uint32
        raw_blob[BYTES_PER_FIELD_ELEMENT..(BYTES_PER_FIELD_ELEMENT + blob_payload_size as usize)]
            .copy_from_slice(&codec_rollup_data);

        Self {
            encoded_payload: Bytes::from(raw_blob),
        }
    }
}

/// Utility function to check if a number is a power of two
fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::Bytes;

    #[test]
    fn test_encode_and_decode_success() {
        let rollup_data = vec![1, 2, 3, 4];
        let encoded_payload = EncodedPayload::encode(&rollup_data, PAYLOAD_ENCODING_VERSION_0);
        let data_len = encoded_payload.encoded_payload.len();
        assert!(data_len % BYTES_PER_FIELD_ELEMENT == 0);

        let result = encoded_payload.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(rollup_data));
    }

    #[test]
    fn test_encode_and_decode_success_empty() {
        let rollup_data = vec![];
        let encoded_payload = EncodedPayload::encode(&rollup_data, PAYLOAD_ENCODING_VERSION_0);
        let data_len = encoded_payload.encoded_payload.len();
        // 32 is eigenda blob header size
        assert!(data_len == 32);

        let result = encoded_payload.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(rollup_data));
    }

    #[test]
    fn test_encode_and_decode_error_invalid_length() {
        let rollup_data = vec![1, 2, 3, 4];
        let mut encoded_payload = EncodedPayload::encode(&rollup_data, PAYLOAD_ENCODING_VERSION_0);
        encoded_payload.encoded_payload.truncate(33);
        let result = encoded_payload.decode();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            EncodedPayloadDecodingError::InvalidBlobSizeInBytes(33).into()
        );
    }
}
