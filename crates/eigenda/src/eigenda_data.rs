//! Contains Kona and EigenDA blob derivation pipeline. Typically rollup or
//! proving stack use their own derivation pipeline with customization.

use crate::{
    errors::{EncodedPayloadDecodingError, HokuleaStatelessError},
    BYTES_PER_FIELD_ELEMENT,
};
use crate::{ENCODED_PAYLOAD_HEADER_LEN_BYTES, PAYLOAD_ENCODING_VERSION_0};
use alloc::vec;
use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};

/// Represents raw payload bytes, alias
pub type Payload = Bytes;

#[derive(Default, Clone, Debug, Deserialize, Serialize, PartialEq)] //
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)] //
// [EigenDAWitness] requires serde for EncodedPayload
/// intended for deriving rollup channel frame from eigenda encoded payload
pub struct EncodedPayload {
    /// Bytes over Vec because Bytes clone is a shallow copy
    pub encoded_payload: Bytes,
}

impl EncodedPayload {
    /// Constructs an EncodedPayload from bytes array.
    /// Does not validate the bytes, the length, header, and body invariants are checked
    /// when calling decode.
    pub fn deserialize(bytes: Bytes) -> Self {
        Self {
            encoded_payload: bytes,
        }
    }

    /// Returns the raw bytes of the encoded payload.
    pub fn serialize(&self) -> &Bytes {
        &self.encoded_payload
    }

    /// Returns the number of field elements in the encoded payload
    pub fn num_field_element(&self) -> u64 {
        (self.encoded_payload.len() / BYTES_PER_FIELD_ELEMENT) as u64
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

        if !self
            .encoded_payload
            .len()
            .is_multiple_of(BYTES_PER_FIELD_ELEMENT)
        {
            return Err(EncodedPayloadDecodingError::InvalidLengthEncodedPayload(
                self.encoded_payload.len() as u64,
            )
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
        // this ensures the header 32 bytes is a valid field element
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

        // all the remaining bytes in the payload header must be zero
        for b in &self.encoded_payload[6..ENCODED_PAYLOAD_HEADER_LEN_BYTES] {
            if *b != 0x00 {
                return Err(
                    EncodedPayloadDecodingError::InvalidEncodedPayloadHeaderPadding(*b).into(),
                );
            }
        }

        Ok(payload_length)
    }

    /// Decodes the payload from the encoded payload bytes.
    /// Removes internal padding and extracts the payload data based on the claimed length.
    fn decode_payload(&self, payload_len: u32) -> Result<Payload, HokuleaStatelessError> {
        let body = self
            .encoded_payload
            .slice(ENCODED_PAYLOAD_HEADER_LEN_BYTES..);

        // Decode the body by removing internal 0 byte padding (0x00 initial byte for every 32 byte chunk)
        // this ensures every 32 bytes is a valid field element
        let decoded_body = EncodedPayload::check_and_remove_zero_padding_for_field_elements(&body)?;

        // data length is checked when constructing an encoded payload. If this error is encountered, that means there
        // must be a flaw in the logic at construction time (or someone was bad and didn't use the proper construction methods)
        if decoded_body.len() < payload_len as usize {
            return Err(EncodedPayloadDecodingError::DecodedPayloadBodyTooShort {
                actual: decoded_body.len(),
                claimed: payload_len,
            }
            .into());
        }

        for b in &decoded_body[payload_len as usize..] {
            if *b != 0x00 {
                return Err(
                    EncodedPayloadDecodingError::InvalidEncodedPayloadBodyPadding(*b).into(),
                );
            }
        }
        Ok(decoded_body.slice(0..payload_len as usize))
    }

    /// Decodes the encoded payload into raw byte data. Reverse of the encode function below
    /// Returns a [EncodedPayloadDecodingError] if the encoded payload is invalid.
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

    /// check_and_remove_zero_padding_for_field_elements checks if the first byte of every mulitple of 32 bytes is 0x00,
    /// it enforces the spec in <https://layr-labs.github.io/eigenda/integration/spec/3-data-structs.html#encoding-payload-version-0x0>
    /// then the function returns bytes with the zero-padding bytes removed.
    /// this ensures every multiple of 32 bytes is a valid field element
    fn check_and_remove_zero_padding_for_field_elements(
        encoded_body: &[u8],
    ) -> Result<Bytes, HokuleaStatelessError> {
        if !encoded_body.len().is_multiple_of(BYTES_PER_FIELD_ELEMENT) {
            return Err(EncodedPayloadDecodingError::InvalidLengthEncodedPayload(
                encoded_body.len() as u64,
            )
            .into());
        }

        let num_field_elements = encoded_body.len() / BYTES_PER_FIELD_ELEMENT;
        let mut decoded_body = vec::Vec::with_capacity(num_field_elements * 31);
        for chunk in encoded_body.chunks_exact(BYTES_PER_FIELD_ELEMENT) {
            if chunk[0] != 0x00 {
                return Err(
                    EncodedPayloadDecodingError::InvalidFirstByteFieldElementPadding(chunk[0])
                        .into(),
                );
            }
            decoded_body.extend_from_slice(&chunk[1..32]);
        }
        Ok(Bytes::from(decoded_body))
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
    use rust_kzg_bn254_primitives::helpers;

    /// The encode function accepts an input of opaque rollup data array into an [EncodedPayload].
    /// [EncodedPayload] contains a header of 32 bytes and a transformation of input data
    /// The 0 index byte of header is always 0, to comply to bn254 field element constraint
    /// The 1 index byte of header is proxy encoding version.
    /// The 2-5(inclusive) indices of header are storing the length of the input rollup data in big endien
    /// The payload is prepared by padding an empty byte for every 31 bytes from the rollup data
    /// This matches exactly the eigenda proxy implementation, whose logic is in
    /// <https://github.com/Layr-Labs/eigenda/blob/master/encoding/utils/codec/codec.go#L12>
    ///
    /// The length of (header + payload) by the encode function is always multiple of 32
    /// The eigenda proxy does not take such constraint.
    /// See also spec <https://layr-labs.github.io/eigenda/integration/spec/3-data-structs.html#encoding-payload-version-0x0>
    /// for the exact encoding methods.
    fn encode(rollup_data: &[u8], payload_encoding_version: u8) -> EncodedPayload {
        let rollup_data_size = rollup_data.len() as u32;

        let padded_rollup_data = helpers::pad_payload(rollup_data);

        let min_blob_payload_size = padded_rollup_data.len();

        // the first field element contains the header
        let blob_size = min_blob_payload_size + BYTES_PER_FIELD_ELEMENT;

        // round up to the closest multiple of 32
        let blob_size = blob_size.div_ceil(BYTES_PER_FIELD_ELEMENT) * BYTES_PER_FIELD_ELEMENT;

        let mut encoded_payload = vec![0u8; blob_size as usize];

        encoded_payload[1] = payload_encoding_version;
        // encode length as uint32
        encoded_payload[2..6].copy_from_slice(&rollup_data_size.to_be_bytes());

        encoded_payload
            [BYTES_PER_FIELD_ELEMENT..(BYTES_PER_FIELD_ELEMENT + min_blob_payload_size as usize)]
            .copy_from_slice(&padded_rollup_data);

        EncodedPayload {
            encoded_payload: Bytes::from(encoded_payload),
        }
    }

    #[test]
    fn test_encode_and_decode_success() {
        let rollup_data = vec![1, 2, 3, 4];
        let encoded_payload = encode(&rollup_data, PAYLOAD_ENCODING_VERSION_0);
        let data_len = encoded_payload.encoded_payload.len();
        assert!(data_len.is_multiple_of(BYTES_PER_FIELD_ELEMENT) && data_len != 0);

        let result = encoded_payload.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(rollup_data));
    }

    #[test]
    fn test_encode_and_decode_success_empty() {
        let rollup_data = vec![];
        let encoded_payload = encode(&rollup_data, PAYLOAD_ENCODING_VERSION_0);
        let data_len = encoded_payload.encoded_payload.len();
        // 32 byte is encoded payload header size
        assert!(data_len == 32);

        let result = encoded_payload.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from(rollup_data));
    }

    #[test]
    fn test_encode_and_decode_error_invalid_length() {
        let rollup_data = vec![1, 2, 3, 4];
        let mut encoded_payload = encode(&rollup_data, PAYLOAD_ENCODING_VERSION_0);
        encoded_payload.encoded_payload.truncate(33);
        let result = encoded_payload.decode();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            EncodedPayloadDecodingError::InvalidLengthEncodedPayload(33).into()
        );
    }

    #[test]
    fn test_serde_on_encoded_payload() {
        let rollup_data = vec![1, 2, 3, 4];
        let encoded_payload = encode(&rollup_data, PAYLOAD_ENCODING_VERSION_0);
        let ser = encoded_payload.serialize();
        let deserialized_encoded_payload = EncodedPayload::deserialize(ser.clone());
        assert_eq!(encoded_payload, deserialized_encoded_payload);
    }

    #[test]
    fn test_check_len_invariant() {
        struct Case {
            input: vec::Vec<u8>,
            result: Result<(), HokuleaStatelessError>,
        }
        let cases = [
            // not long enough
            Case {
                input: vec![1, 2, 3, 4],
                result: Err(EncodedPayloadDecodingError::PayloadTooShortForHeader {
                    expected: 32,
                    actual: 4,
                }
                .into()),
            },
            // not power of 2
            Case {
                input: vec![0; 96],
                result: Err(EncodedPayloadDecodingError::InvalidPowerOfTwoLength(
                    96 / BYTES_PER_FIELD_ELEMENT,
                )
                .into()),
            },
            // not divide 32
            Case {
                input: vec![0; 34],
                result: Err(EncodedPayloadDecodingError::InvalidLengthEncodedPayload(34).into()),
            },
            Case {
                input: vec![0; 64],
                result: Ok(()),
            },
        ];

        for case in cases {
            let encoded_payload = EncodedPayload {
                encoded_payload: case.input.into(),
            };
            if let Err(e) = encoded_payload.check_len_invariant() {
                assert_eq!(Err(e), case.result)
            }
        }
    }

    #[test]
    fn test_decode_header() {
        struct Case {
            input: vec::Vec<u8>,
            result: Result<u32, HokuleaStatelessError>,
        }
        let cases = [
            // insufficient length
            Case {
                input: vec![1, 2, 3, 4],
                result: Err(EncodedPayloadDecodingError::PayloadTooShortForHeader {
                    expected: 32,
                    actual: 4,
                }
                .into()),
            },
            // First byte is not 0
            Case {
                input: vec![1; 32],
                result: Err(EncodedPayloadDecodingError::InvalidHeaderFirstByte(1).into()),
            },
            // unknown encoding version
            Case {
                input: vec![
                    0, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                result: Err(EncodedPayloadDecodingError::UnknownEncodingVersion(2).into()),
            },
            // invalid header padding
            Case {
                input: vec![
                    0, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 3,
                ],
                result: Err(
                    EncodedPayloadDecodingError::InvalidEncodedPayloadHeaderPadding(3).into(),
                ),
            },
            // working case
            Case {
                input: vec![
                    0, 0, 0, 0, 0, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                result: Ok(129),
            },
        ];

        for case in cases {
            let encoded_payload = EncodedPayload {
                encoded_payload: case.input.into(),
            };
            match encoded_payload.decode_header() {
                Ok(length) => assert_eq!(length, case.result.unwrap()),
                Err(err) => assert_eq!(Err(err), case.result),
            }
        }
    }

    #[test]
    fn test_check_and_remove_zero_padding_for_field_elements() {
        struct Case {
            input: vec::Vec<u8>,
            result: Result<Bytes, HokuleaStatelessError>,
        }
        let cases = [
            // invalid length not divide 32 byte, which is size of field element
            Case {
                // 33 bytes
                input: vec![
                    0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2, 2,
                ],
                result: Err(EncodedPayloadDecodingError::InvalidLengthEncodedPayload(33).into()),
            },
            Case {
                // 64 bytes first byte violation
                input: vec![
                    3, 0, 0, 0, 0, 128, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                ],
                result: Err(
                    EncodedPayloadDecodingError::InvalidFirstByteFieldElementPadding(3).into(),
                ),
            },
            Case {
                // 64 bytes 32-th byte violation
                input: vec![
                    0, 0, 0, 0, 0, 128, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2, 111, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                ],
                result: Err(
                    EncodedPayloadDecodingError::InvalidFirstByteFieldElementPadding(111).into(),
                ),
            },
            Case {
                // 32 bytes
                input: vec![
                    0, 0, 0, 0, 0, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2,
                ],
                result: Ok(vec![
                    0, 0, 0, 0, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2,
                ]
                .into()),
            },
            Case {
                // 64 bytes
                input: vec![
                    0, 0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                ],
                result: Ok(vec![
                    0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                ]
                .into()),
            },
        ];

        for case in cases {
            match EncodedPayload::check_and_remove_zero_padding_for_field_elements(&case.input) {
                Ok(decoded_body) => assert_eq!(Ok(decoded_body), case.result),
                Err(e) => assert_eq!(Err(e), case.result),
            }
        }
    }

    #[test]
    fn test_decode_payload() {
        struct Case {
            input: vec::Vec<u8>,
            result: Result<Bytes, HokuleaStatelessError>,
        }
        let cases = [
            // invalid length not divide 32 byte, which is size of field element
            Case {
                // 33 bytes -> 1 byte payload body
                input: vec![
                    0, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 128,
                ],
                result: Err(EncodedPayloadDecodingError::InvalidLengthEncodedPayload(1).into()),
            },
            Case {
                // 64 bytes -> claimed length 128
                input: vec![
                    0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                ],
                result: Err(
                    EncodedPayloadDecodingError::InvalidFirstByteFieldElementPadding(3).into(),
                ),
            },
            Case {
                // 64 bytes -> claimed length 128
                input: vec![
                    0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                ],
                result: Err(EncodedPayloadDecodingError::DecodedPayloadBodyTooShort {
                    actual: 31,
                    claimed: 128,
                }
                .into()),
            },
            Case {
                // 64 bytes in total, but payload_len is 1 (number is represented in big endian),
                // so the remaining padding bytes need to be 0
                input: vec![
                    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                ],
                result: Err(
                    EncodedPayloadDecodingError::InvalidEncodedPayloadBodyPadding(2).into(),
                ),
            },
            Case {
                // 64 bytes
                input: vec![
                    0, 0, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                ],
                result: Ok(vec![1; 31].into()),
            },
            Case {
                // 64 bytes with special case when length is 1, with many 0 padding
                input: vec![
                    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                result: Ok(vec![128].into()),
            },
            Case {
                // 64 bytes with special case when length is 0, and all padding are 0
                input: vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                result: Ok(Bytes::new()),
            },
            Case {
                // 32 bytes with special case when length is 0
                input: vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                result: Ok(Bytes::new()),
            },
            Case {
                // 32 bytes with special case but claimed length is 3
                input: vec![
                    0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                // expect 64
                result: Err(EncodedPayloadDecodingError::DecodedPayloadBodyTooShort {
                    actual: 0,
                    claimed: 3,
                }
                .into()),
            },
        ];

        for case in cases {
            let encoded_payload = EncodedPayload {
                encoded_payload: case.input.into(),
            };
            let length_in_byte = encoded_payload
                .decode_header()
                .expect("should have decoded header successfully");

            match encoded_payload.decode_payload(length_in_byte) {
                Ok(payload) => assert_eq!(Ok(payload), case.result),
                Err(e) => {
                    assert_eq!(Err(e), case.result);
                }
            }
        }
    }
}
