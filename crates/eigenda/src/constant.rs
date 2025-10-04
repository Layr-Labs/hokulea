/// The PAYLOAD_ENCODING_VERSION_0 requires payload to be encoded as follows
/// - begin with 32 byte header = [0x00, version byte 0, uint32 len of data, 0x00, 0x00,..., 0x00]
/// - followed by the encoded data [0x00, 31 bytes of data, 0x00, 31 bytes of data,...]
pub const PAYLOAD_ENCODING_VERSION_0: u8 = 0x0;
/// Number of fields for field element on bn254
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
/// Encoded payload header length in bytes (first field element)
pub const ENCODED_PAYLOAD_HEADER_LEN_BYTES: usize = 32;
