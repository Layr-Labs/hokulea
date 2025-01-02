/// This minimal blob encoding contains a 32 byte header = [0x00, version byte, uint32 len of data, 0x00, 0x00,...]
/// followed by the encoded data [0x00, 31 bytes of data, 0x00, 31 bytes of data,...]
pub const BLOB_ENCODING_VERSION_0: u8 = 0x0;
