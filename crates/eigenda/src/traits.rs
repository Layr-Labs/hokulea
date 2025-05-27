use crate::errors::HokuleaErrorKind;
use crate::AltDACommitment;
use alloc::{boxed::Box, string::ToString};
use async_trait::async_trait;
use core::fmt::Display;
use rust_kzg_bn254_primitives::blob::Blob;

/// A trait for providing EigenDA blobs.
/// TODO: add explanation for why we need this to be a trait.
#[async_trait]
pub trait EigenDABlobProvider {
    /// The error type for the [EigenDABlobProvider].
    type Error: Display + ToString + Into<HokuleaErrorKind>;

    /// Query preimage about the validity of a DA cert. Return error when cert is invalid, or generic preimage error
    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error>;

    /// Fetches eigenda blob. The returned blob must contain a number of field elements that is power of 2
    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error>;
}

/// The index where INTERFACE_BYTE is located
/// More see <https://github.com/Layr-Labs/hokulea/tree/master/docs#reserved-addresses-for-da-certificates>
pub const RESERVED_INTERFACE_BYTE_INDEX: usize = 0x20;

/// In the address space of preimage oracle, which interface type a validity query is addressed at
/// More see <https://github.com/Layr-Labs/hokulea/tree/master/docs#reserved-addresses-for-da-certificates>
pub const RESERVED_INTERFACE_BYTE_FOR_VALIDITY: u8 = 0x01;

/// In the address space of preimage oracle, which interface type a recency query is addressed at
/// More see <https://github.com/Layr-Labs/hokulea/tree/master/docs#reserved-addresses-for-da-certificates>
pub const RESERVED_INTERFACE_BYTE_FOR_RECENCY: u8 = 0x02;
