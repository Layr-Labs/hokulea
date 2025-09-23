use crate::{errors::HokuleaErrorKind, EncodedPayload};
use alloc::{boxed::Box, string::ToString};
use async_trait::async_trait;
use core::fmt::Display;
use eigenda_cert::AltDACommitment;

/// This traits defines functions to access preimage oracle for EigenDA blob derivation. See
/// <https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#derivation-process>
#[async_trait]
pub trait EigenDAPreimageProvider {
    /// The error type for the [EigenDAPreimageProvider].
    type Error: Display + ToString + Into<HokuleaErrorKind>;

    /// Fetch primage about the recency window. To be future compatible when recency window can be a function
    /// of reference block number stored inside AltDACommitment.
    async fn get_recency_window(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<u64, Self::Error>;

    /// Fetch preimage about the validity of a DA cert. Return generic preimage error. Return false when
    /// DA cert is invalid. True if it is valid.
    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error>;

    /// Fetch the encoded payloads from the altda commitment
    /// The encoded payload size is always a power of 2, with a minimum of 32 bytes.
    /// (e.g., 32, 64, 128, 256, 512, ... bytes)
    async fn get_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<EncodedPayload, Self::Error>;
}

/// The index where INTERFACE_BYTE is located
/// More see <https://github.com/Layr-Labs/hokulea/tree/master/docs#reserved-addresses-for-da-certificates>
pub const RESERVED_EIGENDA_API_BYTE_INDEX: usize = 32;

/// In the address space of preimage oracle, which interface type a validity query is addressed at
/// More see <https://github.com/Layr-Labs/hokulea/tree/master/docs#reserved-addresses-for-da-certificates>
pub const RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY: u8 = 1;

/// In the address space of preimage oracle, which interface type a recency query is addressed at
/// More see <https://github.com/Layr-Labs/hokulea/tree/master/docs#reserved-addresses-for-da-certificates>
pub const RESERVED_EIGENDA_API_BYTE_FOR_RECENCY: u8 = 2;
