//! This module contains the [ExtendedHintType], which adds an EigenDACommitment case to kona's [HintType] enum.

use alloc::{string::String, vec::Vec};
use alloy_primitives::hex;
use core::fmt::Display;
use kona_proof::{errors::HintParsingError, HintType};

use alloc::str::FromStr;

/// The [ExtendedHintType] extends the [HintType] enum and is used to specify the type of hint that was received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExtendedHintType {
    Original(HintType),
    EigenDACert,
}

impl ExtendedHintType {
    /// Encodes the hint type as a string.
    pub fn encode_with(&self, data: &[&[u8]]) -> String {
        let concatenated = hex::encode(data.iter().copied().flatten().copied().collect::<Vec<_>>());
        alloc::format!("{} {}", self, concatenated)
    }
}

impl FromStr for ExtendedHintType {
    type Err = HintParsingError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "eigenda-certificate" => Ok(Self::EigenDACert),

            _ => Ok(Self::Original(HintType::from_str(value)?)),
        }
    }
}

impl From<ExtendedHintType> for &str {
    fn from(value: ExtendedHintType) -> Self {
        match value {
            ExtendedHintType::EigenDACert => "eigenda-certificate",
            ExtendedHintType::Original(hint_type) => hint_type.into(),
        }
    }
}

impl Display for ExtendedHintType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s: &str = (*self).into();
        write!(f, "{}", s)
    }
}
