//! This module contains the [ExtendedHintType], which adds an AltDACommitment case to kona's [HintType] enum.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use alloy_primitives::{hex, Bytes};
use core::fmt::Display;
use kona_proof::{errors::HintParsingError, HintType};

/// A [ExtendedHint] is parsed in the format `<hint_type> <hint_data>`, where `<hint_type>` is a string that
/// represents the type of hint, and `<hint_data>` is the data associated with the hint (bytes
/// encoded as hex UTF-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedHint {
    /// The type of hint.
    pub hint_type: ExtendedHintType,
    /// The data associated with the hint.
    pub hint_data: Bytes,
}

impl ExtendedHint {
    /// Parses a hint from a string.
    pub fn parse(s: &str) -> Result<Self, HintParsingError> {
        let mut parts = s.split(' ').collect::<Vec<_>>();

        if parts.len() != 2 {
            return Err(HintParsingError(alloc::format!(
                "Invalid hint format: {}",
                s
            )));
        }

        let hint_type = ExtendedHintType::try_from(parts.remove(0))?;
        let hint_data = hex::decode(parts.remove(0))
            .map_err(|e| HintParsingError(e.to_string()))?
            .into();

        Ok(Self {
            hint_type,
            hint_data,
        })
    }

    /// Splits the [ExtendedHint] into its components.
    pub fn split(self) -> (ExtendedHintType, Bytes) {
        (self.hint_type, self.hint_data)
    }
}

/// The [ExtendedHintType] extends the [HintType] enum and is used to specify the type of hint that was received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExtendedHintType {
    Original(HintType),
    EigenDACommitment,
}

impl ExtendedHintType {
    /// Encodes the hint type as a string.
    pub fn encode_with(&self, data: &[&[u8]]) -> String {
        let concatenated = hex::encode(data.iter().copied().flatten().copied().collect::<Vec<_>>());
        alloc::format!("{} {}", self, concatenated)
    }
}

impl TryFrom<&str> for ExtendedHintType {
    type Error = HintParsingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "eigenda-commitment" => Ok(Self::EigenDACommitment),
            _ => Ok(Self::Original(HintType::try_from(value)?)),
        }
    }
}

impl From<ExtendedHintType> for &str {
    fn from(value: ExtendedHintType) -> Self {
        match value {
            ExtendedHintType::EigenDACommitment => "eigenda-commitment",
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
