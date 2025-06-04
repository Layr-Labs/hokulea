use alloc::string::String;

/// List of errors for verification of canoe proof using hokulea framework
/// Curerntly, all errors are specific to steel implementation except those marked with Sp1.
/// It is because Sp1 library panic as opposed to return an error, and also because
/// sp1 cannot take sp1-sdk as dependency which is needed for verification in non zkvm mode
#[derive(Debug, thiserror::Error)]
pub enum HokuleaCanoeVerificationError {
    /// Invalid Cert validity response
    #[error("When verifying outside of zkvm there is inconsistency between public journal proven by the zk proof and user supplied journal")]
    NonZKVMInconsistentPublicJournal,
    /// Invalid Cert validity response
    #[error("When verifying outside of zkvm the proof is missing")]
    NonZKVMMissingProof,
    /// Invalid Cert validity response. To avoid taking dep on specific zkVM error message, we convert them into string
    #[error("The verifier cannot verify the validity proof and the provided jounral: {0}")]
    InvalidProofAndJournal(String),
    /// unable to deserialize receipt
    #[error("Unable to deserialize receipt: {0}")]
    UnableToDeserializeReceipt(String),
    /// an invalid verification key for sp1
    #[error("Invalid verification key for Sp1")]
    InvalidVerificationKeyForSp1,
}
