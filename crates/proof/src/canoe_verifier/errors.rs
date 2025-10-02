use alloc::string::String;

/// List of errors for verification of canoe proof using hokulea framework
/// Currently, all errors are specific to steel implementation except those marked with Sp1.
/// It is because Sp1 library panic as opposed to return an error, and also because
/// sp1 cannot take sp1-sdk as dependency which is needed for verification in non zkvm mode
#[derive(Debug, thiserror::Error)]
pub enum HokuleaCanoeVerificationError {
    #[error("Non zkvm environment: inconsistency between public journal proven by the zk proof and user supplied journal")]
    InconsistentPublicJournal,
    #[error("Non zkvm environment: proof is missing")]
    MissingProof,
    /// Invalid Cert validity response. To avoid taking dep on specific zkVM error message, we convert them into string
    #[error("The verifier cannot verify the validity proof and the provided jounral it can happen in both zk or non zkvm mode: {0}")]
    InvalidProofAndJournal(String),
    /// unable to deserialize receipt
    #[error("Non zkvm environment: unable to deserialize receipt: {0}")]
    UnableToDeserializeReceipt(String),
}
