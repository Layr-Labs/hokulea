use alloc::string::String;

/// Custom hokulea preimage error
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
}
