use crate::cert_validity::CertValidity;
use alloc::vec::Vec;

use eigenda_cert::AltDACommitment;

use alloc::string::String;
use tracing::warn;

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
    #[error("The verifier cannot verify the validity proof and the provided journal it can happen in both zk or non zkvm mode: {0}")]
    InvalidProofAndJournal(String),
    /// unable to deserialize receipt
    #[error("Non zkvm environment: unable to deserialize receipt: {0}")]
    UnableToDeserializeReceipt(String),
}

pub trait CanoeVerifier: Clone + Send + 'static {
    fn validate_cert_receipt(
        &self,
        _cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        _canoe_proof: Option<Vec<u8>>,
    ) -> Result<(), HokuleaCanoeVerificationError>;

    /// The function converts validity and altda commitment into journals.
    /// Journals are concatenated in a serialized byte array. The output of
    /// the serialization must be identical to one committed by zkVM.
    fn to_journals_bytes(
        &self,
        cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>,
    ) -> Vec<u8>;
}

#[derive(Clone)]
pub struct CanoeNoOpVerifier {}

impl CanoeVerifier for CanoeNoOpVerifier {
    fn validate_cert_receipt(
        &self,
        _cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        _canoe_proof: Option<Vec<u8>>,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        warn!("CanoeNoOpVerifier is unsafe for integration, and should only be used for testing purpose. It returns OK for everything and performs no checks.");
        Ok(())
    }

    fn to_journals_bytes(
        &self,
        _cert_validity_pairs: Vec<(AltDACommitment, CertValidity)>,
    ) -> Vec<u8> {
        Vec::new()
    }
}
