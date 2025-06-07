use crate::canoe_verifier::{errors::HokuleaCanoeVerificationError, CanoeVerifier};
use crate::cert_validity::CertValidity;
use eigenda_cert::AltDACommitment;
use tracing::info;

#[derive(Clone)]
pub struct CanoeNoOpVerifier {}

impl CanoeVerifier for CanoeNoOpVerifier {
    fn validate_cert_receipt(
        &self,
        _cert_validity: CertValidity,
        _altda_commitment: AltDACommitment,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        info!("using CanoeNoOpVerifier");
        Ok(())
    }
}
