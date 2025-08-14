use crate::canoe_verifier::{errors::HokuleaCanoeVerificationError, CanoeVerifier};
use crate::cert_validity::CertValidity;
use alloc::vec::Vec;
use eigenda_cert::AltDACommitment;
use tracing::info;

#[derive(Clone)]
pub struct CanoeNoOpVerifier {}

impl CanoeVerifier for CanoeNoOpVerifier {
    fn validate_cert_receipt(
        &self,
        _cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        _canoe_proof: Option<Vec<u8>>,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        info!("using CanoeNoOpVerifier");
        Ok(())
    }
}
