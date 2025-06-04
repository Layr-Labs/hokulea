use crate::canoe_verifier::{errors::HokuleaCanoeVerificationError, CanoeVerifier};
use crate::cert_validity::CertValidity;
use eigenda_v2_struct::EigenDAV2Cert;
use tracing::info;

#[derive(Clone)]
pub struct CanoeNoOpVerifier {}

impl CanoeVerifier for CanoeNoOpVerifier {
    fn validate_cert_receipt(
        &self,
        _cert_validity: CertValidity,
        _eigenda_cert: EigenDAV2Cert,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        info!("using CanoeNoOpVerifier");
        Ok(())
    }
}
