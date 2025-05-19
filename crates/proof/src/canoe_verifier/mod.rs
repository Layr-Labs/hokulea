pub mod noop;
#[cfg(feature = "steel")]
pub mod steel;

#[cfg(feature = "sp1-cc")]
pub mod sp1_cc;

use crate::cert_validity::CertValidity;
use alloy_primitives::{address, Address};
use eigenda_v2_struct::EigenDAV2Cert;
use tracing::info;

pub trait CanoeVerifier: Clone + Send + 'static {
    fn validate_cert_receipt(&self, _cert_validity: CertValidity, _eigenda_cert: EigenDAV2Cert) {
        info!("using default CanoeVerifier");
    }
}

// changed in each contarct deployment
pub const VERIFIER_ADDRESS: Address = address!("0x17435ccE3d1B4fA2e5f8A08eD921D57C6762A180");
