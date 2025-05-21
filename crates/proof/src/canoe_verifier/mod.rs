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

// This is the cert verifier that canoe provider and verifier are run against.
// In hokulea repo, there is a mock contract under canoe directory, which can be
// deployed to generate the address and test functionality.
pub const VERIFIER_ADDRESS: Address = address!("0xb4B46bdAA835F8E4b4d8e208B6559cD267851051");
