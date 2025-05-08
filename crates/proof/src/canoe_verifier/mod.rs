pub mod noop;
#[cfg(feature = "steel")]
pub mod steel;

use crate::cert_validity::CertValidity;
use alloy_primitives::{address, Address};
use eigenda_v2_struct::EigenDAV2Cert;
use tracing::info;

pub trait CanoeVerifier: Clone + Send + 'static {
    fn validate_cert_receipt(&self, _cert_validity: CertValidity, _eigenda_cert: EigenDAV2Cert) {
        info!("using default CanoeVerifier");
    }
}

pub const VERIFIER_ADDRESS: Address = address!("0x703848F4c85f18e3acd8196c8eC91eb0b7Bd0797");
