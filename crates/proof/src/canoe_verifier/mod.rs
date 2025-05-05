pub mod noop;
#[cfg(feature = "steel")]
pub mod steel;

use eigenda_v2_struct::EigenDAV2Cert;
use crate::cert_validity::CertValidity;
use tracing::info;
use alloy_primitives::{Address, address};

pub trait CanoeVerifier: Clone + Send + 'static {    

    fn validate_cert_receipt(
        &self,        
        _cert_validity: CertValidity,
        _eigenda_cert: EigenDAV2Cert,        
    ) {
        info!("using default CanoeVerifier");
        
    }

}

pub const VERIFIER_ADDRESS: Address = address!("0xb4B46bdAA835F8E4b4d8e208B6559cD267851051");