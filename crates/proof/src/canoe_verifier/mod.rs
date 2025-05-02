pub mod noop;
#[cfg(feature = "steel")]
pub mod steel;

use eigenda_v2_struct::EigenDAV2Cert;
use crate::cert_validity::CertValidity;
use tracing::info;

use alloy_sol_types::sol;

sol! {
    struct Journal {
        address contract;
        bytes input;        
        // add chain spec    
    }
}

pub trait CanoeVerifier: Clone + Send + 'static {    

    fn validate_cert_receipt(
        &self,        
        _cert_validity: CertValidity,
        _eigenda_cert: EigenDAV2Cert,        
    ) {
        info!("using default CanoeVerifier");
    }

}