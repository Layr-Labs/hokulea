pub mod steel;
pub mod noop;

use eigenda_v2_struct::EigenDAV2Cert;
use crate::cert_validity::CertValidity;

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
        cert_validity: CertValidity,
        eigenda_cert: EigenDAV2Cert,        
    );

}