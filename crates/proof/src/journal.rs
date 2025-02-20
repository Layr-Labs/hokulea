use alloy_primitives::B256;
use alloy_rlp::{RlpDecodable, RlpEncodable};
use eigenda_v2_struct_rust::EigenDAV2Cert;

/// CertValidityJournal is a data structure committed by zkvm guest code, that comes with
/// corresponding zk proof attesting its validity
#[derive(PartialEq, Eq, Ord, PartialOrd, Clone, Copy, Debug, RlpEncodable, RlpDecodable)]
pub struct CertValidityJournal {
    /// indicate if cert is honest
    pub is_valid: bool,
    /// the hash digest of Cert
    pub cert_digest: B256,
}

impl CertValidityJournal {
    pub fn new(is_valid: bool, cert: EigenDAV2Cert) -> Self {
        Self {
            is_valid,
            cert_digest: cert.digest(),
        }
    }
}
