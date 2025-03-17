//! This module generate da cert view proof using risc0 steel
use eigenda_v2_struct_rust::EigenDAV2Cert;
use risc0_zkvm::Receipt;

/// compute view proof using Steel
/// The higher level call should call each steel
pub fn compute_view_proof_steel(_cert: &EigenDAV2Cert) -> Receipt {
    unimplemented!()
}
