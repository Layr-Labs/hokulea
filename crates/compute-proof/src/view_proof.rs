//! This is the crate for generating the view proof for a da cert.
use crate::steel;
use eigenda_v2_struct_rust::EigenDAV2Cert;
use risc0_zkvm::Receipt;

/// This function computes view proof. The proof either shows the cert is valid or invalid
/// TODO abstract away Reciept to make it
/// generic to multiple zkVM
pub fn compute_view_proof(cert: &EigenDAV2Cert) -> Receipt {
    steel::compute_view_proof_steel(cert)
}
