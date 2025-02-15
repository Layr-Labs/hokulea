use alloy_primitives::{Bytes, U256};
use crate::eigenda_blob_witness::EigenDABlobWitnessData;
use eigenda_v2_struct_rust::EigenDAV2Cert;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_verifier::batch;
use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use tracing::info;

/// PreloadedEigenDABlobProvider ensures the following invariants
/// (V1) Given a cert is valid, then blob and the commitment in the cert must be consistent
/// (V2) Given a cert is invalid, then blob must be empty
#[derive(Clone, Debug, Default)]
pub struct PreloadedEigenDABlobProvider {
    /// The tuple contains EigenDAV2Cert, Blob, isValid cert.
    pub entries: Vec<(EigenDAV2Cert, Bytes, bool)>,
}

impl From<EigenDABlobWitnessData> for PreloadedEigenDABlobProvider {
    fn from(value: EigenDABlobWitnessData) -> Self {
        let mut blobs = vec![];
        let mut proofs =  vec![];
        let mut commitments = vec![];

        let mut entries = vec![];

        for i in 0..blobs.len() {
            if value.is_valid[i] {
                blobs.push(value.eigenda_blobs[i].clone());
                proofs.push(value.proofs[i].clone());
                let commitment = value.eigenda_certs[i].blob_inclusion_info.blob_certificate.blob_header.commitment.commitment;
                commitments.push((commitment.x, commitment.y));
            } else {
                // check (V2) if cert is not valie, the blob must be empty
                assert!(value.eigenda_blobs[i].len() == 0);
            }
            entries.push((value.eigenda_certs[i].clone(), value.eigenda_blobs[i].clone(), value.is_valid[i]));
        }

        // check (V1) if cert is not valie, the blob must be empty, assert that commitments in the cert and blobs are consistent
        assert!(batch_verify(blobs, commitments, proofs));

        PreloadedEigenDABlobProvider {
            entries: entries,
        }
    }
}

/// Eventually, rust-kzg-bn254 would provide a nice interface that takes
/// bytes input, so that we can remove this wrapper. For now, just include it here
pub fn batch_verify(eigenda_blobs: Vec<Bytes>, commitments: Vec<(U256, U256)>, proofs: Vec<Bytes>) -> bool {
    info!("lib_blobs len {:?}", eigenda_blobs.len());
    // transform to rust-kzg-bn254 inputs types
    // TODO should make library do the parsing the return result
    let lib_blobs: Vec<Blob> = eigenda_blobs.iter().map(|b| Blob::new(b)).collect();
    let lib_commitments: Vec<G1Affine> = commitments
        .iter()
        .map(|c| {
            let a: [u8; 32] = c.0.to_be_bytes();
            let b: [u8; 32] = c.1.to_be_bytes();
            let x = Fq::from_be_bytes_mod_order(&a);
            let y = Fq::from_be_bytes_mod_order(&b);
            G1Affine::new(x, y)
        })
        .collect();
    let lib_proofs: Vec<G1Affine> = proofs
        .iter()
        .map(|p| {
            let x = Fq::from_be_bytes_mod_order(&p[..32]);
            let y = Fq::from_be_bytes_mod_order(&p[32..64]);

            G1Affine::new(x, y)
        })
        .collect();
    let pairing_result = batch::verify_blob_kzg_proof_batch(&lib_blobs, &lib_commitments, &lib_proofs).unwrap();

    pairing_result
}
