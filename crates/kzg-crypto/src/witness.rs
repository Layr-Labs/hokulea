extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::Bytes;
use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_prover::kzg::KZG;
use rust_kzg_bn254_prover::srs::SRS;
use rust_kzg_bn254_verifier::batch;
use tracing::info;
use num::BigUint;
use rust_kzg_bn254_primitives::errors::KzgError;

/// stores  
#[derive(Debug, Clone, Default)]
pub struct EigenDABlobWitness {
    pub eigenda_blobs: Vec<Bytes>,
    pub commitments: Vec<Bytes>,
    pub proofs: Vec<Bytes>,
}

/// 
impl EigenDABlobWitness {
    pub fn new() -> Self {
        EigenDABlobWitness {
            eigenda_blobs: Vec::new(),
            commitments: Vec::new(),
            proofs: Vec::new(),
        }
    }

    /// This function computes a witness for a eigenDA blob
    /// nitro code https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L141
    /// could refactor in the future, such that both host and client can compute the proof
    pub fn push_witness(&mut self, blob: &[u8]) -> Result<(), KzgError> {
        // TODO remove the need for G2 access
        // Add command line to specify where are g1 and g2 path
        // In the future, it might make sense to let the proxy to return such
        // value, instead of local computation
        let srs = SRS::new("resources/g1.32mb.point", 268435456, 1024).unwrap();
        let mut kzg = KZG::new();

        let input = Blob::new(blob);
        let input_poly = input.to_polynomial_eval_form();

        kzg.calculate_and_store_roots_of_unity(blob.len() as u64).unwrap();

        let mut commitment_bytes = vec![0u8; 0];

        let commitment = kzg.commit_eval_form(&input_poly, &srs)?;

        // TODO the library should have returned the bytes, or provide a helper
        // for conversion. For both proof and commitment
        let commitment_x_bigint: BigUint = commitment.x.into();
        let commitment_y_bigint: BigUint = commitment.y.into();

        append_left_padded_biguint_be(&mut commitment_bytes, &commitment_x_bigint);
        append_left_padded_biguint_be(&mut commitment_bytes, &commitment_y_bigint);

        let mut proof_bytes = vec![0u8; 0];

        let proof = kzg.compute_blob_proof(&input, &commitment, &srs)?;
        let proof_x_bigint: BigUint = proof.x.into();
        let proof_y_bigint: BigUint = proof.y.into();

        append_left_padded_biguint_be(&mut proof_bytes, &proof_x_bigint);
        append_left_padded_biguint_be(&mut proof_bytes, &proof_y_bigint);

        // push data into witness
        self.write(Bytes::copy_from_slice(blob), Bytes::copy_from_slice(&commitment_bytes), proof_bytes.into());

        Ok(())
    }

    pub fn write(&mut self, blob: Bytes, commitment: Bytes, proof: Bytes) {
        self.eigenda_blobs.push(blob);
        self.commitments.push(commitment);
        self.proofs.push(proof);
        info!("added a blob");
    }

    pub fn batch_verify(&self) -> bool {
        info!("lib_blobs len {:?}", self.eigenda_blobs.len());

        // transform to rust-kzg-bn254 inputs types
        // TODO should make library do the parsing the return result
        let lib_blobs: Vec<Blob> = self.eigenda_blobs.iter().map(|b| Blob::new(b)).collect();
        let lib_commitments: Vec<G1Affine> = self
            .commitments
            .iter()
            .map(|c| {
                let x = Fq::from_be_bytes_mod_order(&c[..32]);
                let y = Fq::from_be_bytes_mod_order(&c[32..64]);
                G1Affine::new(x, y)
            })
            .collect();
        let lib_proofs: Vec<G1Affine> = self
            .proofs
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
}


/// This function convert a BigUint into 32Bytes vector in big endian format
pub fn append_left_padded_biguint_be(vec: &mut Vec<u8>, biguint: &BigUint) {
    let bytes = biguint.to_bytes_be();
    let padding = 32 - bytes.len();
    vec.extend(std::iter::repeat(0).take(padding));
    vec.extend_from_slice(&bytes);
}