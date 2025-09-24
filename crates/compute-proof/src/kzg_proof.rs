//! This is a crate for generating a kzg proof for an eigenda blob. In the future,
//! such proof is carried inside the blob header. Then it can be removed. This crate access filesystem,
//! cannot be used in any fault proof or zk vm.
extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::Bytes;
use num::BigUint;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_primitives::errors::KzgError;
use rust_kzg_bn254_prover::kzg::KZG;
use rust_kzg_bn254_prover::srs::SRS;

/// This function computes a KZG proof for a eigenDA blob
/// nitro code <https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L141>
/// could refactor in the future, such that both host and client can compute the proof
pub fn compute_kzg_proof(encoded_payload: &[u8]) -> Result<Bytes, KzgError> {
    let srs_file_path = "resources/g1.point";
    // In the future, it might make sense to let the proxy to return kzg proof, instead of local computation
    let srs = SRS::new(srs_file_path, 268435456, 524288)
        .unwrap_or_else(|err| panic!("Failed to load SRS file {}: {}", srs_file_path, err));
    let mut kzg = KZG::new();

    // The encoded payload is a polynomial presented in its evaluation form
    let input = Blob::new(encoded_payload).expect("should be able to construct a blob");
    let input_poly = input.to_polynomial_eval_form();

    kzg.calculate_and_store_roots_of_unity(encoded_payload.len() as u64)
        .unwrap();

    let mut commitment_bytes = vec![0u8; 0];

    let commitment = kzg.commit_eval_form(&input_poly, &srs)?;

    // TODO the rust bn254 library should have returned the bytes, or provide a helper
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
    Ok(proof_bytes.into())
}

/// This function convert a BigUint into 32Bytes vector in big endian format
pub fn append_left_padded_biguint_be(vec: &mut Vec<u8>, biguint: &BigUint) {
    let bytes = biguint.to_bytes_be();
    let padding = 32 - bytes.len();
    vec.extend(std::iter::repeat_n(0, padding));
    vec.extend_from_slice(&bytes);
}
