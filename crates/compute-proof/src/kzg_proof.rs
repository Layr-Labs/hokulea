//! This is a crate for generating a kzg proof for an eigenda blob. In the future,
//! such proof is carried inside the blob header. Then it can be removed. This crate access filesystem,
//! cannot be used in any fault proof or zk vm.
use alloy_primitives::Bytes;
use num::BigUint;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_primitives::errors::KzgError;
use rust_kzg_bn254_prover::kzg::KZG;
use rust_kzg_bn254_prover::srs::SRS;
use spin::Lazy;

/// load srs points
pub static G1_SRS: Lazy<SRS> = Lazy::new(load_g1_srs);

fn load_g1_srs() -> SRS {
    let srs_file_path = "resources/g1.point";
    // In the future, it might make sense to let the proxy to return kzg proof, instead of local computation
    SRS::new(srs_file_path, 268435456, 524288)
        .unwrap_or_else(|err| panic!("Failed to load SRS file {}: {}", srs_file_path, err))
}

/// This function computes a KZG proof for a eigenDA blob
/// nitro code <https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L141>
/// could refactor in the future, such that both host and client can compute the proof
pub fn compute_kzg_proof(encoded_payload: &[u8]) -> Result<Bytes, KzgError> {
    compute_kzg_proof_with_srs(encoded_payload, &G1_SRS)
}

/// This function computes a KZG proof for a eigenDA blob
/// nitro code <https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L141>
/// could refactor in the future, such that both host and client can compute the proof
pub fn compute_kzg_proof_with_srs(encoded_payload: &[u8], srs: &SRS) -> Result<Bytes, KzgError> {
    let mut kzg = KZG::new();
    kzg.calculate_and_store_roots_of_unity(encoded_payload.len() as u64)
        .unwrap();

    // The encoded payload is a polynomial presented in its evaluation form
    let blob = Blob::new(encoded_payload).expect("should be able to construct a blob");
    let input_poly = blob.to_polynomial_eval_form();

    let commitment = kzg.commit_eval_form(&input_poly, srs)?;

    let proof = kzg.compute_blob_proof(&blob, &commitment, srs)?;
    let proof_x_bigint: BigUint = proof.x.into();
    let proof_y_bigint: BigUint = proof.y.into();

    let proof_x_bytes = convert_biguint_to_be_32_bytes(&proof_x_bigint);
    let proof_y_bytes = convert_biguint_to_be_32_bytes(&proof_y_bigint);

    let mut proof_bytes = proof_x_bytes.to_vec();
    proof_bytes.extend_from_slice(&proof_y_bytes);

    // push data into witness
    Ok(proof_bytes.into())
}

/// This function convert a BigUint into 32Bytes vector in big endian format
//pub fn append_left_padded_biguint_be(vec: &mut Vec<u8>, biguint: &BigUint) {
pub fn convert_biguint_to_be_32_bytes(biguint: &BigUint) -> [u8; 32] {
    let mut output = [0; 32];
    let be_bytes = biguint.to_bytes_be();
    let padding = 32 - be_bytes.len();
    output[padding..].copy_from_slice(&be_bytes);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_biguint_to_be_32_bytes() {
        // most significant bit 1
        let a = vec![129, 255];
        let a_biguint = BigUint::from_bytes_be(&a);
        let out_a = convert_biguint_to_be_32_bytes(&a_biguint);

        let mut expected = vec![0u8; 30];
        expected.extend_from_slice(&a);
        assert_eq!(&out_a[..], &expected[..]);

        // most significant bit 0 of 2 bytes are 0
        let a = vec![1; 32];
        let a_biguint = BigUint::from_bytes_be(&a);
        let out_a = convert_biguint_to_be_32_bytes(&a_biguint);

        let expected = a;
        assert_eq!(&out_a[..], &expected[..]);
    }
}
