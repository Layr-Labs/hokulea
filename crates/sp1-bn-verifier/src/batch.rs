//! `verify_blob_kzg_proof_batch` — substrate-bn / sp1-patches port.
//!
//! See `rust-kzg-bn254-verifier::batch` for the arkworks-flavoured original this is portable
//! against. The batched pairing equation follows the EIP-4844 / Deneb spec:
//!
//! ```text
//! e(Σ rᵢ · proofᵢ, [τ]) = e(Σ rᵢ · (Cᵢ - [yᵢ]) + Σ rᵢ · zᵢ · proofᵢ, [1])
//! ```
//!
//! where `r` is the Fiat-Shamir random challenge derived from the transcript of all
//! `(commitment, z, y, proof, blob_length)` tuples.

extern crate alloc;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use alloy_primitives::FixedBytes;
use eigenda_cert::G1Point;
use substrate_bn::{AffineG1, AffineG2, Fr, Group, G1};

use crate::consts::{BYTES_PER_FIELD_ELEMENT, RANDOM_CHALLENGE_KZG_BATCH_DOMAIN};
use crate::errors::KzgError;
use crate::helpers::{
    compute_challenges_and_evaluate_polynomial, compute_powers, g1_lincomb, g2_tau,
    hash_to_field_element, pairings_verify, serialize_fr_le, serialize_g1_compressed,
    to_fr_array_canonical, usize_to_be_bytes, validate_g1_point, PolynomialEvalForm,
};

/// Convert `(x, y) ∈ U256²` (big-endian-encoded coordinates from `eigenda-cert::G1Point`) into
/// a substrate-bn affine point. Performs full curve + subgroup validation.
fn g1_point_to_affine(commitment: &G1Point) -> Result<AffineG1, KzgError> {
    let x_bytes: [u8; 32] = commitment.x.to_be_bytes();
    let y_bytes: [u8; 32] = commitment.y.to_be_bytes();
    let x = substrate_bn::Fq::from_be_bytes_mod_order(&x_bytes)
        .map_err(|_| KzgError::SerializationError)?;
    let y = substrate_bn::Fq::from_be_bytes_mod_order(&y_bytes)
        .map_err(|_| KzgError::SerializationError)?;
    let affine = AffineG1::new(x, y)
        .map_err(|_| KzgError::NotOnCurveError("commitment not on curve".to_string()))?;
    Ok(affine)
}

/// Convert a 64-byte big-endian (X || Y) proof encoding into a substrate-bn affine point with
/// curve + subgroup validation.
fn proof_bytes_to_affine(proof: &FixedBytes<64>) -> Result<AffineG1, KzgError> {
    let x = substrate_bn::Fq::from_be_bytes_mod_order(&proof[..32])
        .map_err(|_| KzgError::SerializationError)?;
    let y = substrate_bn::Fq::from_be_bytes_mod_order(&proof[32..])
        .map_err(|_| KzgError::SerializationError)?;
    let affine = AffineG1::new(x, y)
        .map_err(|_| KzgError::NotOnCurveError("proof not on curve".to_string()))?;
    Ok(affine)
}

/// Top-level entry: matches the contract of `crate::preloaded_eigenda_provider::batch_verify` in
/// hokulea-proof, but uses substrate-bn (sp1-patches) instead of arkworks.
///
/// `blobs[i]` is the raw blob bytes (length must be a multiple of 32 and each chunk a canonical
/// field element). `commitments[i]` is the KZG commitment as `(x, y)` BE-encoded U256s, and
/// `proofs[i]` is the 64-byte BE-encoded `(x, y)` proof point.
pub fn batch_verify(
    blobs: impl Iterator<Item = impl AsRef<[u8]>>,
    commitments: impl Iterator<Item = G1Point>,
    proofs: impl Iterator<Item = FixedBytes<64>>,
) -> bool {
    verify_blob_kzg_proof_batch(blobs, commitments, proofs).unwrap_or(false)
}

/// Verbose result variant of [`batch_verify`].
pub fn verify_blob_kzg_proof_batch(
    blobs: impl Iterator<Item = impl AsRef<[u8]>>,
    commitments: impl Iterator<Item = G1Point>,
    proofs: impl Iterator<Item = FixedBytes<64>>,
) -> Result<bool, KzgError> {
    let polys: Vec<PolynomialEvalForm> = blobs
        .map(|b| PolynomialEvalForm::new(to_fr_array_canonical(b.as_ref())?))
        .collect::<Result<Vec<_>, KzgError>>()?;

    // The empty batch is vacuously valid. Short-circuit before calling into substrate-bn:
    // `AffineG1::msm` panics on a zero-length slice, and the reference verifier accepts
    // the empty case (the equation `e(0, [τ]) = e(0, G)` is `1 = 1`).
    if polys.is_empty() {
        return Ok(true);
    }

    let commitments_aff: Vec<AffineG1> = commitments
        .map(|c| g1_point_to_affine(&c))
        .collect::<Result<Vec<_>, _>>()?;
    let proofs_aff: Vec<AffineG1> = proofs
        .map(|p| proof_bytes_to_affine(&p))
        .collect::<Result<Vec<_>, _>>()?;

    if commitments_aff.len() != polys.len() || proofs_aff.len() != polys.len() {
        return Err(KzgError::GenericError(
            "length's of the input are not the same".to_string(),
        ));
    }

    let (zs, ys) = compute_challenges_and_evaluate_polynomial(&polys, &commitments_aff)?;

    // Per-blob padded polynomial length, in field elements. The FS transcript binds these,
    // so a verifier hands the prover a transcript that depends on each blob's length.
    let blob_lengths: Vec<u64> = polys.iter().map(|poly| poly.len() as u64).collect();

    verify_kzg_proof_batch(&commitments_aff, &zs, &ys, &proofs_aff, &blob_lengths)
}

/// Compute powers `[r⁰, r¹, …, rⁿ⁻¹]` of the Fiat-Shamir batch challenge.
fn compute_r_powers(
    commitments: &[AffineG1],
    zs: &[Fr],
    ys: &[Fr],
    proofs: &[AffineG1],
    blob_lengths: &[u64],
) -> Result<Vec<Fr>, KzgError> {
    let n = commitments.len();

    let initial_data_length: usize = 40;
    let input_size = initial_data_length
        + n * (BYTES_PER_FIELD_ELEMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_FIELD_ELEMENT + 8);
    let mut buf: Vec<u8> = vec![0u8; input_size];

    // Domain separator (24 bytes) + n (8 bytes).
    buf[0..24].copy_from_slice(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN);
    let n_bytes = usize_to_be_bytes(n);
    buf[32..40].copy_from_slice(&n_bytes);

    // Per-blob lengths slot in [24 .. 24 + 8n].
    let target_slice = &mut buf[24..24 + (n * 8)];
    for (chunk, &length) in target_slice.chunks_mut(8).zip(blob_lengths) {
        chunk.copy_from_slice(&length.to_be_bytes());
    }

    let mut offset = 40 + n * 8;
    for i in 0..n {
        // commitment
        let v = serialize_g1_compressed(&commitments[i]);
        buf[offset..offset + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&v);
        offset += BYTES_PER_FIELD_ELEMENT;

        // z
        let v = serialize_fr_le(&zs[i]);
        buf[offset..offset + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&v);
        offset += BYTES_PER_FIELD_ELEMENT;

        // y
        let v = serialize_fr_le(&ys[i]);
        buf[offset..offset + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&v);
        offset += BYTES_PER_FIELD_ELEMENT;

        // proof
        let v = serialize_g1_compressed(&proofs[i]);
        buf[offset..offset + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&v);
        offset += BYTES_PER_FIELD_ELEMENT;
    }

    if offset != input_size {
        return Err(KzgError::InvalidInputLength);
    }

    let r = hash_to_field_element(&buf);
    Ok(compute_powers(&r, n))
}

fn verify_kzg_proof_batch(
    commitments: &[AffineG1],
    zs: &[Fr],
    ys: &[Fr],
    proofs: &[AffineG1],
    blob_lengths: &[u64],
) -> Result<bool, KzgError> {
    if !(commitments.len() == zs.len() && zs.len() == ys.len() && ys.len() == proofs.len()) {
        return Err(KzgError::GenericError(
            "length's of the input are not the same".to_string(),
        ));
    }

    for c in commitments {
        validate_g1_point(&(*c).into())?;
    }
    for p in proofs {
        validate_g1_point(&(*p).into())?;
    }

    let n = commitments.len();
    let r_powers = compute_r_powers(commitments, zs, ys, proofs, blob_lengths)?;

    // Σ rᵢ · proofᵢ
    let proof_lincomb = g1_lincomb(proofs, &r_powers)?;

    // Build [Cᵢ - yᵢ·G] in affine, plus rᵢ·zᵢ scalars.
    let g = G1::one();
    let mut c_minus_y: Vec<AffineG1> = Vec::with_capacity(n);
    let mut r_times_z: Vec<Fr> = Vec::with_capacity(n);
    for i in 0..n {
        let ys_encrypted: G1 = g * ys[i];
        let ci_jac: G1 = commitments[i].into();
        let diff: G1 = ci_jac - ys_encrypted;
        // The diff is on the curve and in the subgroup; converting to affine cannot fail except
        // for the identity, which we permit.
        let diff_aff = if diff.is_zero() {
            AffineG1::default() // sentinel; the matching scalar from r_powers may be non-zero,
                                // but msm of identity-with-anything is identity.
        } else {
            AffineG1::from_jacobian(diff).expect("diff has an affine representation")
        };
        c_minus_y.push(diff_aff);
        r_times_z.push(r_powers[i] * zs[i]);
    }

    let proof_z_lincomb = g1_lincomb(proofs, &r_times_z)?;
    let c_minus_y_lincomb = g1_lincomb(&c_minus_y, &r_powers)?;

    let rhs_g1 = c_minus_y_lincomb + proof_z_lincomb;

    // Pairing check: e(proof_lincomb, [τ]G2) =? e(rhs_g1, G2_generator)
    let g2_one: substrate_bn::G2 = AffineG2::one().into();
    Ok(pairings_verify(proof_lincomb, g2_tau(), rhs_g1, g2_one))
}
