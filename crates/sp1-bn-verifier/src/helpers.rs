//! Field/group helpers used by the batch verifier.
//!
//! Where the reference crate (`rust-kzg-bn254-primitives::helpers`) reaches
//! for `arkworks` types, we use `substrate-bn` here. Encodings on the wire
//! (Fiat-Shamir transcript bytes, blob byte layout) are kept identical to the
//! reference implementation so transcripts are interchangeable.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use sha2::{Digest, Sha256};
use substrate_bn::{pairing_batch, AffineG1, Fq, Fr, Group, Gt, G1, G2};

use crate::consts::{
    get_primitive_root_of_unity, BYTES_PER_FIELD_ELEMENT, FIAT_SHAMIR_PROTOCOL_DOMAIN, G2_TAU,
    MAINNET_SRS_G1_SIZE, SIZE_OF_G1_AFFINE_COMPRESSED,
};
use crate::errors::KzgError;

/// Big-endian length-8 encoding of a `usize`, matching
/// `rust_kzg_bn254_primitives::helpers::usize_to_be_bytes`.
pub fn usize_to_be_bytes(number: usize) -> [u8; 8] {
    (number as u64).to_be_bytes()
}

/// Hash an arbitrary byte slice into an `Fr` via SHA-256, reducing modulo the scalar field order.
pub fn hash_to_field_element(msg: &[u8]) -> Fr {
    let digest = Sha256::digest(msg);
    Fr::from_bytes_be_mod_order(digest.as_ref())
        .expect("SHA-256 digest is 32 bytes, always valid for Fr::from_bytes_be_mod_order")
}

/// Compute `[base^0, base^1, ..., base^(count-1)]`.
pub fn compute_powers(base: &Fr, count: usize) -> Vec<Fr> {
    let mut powers = Vec::with_capacity(count);
    let mut current = Fr::one();
    for _ in 0..count {
        powers.push(current);
        current = current * *base;
    }
    powers
}

/// Validate `point` is on the curve and in the correct subgroup. The point at infinity is
/// accepted (matching the arkworks-based reference, which treats `is_on_curve` as `true` for
/// the identity element).
pub fn validate_g1_point(point: &G1) -> Result<(), KzgError> {
    if point.is_zero() {
        return Ok(());
    }
    AffineG1::from_jacobian(*point)
        .ok_or_else(|| KzgError::NotOnCurveError("g1 point not on curve".to_string()))?;
    Ok(())
}

/// Multi-scalar multiplication: `Σ scalars[i] * points[i]`.
pub fn g1_lincomb(points: &[AffineG1], scalars: &[Fr]) -> Result<G1, KzgError> {
    if points.len() != scalars.len() {
        return Err(KzgError::GenericError(
            "g1_lincomb: points and scalars have mismatched lengths".to_string(),
        ));
    }
    Ok(AffineG1::msm(points, scalars).into())
}

/// Two-pairing check: returns `true` iff `e(a1, a2) == e(b1, b2)`.
///
/// Implemented as a single multi-pairing `e(a1, a2) * e(-b1, b2) == 1`.
pub fn pairings_verify(a1: G1, a2: G2, b1: G1, b2: G2) -> bool {
    let result = pairing_batch(&[(a1, a2), (-b1, b2)]);
    result == Gt::one()
}

/// Encode an `Fq` as 32 little-endian bytes — the wire format used by `arkworks`'s
/// `CanonicalSerialize` for an Fp element. `Fq::to_big_endian` writes the canonical
/// (non-Montgomery) value, which is what we need.
fn fq_to_le_bytes(value: &Fq) -> [u8; 32] {
    let mut be = [0u8; 32];
    value
        .to_big_endian(&mut be)
        .expect("Fq::to_big_endian writes exactly 32 bytes for a valid Fq");
    let mut le = [0u8; 32];
    for (i, b) in be.iter().rev().enumerate() {
        le[i] = *b;
    }
    le
}

/// "Lexicographically larger" predicate matching arkworks' `y <= -y` test:
/// a coordinate is treated as YIsNegative iff `y > -y` in the canonical ordering.
fn fq_is_negative(y: &Fq) -> bool {
    let neg_y = -*y;
    matches!(y.cmp(&neg_y), Ordering::Greater)
}

/// Serialize an `AffineG1` in the same 32-byte compressed format that
/// `ark`'s `CanonicalSerialize::serialize_compressed` produces for short-Weierstrass
/// affine points:
///
/// * X coordinate written little-endian into the 32 bytes.
/// * The top two bits of byte 31 carry SWFlags:
///   - `1<<7` (`0x80`) if the point's Y is negative,
///   - `1<<6` (`0x40`) if the point is at infinity,
///   - `0` for finite points with non-negative Y.
///
/// Used to feed the same Fiat-Shamir transcript as `rust-kzg-bn254-verifier`.
pub fn serialize_g1_compressed(point: &AffineG1) -> [u8; 32] {
    let jac: G1 = (*point).into();
    if jac.is_zero() {
        let mut out = [0u8; 32];
        out[31] = 1u8 << 6;
        return out;
    }
    let mut bytes = fq_to_le_bytes(&point.x());
    if fq_is_negative(&point.y()) {
        bytes[31] |= 1u8 << 7;
    }
    bytes
}

/// Serialize an `Fr` as 32 little-endian bytes representing the canonical (non-Montgomery)
/// value. Mirrors `ark_ff::PrimeField::serialize_compressed` for Fp elements.
///
/// `Fr::to_big_endian` returns Montgomery form, so we route through `into_u256()` instead.
pub fn serialize_fr_le(value: &Fr) -> [u8; 32] {
    let u = value.into_u256();
    let be = u.to_bytes_be();
    let mut le = [0u8; 32];
    for (i, b) in be.iter().rev().enumerate() {
        le[i] = *b;
    }
    le
}

/// Convert a 32-byte aligned blob to `Vec<Fr>` field elements.
///
/// Each 32-byte chunk must encode a value strictly less than the field order; non-canonical
/// chunks are rejected (matching `rust_kzg_bn254_primitives::helpers::validate_blob_data_as_canonical_field_elements`).
pub fn to_fr_array_canonical(blob: &[u8]) -> Result<Vec<Fr>, KzgError> {
    if blob.len() % BYTES_PER_FIELD_ELEMENT != 0 {
        return Err(KzgError::InvalidInputLength);
    }
    let mut out = Vec::with_capacity(blob.len() / BYTES_PER_FIELD_ELEMENT);
    for chunk in blob.chunks_exact(BYTES_PER_FIELD_ELEMENT) {
        // Round-trip through `from_bytes_be_mod_order` and compare with `from_slice`
        // (which does no modulus check) to detect non-canonical encodings.
        let reduced =
            Fr::from_bytes_be_mod_order(chunk).map_err(|_| KzgError::InvalidFieldElement)?;
        let direct = Fr::from_slice(chunk).map_err(|_| KzgError::InvalidFieldElement)?;
        if reduced != direct {
            return Err(KzgError::InvalidFieldElement);
        }
        out.push(direct);
    }
    Ok(out)
}

/// Polynomial in evaluation form, padded with zeros to the next power of two.
///
/// The original blob length (in bytes, before padding) is preserved so we can reconstruct the
/// same Fiat-Shamir transcript bytes that the reference verifier produces.
#[derive(Clone, Debug, PartialEq)]
pub struct PolynomialEvalForm {
    evaluations: Vec<Fr>,
    len_underlying_blob_bytes: usize,
}

impl PolynomialEvalForm {
    pub fn new(evals: Vec<Fr>) -> Result<Self, KzgError> {
        if evals.len() > MAINNET_SRS_G1_SIZE {
            return Err(KzgError::GenericError(
                "Input size exceeds maximum polynomial size".to_string(),
            ));
        }
        let underlying = evals.len() * BYTES_PER_FIELD_ELEMENT;
        let next_pow2 = evals.len().next_power_of_two();
        let mut padded = evals;
        padded.resize(next_pow2, Fr::zero());
        Ok(Self {
            evaluations: padded,
            len_underlying_blob_bytes: underlying,
        })
    }

    pub fn evaluations(&self) -> &[Fr] {
        &self.evaluations
    }

    pub fn len(&self) -> usize {
        self.evaluations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evaluations.is_empty()
    }

    pub fn len_underlying_blob_bytes(&self) -> usize {
        self.len_underlying_blob_bytes
    }
}

/// Serialize an `Fr` slice as a flat big-endian byte buffer of `max_output_size` bytes.
///
/// Matches `rust_kzg_bn254_primitives::helpers::to_byte_array`: each Fr is written as 32 BE
/// bytes of its canonical representation, the buffer is truncated (or zero-extended via the
/// last partial element) to exactly `max_output_size`.
pub fn to_byte_array(data_fr: &[Fr], max_output_size: usize) -> Vec<u8> {
    let n = data_fr.len();
    let data_size = core::cmp::min(n * BYTES_PER_FIELD_ELEMENT, max_output_size);
    let mut data = vec![0u8; data_size];

    for (i, element) in data_fr.iter().enumerate().take(n) {
        let v = element.into_u256().to_bytes_be();
        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;

        if end > max_output_size {
            let slice_end = core::cmp::min(v.len(), max_output_size - start);
            data[start..start + slice_end].copy_from_slice(&v[..slice_end]);
            break;
        } else {
            let actual_end = core::cmp::min(end, data_size);
            data[start..actual_end].copy_from_slice(&v[..actual_end - start]);
        }
    }
    data
}

/// Render a `usize` as its decimal string. Used to feed integers into `Fr::from_str` (the only
/// public route for constructing an `Fr` from a small integer in substrate-bn 0.6).
fn usize_to_decimal(n: usize) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut digits: Vec<u8> = Vec::new();
    let mut x = n;
    while x > 0 {
        digits.push((x % 10) as u8 + b'0');
        x /= 10;
    }
    digits.iter().rev().map(|d| *d as char).collect()
}

/// Build an `Fr` from an integer that is known to fit in the scalar field.
fn fr_from_usize(n: usize) -> Fr {
    Fr::from_str(&usize_to_decimal(n))
        .expect("decimal representation of usize is always a valid Fr")
}

/// `evaluate_polynomial_in_evaluation_form` — barycentric evaluation of a polynomial in evaluation
/// form on the multiplicative subgroup of size `polynomial.len()`.
pub fn evaluate_polynomial_in_evaluation_form(
    polynomial: &PolynomialEvalForm,
    z: &Fr,
) -> Result<Fr, KzgError> {
    let blob_size = polynomial.len_underlying_blob_bytes();
    let roots_of_unity = calculate_roots_of_unity(blob_size as u64)?;

    if polynomial.len() != roots_of_unity.len() {
        return Err(KzgError::InvalidInputLength);
    }

    let width = polynomial.len();
    let inverse_width = fr_from_usize(width)
        .inverse()
        .ok_or(KzgError::InvalidDenominator)?;

    if let Some(idx) = roots_of_unity.iter().position(|d| *d == *z) {
        return polynomial
            .evaluations()
            .get(idx)
            .copied()
            .ok_or_else(|| KzgError::GenericError("polynomial element missing".to_string()));
    }

    let mut sum = Fr::zero();
    for (f_i, domain_i) in polynomial.evaluations().iter().zip(roots_of_unity.iter()) {
        let a = *f_i * *domain_i;
        let b = *z - *domain_i;
        if b.is_zero() {
            return Err(KzgError::GenericError(
                "Division by zero in barycentric evaluation".to_string(),
            ));
        }
        sum = sum + a * b.inverse().ok_or(KzgError::InvalidDenominator)?;
    }

    let r = z.pow(fr_from_usize(width)) - Fr::one();
    Ok(sum * r * inverse_width)
}

/// Calculate the multiplicative subgroup roots of unity for the given padded blob length in bytes.
pub fn calculate_roots_of_unity(length_of_data_after_padding: u64) -> Result<Vec<Fr>, KzgError> {
    if length_of_data_after_padding == 0 {
        return Err(KzgError::GenericError(
            "Length of data after padding is 0".to_string(),
        ));
    }

    let n_field_elements = length_of_data_after_padding.div_ceil(BYTES_PER_FIELD_ELEMENT as u64);
    if n_field_elements > MAINNET_SRS_G1_SIZE as u64 {
        return Err(KzgError::GenericError("Length exceeds SRS".to_string()));
    }
    let target = (n_field_elements as usize).next_power_of_two();
    let log2 = target.trailing_zeros() as usize;

    let root = get_primitive_root_of_unity(log2)
        .ok_or_else(|| KzgError::GenericError("power must be <= 28".to_string()))?;
    let mut roots = expand_root_of_unity(&root);
    // Drop the duplicated trailing `1` so `roots.len() == target`.
    let last = roots.len() - 1;
    roots.truncate(last);
    Ok(roots)
}

fn expand_root_of_unity(root: &Fr) -> Vec<Fr> {
    let mut roots = vec![Fr::one(), *root];
    let max_iter = MAINNET_SRS_G1_SIZE + 1;
    let mut i = 1usize;
    while i < max_iter {
        let cur = roots[i];
        if cur == Fr::one() {
            break;
        }
        i += 1;
        roots.push(cur * *root);
    }
    roots
}

/// Compute the Fiat-Shamir challenge for a single (blob, commitment) pair. Encoding matches
/// `rust_kzg_bn254_primitives::helpers::compute_challenge` byte-for-byte.
pub fn compute_challenge(blob_data: &[u8], commitment: &AffineG1) -> Result<Fr, KzgError> {
    validate_g1_point(&(*commitment).into())?;

    let blob_fr = to_fr_array_canonical(blob_data)?;
    let blob_poly = PolynomialEvalForm::new(blob_fr)?;

    let challenge_input_size = FIAT_SHAMIR_PROTOCOL_DOMAIN.len()
        + 8
        + blob_poly.len() * BYTES_PER_FIELD_ELEMENT
        + SIZE_OF_G1_AFFINE_COMPRESSED;

    let mut buf = vec![0u8; challenge_input_size];
    let mut offset = 0;

    buf[offset..offset + FIAT_SHAMIR_PROTOCOL_DOMAIN.len()]
        .copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN);
    offset += FIAT_SHAMIR_PROTOCOL_DOMAIN.len();

    let n_fe_bytes = usize_to_be_bytes(blob_poly.len());
    buf[offset..offset + 8].copy_from_slice(&n_fe_bytes);
    offset += 8;

    let blob_bytes = to_byte_array(
        blob_poly.evaluations(),
        blob_poly.len() * BYTES_PER_FIELD_ELEMENT,
    );
    buf[offset..offset + blob_bytes.len()].copy_from_slice(&blob_bytes);
    offset += blob_bytes.len();

    let commit_bytes = serialize_g1_compressed(commitment);
    buf[offset..offset + SIZE_OF_G1_AFFINE_COMPRESSED].copy_from_slice(&commit_bytes);

    Ok(hash_to_field_element(&buf))
}

/// For each blob/commitment pair: compute the FS challenge `z_i` and evaluate the blob's
/// polynomial at `z_i`, returning `(zs, ys)`.
pub fn compute_challenges_and_evaluate_polynomial(
    blobs_data: &[&[u8]],
    commitments: &[AffineG1],
) -> Result<(Vec<Fr>, Vec<Fr>), KzgError> {
    if blobs_data.len() != commitments.len() && !blobs_data.is_empty() {
        return Err(KzgError::GenericError(
            "length's of the input are not the same or is empty".to_string(),
        ));
    }

    let mut zs = Vec::with_capacity(blobs_data.len());
    let mut ys = Vec::with_capacity(blobs_data.len());
    for (blob, commit) in blobs_data.iter().zip(commitments.iter()) {
        let blob_fr = to_fr_array_canonical(blob)?;
        let poly = PolynomialEvalForm::new(blob_fr)?;
        let z = compute_challenge(blob, commit)?;
        let y = evaluate_polynomial_in_evaluation_form(&poly, &z)?;
        zs.push(z);
        ys.push(y);
    }
    Ok((zs, ys))
}

/// Re-export of the lazily-constructed `[τ]G2`.
pub fn g2_tau() -> G2 {
    *G2_TAU
}
