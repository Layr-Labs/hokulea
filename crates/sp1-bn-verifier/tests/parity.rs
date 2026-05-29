//! Parity tests against `rust-kzg-bn254-verifier`.
//!
//! For each fixture, we compute the same `(blob, commitment, proof)` triple via
//! `hokulea-compute-proof`, then run *both* the arkworks-flavoured reference verifier
//! (`rust_kzg_bn254_verifier::batch::verify_blob_kzg_proof_batch`) and our substrate-bn
//! port. The two implementations must agree on every input — including the rejection cases.

use std::borrow::Cow;
use std::vec;
use std::vec::Vec;

use alloy_primitives::{hex, FixedBytes, U256};
use ark_bn254::{Fq, Fr as ArkFr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use eigenda_cert::G1Point;
use hokulea_eigenda::EncodedPayload;
use num::BigUint;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_primitives::errors::KzgError as RefKzgError;
use rust_kzg_bn254_primitives::helpers::{
    compute_challenge as ref_compute_challenge, read_g1_point_from_bytes_be,
};
use rust_kzg_bn254_prover::{kzg::KZG, srs::SRS};
use rust_kzg_bn254_verifier::batch as ref_batch;
use substrate_bn::{AffineG1, Fq as BnFq};

// First 128 bytes of resources/g1.point — same fixture used by hokulea-proof's tests.
const G1_POINTS_BYTE: &str = "8000000000000000000000000000000000000000000000000000000000000001cbfc87ecbdcdc23ef5481bb179aaada7f42c22d2dfd52b4655a18c2879c54eea9fb27cc0e2465b3e57a42a051dbfbd8d0b62eec80cd07c46401781deab36ca27c44ab250113840f37622eb001cfbcb1dec55f15e6ea48333ddb63e9d2befecab";

fn load_g1_srs(g1_srs: &mut Vec<G1Affine>) -> SRS<'_> {
    let bytes = hex::decode(G1_POINTS_BYTE).unwrap();
    g1_srs.push(read_g1_point_from_bytes_be(&bytes[..32]).unwrap());
    g1_srs.push(read_g1_point_from_bytes_be(&bytes[32..64]).unwrap());
    g1_srs.push(read_g1_point_from_bytes_be(&bytes[64..96]).unwrap());
    g1_srs.push(read_g1_point_from_bytes_be(&bytes[96..128]).unwrap());
    SRS {
        g1: Cow::Borrowed(g1_srs),
        order: 4,
    }
}

fn compute_commitment(blob: &Blob) -> Result<G1Point, RefKzgError> {
    let mut kzg = KZG::new();
    kzg.calculate_and_store_roots_of_unity(blob.len() as u64)
        .unwrap();
    let poly = blob.to_polynomial_eval_form()?;
    let mut srs_storage = vec![];
    let commitment = kzg.commit_eval_form(&poly, &load_g1_srs(&mut srs_storage))?;

    let cx: BigUint = commitment.x.into();
    let cy: BigUint = commitment.y.into();
    let cx_bytes = hokulea_compute_proof::convert_biguint_to_be_32_bytes(&cx);
    let cy_bytes = hokulea_compute_proof::convert_biguint_to_be_32_bytes(&cy);
    Ok(G1Point {
        x: U256::from_be_bytes(cx_bytes),
        y: U256::from_be_bytes(cy_bytes),
    })
}

fn compute_proof_and_commitment(payload: Vec<u8>) -> (Blob, G1Point, FixedBytes<64>) {
    let encoded = EncodedPayload {
        encoded_payload: payload.into(),
    };
    let mut srs_storage = vec![];
    let proof = hokulea_compute_proof::compute_kzg_proof_with_srs(
        encoded.serialize(),
        &load_g1_srs(&mut srs_storage),
    )
    .unwrap();
    let proof_fb = FixedBytes::<64>::from_slice(proof.as_ref());

    let blob = Blob::new(encoded.serialize()).unwrap();
    let commitment = compute_commitment(&blob).unwrap();
    (blob, commitment, proof_fb)
}

/// Reference verifier wrapper: takes the same input shape as our substrate-bn `batch_verify`.
fn ref_batch_verify(blobs: &[Blob], commitments: &[G1Point], proofs: &[FixedBytes<64>]) -> bool {
    let lib_commitments: Vec<G1Affine> = commitments
        .iter()
        .map(|c| {
            let a: [u8; 32] = c.x.to_be_bytes();
            let b: [u8; 32] = c.y.to_be_bytes();
            G1Affine::new(
                Fq::from_be_bytes_mod_order(&a),
                Fq::from_be_bytes_mod_order(&b),
            )
        })
        .collect();
    let lib_proofs: Vec<G1Affine> = proofs
        .iter()
        .map(|p| {
            G1Affine::new(
                Fq::from_be_bytes_mod_order(&p[..32]),
                Fq::from_be_bytes_mod_order(&p[32..64]),
            )
        })
        .collect();
    ref_batch::verify_blob_kzg_proof_batch(blobs, &lib_commitments, &lib_proofs).unwrap_or(false)
}

fn sp1_batch_verify(blobs: &[Blob], commitments: &[G1Point], proofs: &[FixedBytes<64>]) -> bool {
    hokulea_sp1_bn_verifier::batch::batch_verify(
        blobs.iter().map(|b| b.data()),
        commitments.iter().copied(),
        proofs.iter().copied(),
    )
}

fn fixture_payload_a() -> Vec<u8> {
    vec![
        0, 0, 0, 0, 0, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1,
    ]
}

fn fixture_payload_b() -> Vec<u8> {
    vec![
        0, 1, 1, 1, 1, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1,
    ]
}

#[test]
fn parity_single_blob_valid() {
    let (blob, commitment, proof) = compute_proof_and_commitment(fixture_payload_a());
    let blobs = vec![blob];
    let commitments = vec![commitment];
    let proofs = vec![proof];
    let r = ref_batch_verify(&blobs, &commitments, &proofs);
    let s = sp1_batch_verify(&blobs, &commitments, &proofs);
    assert!(r, "reference verifier rejected a valid proof");
    assert_eq!(r, s, "ref={} sp1={}", r, s);
}

#[test]
fn parity_two_blobs_valid() {
    let (b1, c1, p1) = compute_proof_and_commitment(fixture_payload_a());
    let (b2, c2, p2) = compute_proof_and_commitment(fixture_payload_b());
    let blobs = vec![b1, b2];
    let commitments = vec![c1, c2];
    let proofs = vec![p1, p2];
    let r = ref_batch_verify(&blobs, &commitments, &proofs);
    let s = sp1_batch_verify(&blobs, &commitments, &proofs);
    assert!(r, "ref rejected a valid two-blob batch");
    assert_eq!(r, s, "ref={} sp1={}", r, s);
}

#[test]
fn parity_two_blobs_swapped_proofs_invalid() {
    let (b1, c1, p1) = compute_proof_and_commitment(fixture_payload_a());
    let (b2, c2, p2) = compute_proof_and_commitment(fixture_payload_b());
    let blobs = vec![b1, b2];
    let commitments = vec![c1, c2];
    // Swap proofs to break the relationship.
    let proofs = vec![p2, p1];
    let r = ref_batch_verify(&blobs, &commitments, &proofs);
    let s = sp1_batch_verify(&blobs, &commitments, &proofs);
    assert!(!r, "ref accepted swapped proofs");
    assert_eq!(r, s, "ref={} sp1={}", r, s);
}

/// Convert a `G1Point` to a `substrate-bn::AffineG1` the same way the production code does.
fn g1point_to_bn_affine(c: &G1Point) -> AffineG1 {
    let x_bytes: [u8; 32] = c.x.to_be_bytes();
    let y_bytes: [u8; 32] = c.y.to_be_bytes();
    let x = BnFq::from_be_bytes_mod_order(&x_bytes).unwrap();
    let y = BnFq::from_be_bytes_mod_order(&y_bytes).unwrap();
    AffineG1::new(x, y).unwrap()
}

/// Same `G1Point` reinterpreted via the arkworks types `rust-kzg-bn254` uses.
fn g1point_to_ark_affine(c: &G1Point) -> G1Affine {
    let x: [u8; 32] = c.x.to_be_bytes();
    let y: [u8; 32] = c.y.to_be_bytes();
    G1Affine::new(
        Fq::from_be_bytes_mod_order(&x),
        Fq::from_be_bytes_mod_order(&y),
    )
}

/// Compare the per-blob FS challenge produced by the two implementations. They must match
/// byte-for-byte (canonical 32-byte LE encoding) for *every* fixture, otherwise the batch
/// pairing equation would be evaluated at different points on each side.
#[test]
fn parity_compute_challenge_bytes_match() {
    for payload in [fixture_payload_a(), fixture_payload_b()] {
        let (blob, commitment, _) = compute_proof_and_commitment(payload);

        // Reference: arkworks-flavoured challenge → 32 LE bytes (canonical).
        let ref_z: ArkFr =
            ref_compute_challenge(&blob, &g1point_to_ark_affine(&commitment)).unwrap();
        let ref_bytes_le = {
            let be: Vec<u8> = ref_z.into_bigint().to_bytes_be();
            let mut le = [0u8; 32];
            for (i, b) in be.iter().rev().enumerate() {
                le[i] = *b;
            }
            le
        };

        // Port: substrate-bn challenge.
        let blob_poly = {
            let fr = hokulea_sp1_bn_verifier::helpers::to_fr_array_canonical(blob.data()).unwrap();
            hokulea_sp1_bn_verifier::helpers::PolynomialEvalForm::new(fr).unwrap()
        };
        let sp1_z = hokulea_sp1_bn_verifier::helpers::compute_challenge(
            &blob_poly,
            &g1point_to_bn_affine(&commitment),
        )
        .unwrap();
        let sp1_bytes_le = hokulea_sp1_bn_verifier::helpers::serialize_fr_le(&sp1_z);

        assert_eq!(
            ref_bytes_le, sp1_bytes_le,
            "compute_challenge bytes diverge:\n  ref={:02x?}\n  sp1={:02x?}",
            ref_bytes_le, sp1_bytes_le
        );
    }
}

#[test]
fn parity_corrupted_proof_invalid() {
    // Use blob A's commitment but blob B's proof — the pairing must fail.
    let (b1, c1, _) = compute_proof_and_commitment(fixture_payload_a());
    let (_, _, p2) = compute_proof_and_commitment(fixture_payload_b());
    let blobs = vec![b1];
    let commitments = vec![c1];
    let proofs = vec![p2];
    let r = ref_batch_verify(&blobs, &commitments, &proofs);
    let s = sp1_batch_verify(&blobs, &commitments, &proofs);
    assert!(!r, "ref accepted a corrupted proof");
    assert_eq!(r, s, "ref={} sp1={}", r, s);
}
