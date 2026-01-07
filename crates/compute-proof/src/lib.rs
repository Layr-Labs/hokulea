#![doc = include_str!("../README.md")]
#![warn(
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    rustdoc::all
)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod kzg_proof;
use alloy_primitives::FixedBytes;
use ark_bn254::G1Affine;
use hokulea_proof::EigenDAPreimage;
pub use kzg_proof::{
    compute_kzg_proof, compute_kzg_proof_with_srs, convert_biguint_to_be_32_bytes,
};
use rust_kzg_bn254_prover::srs::SRS;
use std::borrow::Cow;
use std::sync::LazyLock;
use std::time::Instant;
use tracing::info;

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

// SAFETY: Transmuting compile-time embedded binary data to typed G1Affine array.
// - Binary data originates from the same G1Affine structures in build.rs
// - BYTE_SIZE constant ensures exact size match: POINTS_TO_LOAD * size_of::<G1Affine>()
// - G1Affine has stable, well-defined memory representation from ark-bn254
// - Both source and target arrays have identical size and alignment requirements
// - Static lifetime is appropriate for compile-time embedded data
static SRS_POINTS: &[G1Affine; POINTS_TO_LOAD] = unsafe {
    &core::mem::transmute::<[u8; BYTE_SIZE], [G1Affine; POINTS_TO_LOAD]>(*include_bytes!(concat!(
        env!("OUT_DIR"),
        "/srs_points.bin"
    )))
};

/// Globally accessible SRS (Structured Reference String) for KZG operations.
///
/// This static contains precomputed G1 curve points loaded from embedded binary data.
/// The SRS is lazily initialized on first access and provides the cryptographic
/// parameters needed for KZG polynomial commitments and proofs.
pub static G1_SRS: LazyLock<SRS<'static>> = LazyLock::new(|| SRS {
    g1: Cow::Borrowed(SRS_POINTS),
    order: (POINTS_TO_LOAD * 32) as u32,
});

/// creates kzg proof for all encoded payloads within the eigenda preimage.
/// The KZG proofs is computed on Fiat-Sharmir point from the encoded payload
/// (blob is an inverse Fourier Transform of encoded payload).
pub fn create_kzg_proofs_for_eigenda_preimage(preimage: &EigenDAPreimage) -> Vec<FixedBytes<64>> {
    let start = Instant::now();
    let mut kzg_proofs = vec![];
    for (_, encoded_payload) in &preimage.encoded_payloads {
        // Compute kzg proof for the entire encoded payload on a deterministic random point
        let kzg_proof = match compute_kzg_proof(encoded_payload.serialize()) {
            Ok(p) => p,
            Err(e) => panic!("cannot generate a kzg proof: {e}"),
        };
        let fixed_bytes: FixedBytes<64> = FixedBytes::from_slice(kzg_proof.as_ref());
        kzg_proofs.push(fixed_bytes);
    }
    let elapsed = start.elapsed();
    let num_proofs = kzg_proofs.len();
    info!(
        target: "kzg_proof_provider",
        "completed {num_proofs} kzg proofs generation in {:?} times",
        elapsed
    );
    kzg_proofs
}
