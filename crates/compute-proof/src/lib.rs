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
pub use kzg_proof::{
    compute_kzg_proof, compute_kzg_proof_with_srs, convert_biguint_to_be_32_bytes, G1_SRS,
};

use alloy_primitives::FixedBytes;
use hokulea_proof::EigenDAPreimage;
use std::time::Instant;
use tracing::info;

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
