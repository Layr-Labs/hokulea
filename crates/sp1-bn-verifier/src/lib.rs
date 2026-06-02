//! KZG batch verifier built on the [`substrate-bn`](https://github.com/sp1-patches/bn) fork.
//!
//! This crate is a `no_std`-friendly reimplementation of the EigenDA-flavoured
//! KZG batch verification logic that lives in `rust-kzg-bn254-verifier`. The
//! reference implementation is built on top of `arkworks` (`ark-bn254`,
//! `ark-ec`, `ark-ff`); inside an SP1 zkVM that path is significantly more
//! expensive than going through the patched substrate-bn primitives, which
//! ship hand-tuned hints for inversion, MSM and the pairing.
//!
//! The on-the-wire encoding of the Fiat-Shamir transcript matches the
//! arkworks-based reference verifier byte-for-byte, so a transcript produced
//! by either side is acceptable to the other.

#![no_std]

extern crate alloc;

pub mod batch;
pub mod consts;
pub mod errors;
pub mod helpers;

pub use batch::verify_blob_kzg_proof_batch;
pub use errors::KzgError;
