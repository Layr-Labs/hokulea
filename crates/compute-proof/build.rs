//! Build script for srs-data crate.
//!
//! This script generates compile-time Rust code for the SRS (Structured Reference String)
//! by reading the g1.point file and creating a static G1Affine point array that can be
//! embedded directly in the binary at compile time
use std::path::Path;
use std::{env, fs};

use ark_serialize::CanonicalSerialize;
use rust_kzg_bn254_prover::srs::SRS;

const POINTS_TO_LOAD: u32 = 16 * 1024 * 1024 / 32;
// total number of srs points elligible to use
const SRS_ORDER: u32 = 268435456;

fn main() {
    let workspace_root = env::var("CARGO_MANIFEST_DIR")
        .map(|dir| {
            Path::new(&dir)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .expect("Failed to get workspace root");
    let path = workspace_root.join("resources/g1.point");
    let path_str = path.to_str().expect("Invalid path");

    println!("cargo:rerun-if-changed={path_str}");

    let srs = SRS::new(path_str, SRS_ORDER, POINTS_TO_LOAD).expect("Failed to create SRS");
    assert_eq!(srs.g1.len(), POINTS_TO_LOAD as usize);

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);

    let g1_slice = &srs.g1[..];
    // Serialize G1Affine points using arkworks' canonical serialization.
    // This ensures stable, well-defined binary format across compiler versions.
    let mut g1_bytes = Vec::new();
    g1_slice
        .serialize_uncompressed(&mut g1_bytes)
        .expect("Failed to serialize G1 points");

    let g1_path = out_path.join("srs_points.bin");
    fs::write(&g1_path, &g1_bytes).expect("Failed to write G1 points");

    let byte_size = g1_bytes.len();

    macro_rules! generate_constants {
        ($points:expr, $byte_size:expr) => {
            format!(
                r#"// Auto-generated constants - DO NOT EDIT

/// Number of G1 points to load from the SRS data.
/// This represents the maximum degree of polynomials that can be committed.
pub const POINTS_TO_LOAD: usize = {};

/// Total byte size of the embedded SRS point data.
/// This is calculated as POINTS_TO_LOAD * `size_of::<G1Affine>`().
pub const BYTE_SIZE: usize = {};
"#,
                $points, $byte_size
            )
        };
    }

    let constants_content = generate_constants!(POINTS_TO_LOAD, byte_size);
    let constants_path = out_path.join("constants.rs");
    fs::write(&constants_path, constants_content).expect("Failed to write constants");
}
