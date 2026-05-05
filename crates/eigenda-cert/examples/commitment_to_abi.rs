//! Converts an AltDA commitment hex to an ABI-encoded cert hex.
//!
//! ```sh
//! echo "010002f908f8..." | cargo run --example commitment_to_abi -p eigenda-cert
//! ```

use alloy_primitives::Bytes;
use alloy_sol_types::SolValue;
use eigenda_cert::{AltDACommitment, EigenDACertV3, EigenDAVersionedCert};
use std::{io::Read, str::FromStr};

fn main() {
    let bytes = {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let raw = Bytes::from_str(input.trim()).expect("invalid hex input");
        if raw.starts_with(&[0x01, 0x01, 0x00]) {
            eprintln!("warning: input looks like batcher calldata; strip the leading version byte so it starts with 0x0100.");
            raw.slice(1..)
        } else {
            raw
        }
    };

    let comm = AltDACommitment::try_from(&bytes[..]).expect("failed to parse AltDA commitment");
    let abi_bytes: Bytes = match comm.versioned_cert {
        EigenDAVersionedCert::V2(v2) => {
            // V2 is promoted to V3 for the verifier interface (same as verifier_caller.rs)
            let v3 = EigenDACertV3 {
                batch_header_v2: v2.batch_header_v2,
                blob_inclusion_info: v2.blob_inclusion_info,
                nonsigner_stake_and_signature: v2.nonsigner_stake_and_signature,
                signed_quorum_numbers: v2.signed_quorum_numbers,
            };
            v3.to_sol().abi_encode().into()
        }
        EigenDAVersionedCert::V3(v3) => v3.to_sol().abi_encode().into(),
        EigenDAVersionedCert::V4(v4) => v4.to_sol().abi_encode().into(),
    };

    println!("{abi_bytes}");
}
