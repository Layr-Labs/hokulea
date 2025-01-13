use alloy_primitives::Bytes;
use alloc::vec::Vec;
use rust_kzg_bn254::kzg::KZG;
use rust_kzg_bn254::blob::Blob;
use ark_bn254::{G1Affine, Fq};
use ark_ff::PrimeField;
use tracing::info;

#[derive(Debug, Clone)]
pub struct EigenDABlobWitness {
    pub eigenda_blobs: Vec<Bytes>,
    pub commitments: Vec<Bytes>,
    pub proofs: Vec<Bytes>,
}

impl EigenDABlobWitness {
    pub fn new() -> Self {
        EigenDABlobWitness {
            eigenda_blobs: Vec::new(),
            commitments: Vec::new(),
            proofs:  Vec::new(),
        }
    }

    pub fn write(&mut self, blob: Bytes, commitment: Bytes, proof: Bytes) {
        self.eigenda_blobs.push(blob);
        self.commitments.push(commitment);
        self.proofs.push(proof);
        info!("added a blob");
    }

    pub fn verify(&self) -> bool {
        // TODO we should have to specify the details to get a kzg to perform a verification
        let kzg = match KZG::setup(
            "resources/g1.32mb.point",
            "",
            "resources/g2.point.powerOf2",
            268435456,
            1024,
        ) {
            Ok(k) => k,
            Err(e) => panic!("cannot setup kzg {}", e),
        };

        
        info!("lib_blobs len {:?}", self.eigenda_blobs.len());

        // transform to rust-kzg-bn254 inputs types
        // TODO should make library do the parsing the return result
        let lib_blobs: Vec<Blob> = self.eigenda_blobs.iter().map(|b| Blob::new(b)).collect();
        let lib_commitments: Vec<G1Affine> = self.commitments.iter().map(|c| {
            let x = Fq::from_be_bytes_mod_order(&c[..32]);
            let y = Fq::from_be_bytes_mod_order(&c[32..64]);
            G1Affine::new(x, y)
            }).collect();
        let lib_proofs: Vec<G1Affine> = self.proofs.iter().map(|p| {
            let x = Fq::from_be_bytes_mod_order(&p[..32]);
            let y = Fq::from_be_bytes_mod_order(&p[32..64]);

            G1Affine::new(x, y)
            }).collect();
        let pairing_result = kzg
            .verify_blob_kzg_proof_batch(&lib_blobs, &lib_commitments, &lib_proofs)
            .unwrap();
        
        //info!("lib_blobs {:?}", lib_blobs);
        //info!("lib_commitments {:?}", lib_commitments);
        //info!("lib_proofs {:?}", lib_proofs);
        //info!("pairing_result {:?}", pairing_result);

        return pairing_result
    }
}

