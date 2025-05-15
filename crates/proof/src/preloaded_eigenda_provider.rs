use crate::eigenda_blob_witness::EigenDABlobWitnessData;
use alloy_primitives::{FixedBytes, U256};
use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use async_trait::async_trait;
use eigenda_v2_struct::EigenDAV2Cert;
use hokulea_eigenda::{AltDACommitment, EigenDABlobProvider, EigenDAVersionedCert};
use kona_preimage::errors::PreimageOracleError;
use kona_proof::errors::OracleProviderError;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_verifier::batch;
use tracing::debug;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::canoe_verifier::CanoeVerifier;

/// PreloadedEigenDABlobProvider ensures the following invariants
///     there is a zk proof for each cert
///     verification of each zk proof must be valid
/// The system reverts if any of them fails. If the claim validity from EigenDABlobWitnessData from for the cert is
///     true , then return the eigenda blob
///     false, then return the empty byte
#[derive(Clone, Debug, Default)]
pub struct PreloadedEigenDABlobProvider {
    /// The tuple contains EigenDAV2Cert, Blob, isValid cert.
    pub entries: Vec<(EigenDAV2Cert, Blob)>,
}

impl PreloadedEigenDABlobProvider {
    /// Convert EigenDABlobWitnessData into the PreloadedEigenDABlobProvider
    pub fn from_witness(
        value: EigenDABlobWitnessData,
        canoe_verifier: impl CanoeVerifier,
    ) -> PreloadedEigenDABlobProvider {
        let mut blobs = vec![];
        let mut proofs = vec![];
        let mut commitments = vec![];

        let mut entries = vec![];

        for i in 0..value.eigenda_blobs.len() {
            // check cert validity

            assert!(!value.validity[i].canoe_proof.is_empty());
            canoe_verifier
                .validate_cert_receipt(value.validity[i].clone(), value.eigenda_certs[i].clone());

            // if valid, check blob kzg integrity
            if value.validity[i].claimed_validity {
                blobs.push(Blob::new(&value.eigenda_blobs[i]));
                proofs.push(value.kzg_proofs[i]);
                let commitment = value.eigenda_certs[i]
                    .blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment;
                commitments.push((commitment.x, commitment.y));
            } else {
                // check (P2) if cert is not valid, the blob is only allowed to be empty
                assert!(value.eigenda_blobs[i].is_empty());
            }
            entries.push((
                value.eigenda_certs[i].clone(),
                Blob::new(&value.eigenda_blobs[i]),
            ));
        }

        // for ease of when using
        entries.reverse();

        // check (P1) if cert is not valie, the blob must be empty, assert that commitments in the cert and blobs are consistent
        assert!(batch_verify(blobs, commitments, proofs));

        PreloadedEigenDABlobProvider { entries }
    }
}

#[async_trait]
impl EigenDABlobProvider for PreloadedEigenDABlobProvider {
    // TODO investigate if create a speical error type EigenDABlobProviderError
    type Error = OracleProviderError;

    /// Fetches a blob for V2 using preloaded data
    /// Return an error if cert does not match the immeditate next item
    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error> {
        let (eigenda_cert, eigenda_blob) = self.entries.pop().unwrap();
        let is_match = match &altda_commitment.versioned_cert {
            // secure integration is not implemented for v1, but feel free to contribute
            EigenDAVersionedCert::V1(_c) => unimplemented!(),
            EigenDAVersionedCert::V2(c) => {
                debug!("request cert is {:?}", c.digest());
                debug!("stored  cert is {:?}", eigenda_cert.digest());
                c == &eigenda_cert
            }
        };

        if is_match {
            Ok(eigenda_blob)
        } else {
            Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                "does not contain header".into(),
            )))
        }
    }
}

/// Eventually, rust-kzg-bn254 would provide a nice interface that takes
/// bytes input, so that we can remove this wrapper. For now, just include it here
pub fn batch_verify(
    eigenda_blobs: Vec<Blob>,
    commitments: Vec<(U256, U256)>,
    proofs: Vec<FixedBytes<64>>,
) -> bool {
    // transform to rust-kzg-bn254 inputs types
    // TODO should make library do the parsing the return result
    let lib_blobs: Vec<Blob> = eigenda_blobs;
    let lib_commitments: Vec<G1Affine> = commitments
        .iter()
        .map(|c| {
            let a: [u8; 32] = c.0.to_be_bytes();
            let b: [u8; 32] = c.1.to_be_bytes();
            let x = Fq::from_be_bytes_mod_order(&a);
            let y = Fq::from_be_bytes_mod_order(&b);
            G1Affine::new(x, y)
        })
        .collect();
    let lib_proofs: Vec<G1Affine> = proofs
        .iter()
        .map(|p| {
            let x = Fq::from_be_bytes_mod_order(&p[..32]);
            let y = Fq::from_be_bytes_mod_order(&p[32..64]);

            G1Affine::new(x, y)
        })
        .collect();

    // convert all the error to false
    batch::verify_blob_kzg_proof_batch(&lib_blobs, &lib_commitments, &lib_proofs).unwrap_or(false)
}
