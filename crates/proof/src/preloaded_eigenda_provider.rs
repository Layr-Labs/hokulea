use crate::eigenda_blob_witness::EigenDABlobWitnessData;
use crate::errors::HokuleaOracleProviderError;
use alloy_primitives::{FixedBytes, U256};
use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_eigenda::EigenDABlobProvider;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_verifier::batch;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::canoe_verifier::CanoeVerifier;

/// PreloadedEigenDABlobProvider converts EigenDABlobWitnessData into preimage data
/// can be used to implement the EigenDABlobProvider trait, that contains
///   get_validity
///   get_blob
///
/// For each function above, internally PreloadedEigenDABlobProvider maintain a separate
/// struct in the form of a tuple (DA cert, returned data by the interface).
///
/// This allows a safety checks that PreloadedEigenDABlobProvider
/// indeed provides the response back to the correct DA certs
///
/// At the conversion side (i.e from_witness), we only have to maintain the correctness
/// from (DA cert, returned data by the interface).
///
/// Note it is possible, the lenght of validity_entries is greater than len of blob_entries
/// due to possible invalid cert, that does not require preimage to populate a blob
#[derive(Clone, Debug, Default)]
pub struct PreloadedEigenDABlobProvider {
    /// The tuple contains a mapping from DAcert to recency window size
    /// Although currently, recency window does not change across EigenDACertV2
    /// But to be future compatible, we anchor recency window size by rbn from EigenDACertV2
    pub recency_entries: Vec<(AltDACommitment, u64)>,
    /// The tuple contains a mapping from DAcert to cert validity
    pub validity_entries: Vec<(AltDACommitment, bool)>,
    /// The tuple contains a mapping from DAcert to Eigenda blob
    pub blob_entries: Vec<(AltDACommitment, Blob)>,
}

impl PreloadedEigenDABlobProvider {
    /// Convert EigenDABlobWitnessData into the PreloadedEigenDABlobProvider
    pub fn from_witness(
        value: EigenDABlobWitnessData,
        canoe_verifier: impl CanoeVerifier,
    ) -> PreloadedEigenDABlobProvider {
        // check number of element invariants
        assert!(value.recency.len() >= value.validity.len());
        assert!(value.validity.len() >= value.blob.len());

        // recency window is the first check against incoming DA cert from derivation pipeline
        //
        // Important assumption, recency must come from a trusted or validated source
        // currently, recency is set to be identical to sequencing window, which come directly
        // boot info
        let mut recency_entries = value.recency.clone();

        // check all cert validity are substantiated by zk validity proof
        let mut validity_entries = vec![];

        // if the number of da cert is non-zero, verify the single canoe proof, regardless if the
        // da cert is valid or not. Otherwise, skip the verification
        if !value.validity.is_empty() {
            // check cert validity altogether in one verification
            canoe_verifier
                .validate_cert_receipt(value.validity.clone(), value.canoe_proof_bytes)
                .expect("verification should have been passing");
        }

        for (altda_commitment, cert_validity) in &value.validity {
            // populate only the mapping <DAcert, boolean> for preimage trait
            validity_entries.push((altda_commitment.clone(), cert_validity.claimed_validity));
        }

        // check all blobs correponds to cert are correct
        let mut blob_entries = vec![];
        let mut blobs = vec![];
        let mut proofs = vec![];
        let mut commitments = vec![];

        // checking the blob is consistent to the kzg commitment from the da certs
        for (cert, eigenda_blobs, kzg_proof) in value.blob {
            let blob = Blob::new(&eigenda_blobs).expect("should be able to construct a blob");
            // if valid, check blob kzg integrity
            blobs.push(blob.clone());
            proofs.push(kzg_proof);
            commitments.push(cert.get_kzg_commitment());

            // populate entries ahead of time, if something is invalid, batch_verify will abort
            blob_entries.push((cert.clone(), blob));
        }
        assert!(batch_verify(blobs, commitments, proofs));
        // invariant check
        assert!(recency_entries.len() >= validity_entries.len());
        assert!(validity_entries.len() >= blob_entries.len());

        // The pop methods is used by the Preloaded provider when getting the next data
        // reverse there, so that what is being popped is the early data
        validity_entries.reverse();
        blob_entries.reverse();
        recency_entries.reverse();

        PreloadedEigenDABlobProvider {
            recency_entries,
            validity_entries,
            blob_entries,
        }
    }
}

#[async_trait]
impl EigenDABlobProvider for PreloadedEigenDABlobProvider {
    // TODO investigate if create a speical error type EigenDABlobProviderError
    type Error = HokuleaOracleProviderError;

    async fn get_recency_window(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<u64, Self::Error> {
        let (stored_altda_commitment, recency) = self.recency_entries.pop().unwrap();
        if stored_altda_commitment == *altda_commitment {
            Ok(recency)
        } else {
            // It is safe to abort here, because zkVM is not given the correct preimage to start with, stop early
            panic!("preloaded eigenda blob provider does not match altda commitment requested from derivation pipeline
                requested altda commitment is {:?}, stored is {:?}", altda_commitment.to_digest(), stored_altda_commitment.to_digest());
        }
    }

    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        let (stored_altda_commitment, validity) = self.validity_entries.pop().unwrap();
        if stored_altda_commitment == *altda_commitment {
            Ok(validity)
        } else {
            // It is safe to abort here, because zkVM is not given the correct preimage to start with, stop early
            panic!("preloaded eigenda blob provider does not match altda commitment requested from derivation pipeline
                requested altda commitment is {:?}, stored is {:?}", altda_commitment.to_digest(), stored_altda_commitment.to_digest());
        }
    }

    /// Fetches a blob for V2 using preloaded data
    /// Return an error if cert does not match the immeditate next item
    async fn get_blob(&mut self, altda_commitment: &AltDACommitment) -> Result<Blob, Self::Error> {
        let (stored_altda_commitment, eigenda_blob) = self.blob_entries.pop().unwrap();
        if stored_altda_commitment == *altda_commitment {
            Ok(eigenda_blob)
        } else {
            // It is safe to abort here, because zkVM is not given the correct preimage to start with, stop early
            panic!("preloaded eigenda blob provider does not match altda commitment requested from derivation pipeline
                requested altda commitment is {:?}, stored is {:?}", altda_commitment.to_digest(), stored_altda_commitment.to_digest());
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
