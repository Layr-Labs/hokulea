use crate::eigenda_witness::EigenDAWitness;
use crate::errors::HokuleaOracleProviderError;
use alloy_primitives::{FixedBytes, U256};
use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_eigenda::{EigenDAPreimageProvider, EncodedPayload};
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_verifier::batch;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use canoe_verifier::CanoeVerifier;

/// PreloadedEigenDAPreimageProvider converts EigenDAWitness into preimage data
/// can be used to implement the EigenDAPreimageProvider trait, that contains
///   get_validity
///   get_encoded_payload
///
/// For each function above, internally PreloadedEigenDAPreimageProvider maintain a separate
/// struct in the form of a tuple (DA cert, returned data by the interface).
///
/// This allows a safety checks that PreloadedEigenDAPreimageProvider
/// indeed provides the response back to the correct DA certs
///
/// At the conversion side (i.e from_witness), we only have to maintain the correctness
/// from (DA cert, returned data by the interface).
///
/// Note it is possible, the length of validity_entries is greater than len of encoded_payload_entries
/// due to possible invalid cert, that does not require preimage to populate a encoded payload
#[derive(Clone, Debug, Default)]
pub struct PreloadedEigenDAPreimageProvider {
    /// The tuple contains a mapping from DAcert to recency window size
    /// Although currently, recency window does not change across EigenDACertV2
    /// But to be future compatible, we anchor recency window size by rbn from EigenDACertV2
    pub recency_entries: Vec<(AltDACommitment, u64)>,
    /// The tuple contains a mapping from DAcert to cert validity
    pub validity_entries: Vec<(AltDACommitment, bool)>,
    /// The tuple contains a mapping from DAcert to Eigenda encoded payload
    pub encoded_payload_entries: Vec<(AltDACommitment, EncodedPayload)>,
}

impl PreloadedEigenDAPreimageProvider {
    /// Convert EigenDAWitness into the PreloadedEigenDAPreimageProvider
    pub fn from_witness(
        value: EigenDAWitness,
        canoe_verifier: impl CanoeVerifier,
    ) -> PreloadedEigenDAPreimageProvider {
        // check number of element invariants
        assert!(value.recencies.len() >= value.validities.len());
        assert!(value.validities.len() >= value.encoded_payloads.len());

        // recency window is the first check against incoming DA cert from derivation pipeline
        //
        // Important assumption, recency must come from a trusted or validated source
        // currently, recency is set to be identical to sequencing window, which come directly
        // boot info
        let mut recency_entries = value.recencies.clone();

        // check all cert validity are substantiated by zk validity proof
        let mut validity_entries = vec![];

        // if the number of da cert is non-zero, verify the single canoe proof, regardless if the
        // da cert is valid or not. Otherwise, skip the verification
        if !value.validities.is_empty() {
            // check cert validity altogether in one verification
            canoe_verifier
                .validate_cert_receipt(value.validities.clone(), value.canoe_proof_bytes)
                .expect("verification should have been passing");
        }

        for (altda_commitment, cert_validity) in &value.validities {
            // populate only the mapping <DAcert, boolean> for preimage trait
            validity_entries.push((altda_commitment.clone(), cert_validity.claimed_validity));
        }

        let mut encoded_payload_entries = vec![];

        // check all blobs correponds to cert are correct
        let mut blobs = vec![];
        let mut proofs = vec![];
        let mut commitments = vec![];
        //for i in 0..value.eigenda_certs.len() {
        for (cert, encoded_payload, kzg_proof) in value.encoded_payloads {
            // populate entries ahead of time, if something is invalid, batch_verify will abort
            encoded_payload_entries.push((cert.clone(), encoded_payload.clone()));

            // gather fiat shamir kzg commitment and proof for batch verification
            let blob =
                Blob::new(encoded_payload.serialize()).expect("should be able to construct a blob");
            blobs.push(blob);
            proofs.push(kzg_proof);
            commitments.push(cert.get_kzg_commitment());
        }
        assert!(batch_verify(blobs, commitments, proofs));
        // invariant check
        assert!(recency_entries.len() >= validity_entries.len());
        assert!(validity_entries.len() >= encoded_payload_entries.len());

        // The pop methods is used by the Preloaded provider when getting the next data
        // reverse there, so that what is being popped is the early data
        validity_entries.reverse();
        encoded_payload_entries.reverse();
        recency_entries.reverse();

        PreloadedEigenDAPreimageProvider {
            recency_entries,
            validity_entries,
            encoded_payload_entries,
        }
    }
}

#[async_trait]
impl EigenDAPreimageProvider for PreloadedEigenDAPreimageProvider {
    // TODO investigate if create a speical error type EigenDAPreimageProviderError
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
            panic!("preloaded eigenda preimage provider does not match altda commitment requested from derivation pipeline
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
            panic!("preloaded eigenda preimage provider does not match altda commitment requested from derivation pipeline
                requested altda commitment is {:?}, stored is {:?}", altda_commitment.to_digest(), stored_altda_commitment.to_digest());
        }
    }

    /// Fetches a blob for V2 using preloaded data
    /// Return an error if cert does not match the immeditate next item
    async fn get_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<EncodedPayload, Self::Error> {
        let (stored_altda_commitment, encoded_payload) =
            self.encoded_payload_entries.pop().unwrap();
        if stored_altda_commitment == *altda_commitment {
            Ok(encoded_payload)
        } else {
            // It is safe to abort here, because zkVM is not given the correct preimage to start with, stop early
            panic!("preloaded preimage provider does not match altda commitment requested from derivation pipeline
                requested altda commitment is {:?}, stored is {:?}", altda_commitment.to_digest(), stored_altda_commitment.to_digest());
        }
    }
}

/// Eventually, rust-kzg-bn254 would provide an interface that takes
/// bytes input, so that we can remove this wrapper. For now, just include it here
pub fn batch_verify(
    blobs: Vec<Blob>,
    commitments: Vec<(U256, U256)>,
    proofs: Vec<FixedBytes<64>>,
) -> bool {
    // transform to rust-kzg-bn254 inputs types
    // TODO should make library do the parsing the return result
    let lib_blobs: Vec<Blob> = blobs;
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
