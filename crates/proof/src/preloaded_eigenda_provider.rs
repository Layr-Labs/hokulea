use crate::eigenda_witness::EigenDAWitness;
use crate::errors::HokuleaOracleProviderError;
use alloy_primitives::FixedBytes;
use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use async_trait::async_trait;
use eigenda_cert::{AltDACommitment, G1Point};
use hokulea_eigenda::{EigenDAPreimageProvider, EncodedPayload};
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_verifier::batch;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use canoe_verifier::CanoeVerifier;

/// PreloadedEigenDAPreimageProvider converts EigenDAWitness into preimage data
/// can be used to implement the EigenDAPreimageProvider trait, that contains
///   get_recency_window
///   get_validity
///   get_encoded_payload
///
/// For each function above, internally PreloadedEigenDAPreimageProvider maintain a separate
/// struct in the form of a tuple (AltDACommitment, expected preimage).
///
/// This allows a safety checks that PreloadedEigenDAPreimageProvider
/// ensues all provided preimage is binding and correct with respect to the AltDA commitment.
///
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
    /// This function is only responsible for checking if the provided preimage is correct.
    /// It does not perform the filtering operation taking place in eigenda blob derivation.
    /// It implies that an adversarial prover can supply a stale altda commitment, then supply
    /// canoe proof for proving the cert is valid or invalid. However, during the eigenda blob derivation
    /// that only the recency preimage corresponding to the altda commitment is popped, and
    /// the vailidity corresponding to it stil remains in the vec. If it is the last altda commitment
    /// the validity is left unused. If it is not the last, the next altda commitment will panic
    /// due to unmatched key.
    /// The Canoe proof validates all the validity all at once.
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

        // check all altda commitment validity are supported by zk validity proof
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
            // populate only the mapping <DAcert, boolean> for preimage trait, by this time it has been verified
            validity_entries.push((altda_commitment.clone(), cert_validity.claimed_validity));
        }

        let mut encoded_payload_entries = vec![];

        // check all blobs correponds to cert are correct
        let mut blobs = vec![];
        let mut proofs = vec![];
        let mut commitments = vec![];

        for (cert, encoded_payload, kzg_proof) in value.encoded_payloads {
            // populate entries ahead of time, if something is invalid, batch_verify will abort
            encoded_payload_entries.push((cert.clone(), encoded_payload.clone()));

            // gather kzg commitment and proof for batch verification
            let blob =
                Blob::new(encoded_payload.serialize()).expect("should be able to construct a blob");
            blobs.push(blob);
            proofs.push(kzg_proof);
            commitments.push(cert.get_kzg_commitment());
        }

        assert!(batch_verify(&blobs, &commitments, &proofs));
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
    // The error is a place holder, we intentionally abort everything
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

/// Eventually, rust-kzg-bn254 would provide an interface that takes big endian
/// bytes input, so that we can remove this wrapper. For now, just include it here
/// the proving locates inside hokulea-compute-proof crate
pub fn batch_verify(blobs: &[Blob], commitments: &[G1Point], proofs: &[FixedBytes<64>]) -> bool {
    // transform to rust-kzg-bn254 inputs types
    // TODO should make library do the parsing the return result
    let lib_blobs: &[Blob] = blobs;
    let lib_commitments: Vec<G1Affine> = commitments
        .iter()
        .map(|c| {
            let a: [u8; 32] = c.x.to_be_bytes();
            let b: [u8; 32] = c.y.to_be_bytes();
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
    batch::verify_blob_kzg_proof_batch(lib_blobs, &lib_commitments, &lib_proofs).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{hex, Bytes, U256};
    use canoe_verifier::{CanoeNoOpVerifier, CertValidity};
    use eigenda_cert::AltDACommitment;
    use num::BigUint;
    use rust_kzg_bn254_primitives::errors::KzgError;
    use rust_kzg_bn254_primitives::helpers::read_g1_point_from_bytes_be;
    use rust_kzg_bn254_prover::{kzg::KZG, srs::SRS};

    // first 128 bytes of resources/g1.point corresponding to 4 g1 points
    pub const G1_POINTS_BYTE: &str = "8000000000000000000000000000000000000000000000000000000000000001cbfc87ecbdcdc23ef5481bb179aaada7f42c22d2dfd52b4655a18c2879c54eea9fb27cc0e2465b3e57a42a051dbfbd8d0b62eec80cd07c46401781deab36ca27c44ab250113840f37622eb001cfbcb1dec55f15e6ea48333ddb63e9d2befecab";

    pub fn compute_kzg_commitment(blob: &Blob) -> Result<G1Point, KzgError> {
        let mut kzg = KZG::new();
        kzg.calculate_and_store_roots_of_unity(blob.len() as u64)
            .unwrap();

        let input_poly = blob.to_polynomial_eval_form();
        let commitment = kzg.commit_eval_form(&input_poly, &get_g1_points())?;

        // TODO the rust bn254 library should have returned the bytes, or provide a helper
        // for conversion. For both proof and commitment
        let commitment_x_bigint: BigUint = commitment.x.into();
        let commitment_y_bigint: BigUint = commitment.y.into();

        let commitment_x_bytes =
            hokulea_compute_proof::convert_biguint_to_be_32_bytes(&commitment_x_bigint);
        let commitment_y_bytes =
            hokulea_compute_proof::convert_biguint_to_be_32_bytes(&commitment_y_bigint);

        Ok(G1Point {
            x: U256::from_be_bytes(commitment_x_bytes),
            y: U256::from_be_bytes(commitment_y_bytes),
        })
    }

    fn compute_kzg_proof_and_commitment(
        encoded_payload_inner: Vec<u8>,
    ) -> (Blob, G1Point, FixedBytes<64>) {
        let encoded_payload = EncodedPayload {
            encoded_payload: encoded_payload_inner.into(),
        };
        let kzg_proof = hokulea_compute_proof::compute_kzg_proof_with_srs(
            encoded_payload.serialize(),
            &get_g1_points(),
        )
        .expect("should be able to produce a proof");
        let kzg_proof_fixed_bytes: FixedBytes<64> = FixedBytes::from_slice(kzg_proof.as_ref());

        let encoded_payload_serialized = encoded_payload.serialize();

        // The encoded payload is a polynomial presented in its evaluation form
        let blob =
            Blob::new(encoded_payload_serialized).expect("should be able to construct a blob");

        // produce a kzg commitment
        let kzg_commitment = compute_kzg_commitment(&blob).unwrap();

        (blob, kzg_commitment, kzg_proof_fixed_bytes)
    }

    fn get_g1_points() -> SRS {
        let g1_points_bytes = hex::decode(G1_POINTS_BYTE).unwrap();

        let g1_srs = vec![
            read_g1_point_from_bytes_be(&g1_points_bytes[..32]).unwrap(),
            read_g1_point_from_bytes_be(&g1_points_bytes[32..64]).unwrap(),
            read_g1_point_from_bytes_be(&g1_points_bytes[64..96]).unwrap(),
            read_g1_point_from_bytes_be(&g1_points_bytes[96..128]).unwrap(),
        ];
        SRS {
            g1: g1_srs,
            order: 4,
        }
    }

    // witness data that can be verified correctly with a no op canoe verifier
    fn prepare_ok_data() -> EigenDAWitness {
        let encoded_payload_inner = vec![
            0, 0, 0, 0, 0, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1,
        ];
        let calldata: Bytes = alloy_primitives::hex::decode("0x010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001").unwrap().into();
        let mut altda_commitment: AltDACommitment = calldata[..].try_into().unwrap();

        let claimed_false_cert_validity = CertValidity::default();
        let mut claimed_true_cert_validity = claimed_false_cert_validity.clone();
        claimed_true_cert_validity.claimed_validity = true;

        let (_, commitment, proof) =
            compute_kzg_proof_and_commitment(encoded_payload_inner.clone());
        match &mut altda_commitment.versioned_cert {
            eigenda_cert::EigenDAVersionedCert::V2(c) => {
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment = commitment;
            }
            eigenda_cert::EigenDAVersionedCert::V3(c) => {
                c.blob_inclusion_info
                    .blob_certificate
                    .blob_header
                    .commitment
                    .commitment = commitment;
            }
        };

        EigenDAWitness {
            recencies: vec![(altda_commitment.clone(), 1)],
            validities: vec![(altda_commitment.clone(), claimed_true_cert_validity.clone())],
            encoded_payloads: vec![(
                altda_commitment.clone(),
                EncodedPayload {
                    encoded_payload: encoded_payload_inner.into(),
                },
                proof,
            )],
            canoe_proof_bytes: Some(Vec::new()),
        }
    }

    fn prepare_data_with_invalid_encoded_payload() -> EigenDAWitness {
        let mut ok_data = prepare_ok_data();
        // turn the first byte of encoded payload to all 1
        ok_data.encoded_payloads[0].1.encoded_payload = vec![
            255, 0, 0, 0, 0, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1,
        ]
        .into();
        ok_data
    }

    #[test]
    fn test_batch_verify() {
        let encoded_payload_inner_1 = vec![
            0, 0, 0, 0, 0, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1,
        ];
        // though this not a valid encoded payload, but it is a valid blob
        let encoded_payload_inner_2 = vec![
            0, 1, 1, 1, 1, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1,
        ];

        let batch_encoded_payload = vec![encoded_payload_inner_1, encoded_payload_inner_2];

        // collects arrays
        let mut blobs = Vec::with_capacity(batch_encoded_payload.len());
        let mut commitments = Vec::with_capacity(batch_encoded_payload.len());
        let mut proofs = Vec::with_capacity(batch_encoded_payload.len());

        for (blob, commitment, proof) in batch_encoded_payload
            .into_iter()
            .map(compute_kzg_proof_and_commitment)
        {
            blobs.push(blob);
            commitments.push(commitment);
            proofs.push(proof);
        }

        assert!(batch_verify(&blobs, &commitments, &proofs));
        let mut proofs = proofs.clone();

        // switch order of proof 0 and 1 should be enough to corrupt
        proofs.swap(0, 1);

        assert!(!batch_verify(&blobs, &commitments, &proofs));

        // corrupt proof by using the second srs as proof
        assert!(!batch_verify(&blobs[..1], &commitments[..1], &proofs[..1]));
    }

    #[tokio::test]
    async fn test_from_witness_ok_0_preimage() {
        let preimage = PreloadedEigenDAPreimageProvider::from_witness(
            EigenDAWitness::default(),
            CanoeNoOpVerifier {},
        );
        assert_eq!(preimage.encoded_payload_entries.len(), 0);
        assert_eq!(preimage.validity_entries.len(), 0);
        assert_eq!(preimage.recency_entries.len(), 0);
    }

    // no more preimage available
    #[tokio::test]
    #[should_panic]
    async fn test_from_witness_ok_and_preimage_provider() {
        let eigenda_witness = prepare_ok_data();
        let altda_commitment = eigenda_witness.recencies[0].0.clone();

        let mut preimage = PreloadedEigenDAPreimageProvider::from_witness(
            eigenda_witness.clone(),
            CanoeNoOpVerifier {},
        );
        assert_eq!(
            preimage
                .get_recency_window(&altda_commitment)
                .await
                .unwrap(),
            eigenda_witness.recencies[0].1
        );
        assert_eq!(
            preimage.get_validity(&altda_commitment).await.unwrap(),
            eigenda_witness.validities[0].1.claimed_validity
        );
        assert_eq!(
            preimage
                .get_encoded_payload(&altda_commitment)
                .await
                .unwrap(),
            eigenda_witness.encoded_payloads[0].1
        );
        let _ = preimage.get_encoded_payload(&altda_commitment).await;
    }

    // unknown key
    #[tokio::test]
    #[should_panic]
    async fn test_from_witness_panic_unknown_key_recency() {
        let eigenda_witness = prepare_ok_data();
        let mut altda_commitment = eigenda_witness.recencies[0].0.clone();
        altda_commitment.da_layer_byte = 255;
        let mut preimage = PreloadedEigenDAPreimageProvider::from_witness(
            eigenda_witness.clone(),
            CanoeNoOpVerifier {},
        );
        let _ = preimage.get_recency_window(&altda_commitment).await;
    }

    // unknown key
    #[tokio::test]
    #[should_panic]
    async fn test_from_witness_panic_unknown_key_validity() {
        let eigenda_witness = prepare_ok_data();
        let mut altda_commitment = eigenda_witness.recencies[0].0.clone();
        altda_commitment.da_layer_byte = 255;
        let mut preimage = PreloadedEigenDAPreimageProvider::from_witness(
            eigenda_witness.clone(),
            CanoeNoOpVerifier {},
        );
        let _ = preimage.get_validity(&altda_commitment).await;
    }

    // unknown key
    #[tokio::test]
    #[should_panic]
    async fn test_from_witness_panic_unknown_key_encoded_payload() {
        let eigenda_witness = prepare_ok_data();
        let mut altda_commitment = eigenda_witness.recencies[0].0.clone();
        altda_commitment.da_layer_byte = 255;
        let mut preimage = PreloadedEigenDAPreimageProvider::from_witness(
            eigenda_witness.clone(),
            CanoeNoOpVerifier {},
        );
        let _ = preimage.get_encoded_payload(&altda_commitment).await;
    }

    // length violation validity = 2 recency = 1
    #[tokio::test]
    #[should_panic]
    async fn test_from_witness_length_violation_recency_validity() {
        let mut eigenda_witness = prepare_ok_data();
        eigenda_witness
            .validities
            .extend(eigenda_witness.validities.clone());
        let _ = PreloadedEigenDAPreimageProvider::from_witness(
            eigenda_witness.clone(),
            CanoeNoOpVerifier {},
        );
    }

    // length violation validity = 1 recency = 1 encoded_payload = 2
    #[tokio::test]
    #[should_panic]
    async fn test_from_witness_length_violation_validity_encoded_payload() {
        let mut eigenda_witness = prepare_ok_data();
        eigenda_witness
            .encoded_payloads
            .extend(eigenda_witness.encoded_payloads.clone());
        let _ = PreloadedEigenDAPreimageProvider::from_witness(
            eigenda_witness.clone(),
            CanoeNoOpVerifier {},
        );
    }

    // invalid encoded payload that is not a field element, failed when creating a blob
    #[tokio::test]
    #[should_panic]
    async fn test_from_witness_not_field_element() {
        let eigenda_witness = prepare_data_with_invalid_encoded_payload();
        let _ = PreloadedEigenDAPreimageProvider::from_witness(
            eigenda_witness.clone(),
            CanoeNoOpVerifier {},
        );
    }
}
