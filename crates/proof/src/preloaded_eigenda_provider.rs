use crate::eigenda_blob_witness::EigenDABlobWitnessData;
use alloy_primitives::{Bytes, FixedBytes, U256};
use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use eigenda_v2_struct_rust::EigenDAV2Cert;
use hokulea_eigenda::EigenDABlobProvider;
use kona_proof::errors::OracleProviderError;
use kona_preimage::errors::PreimageOracleError;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_verifier::batch;
use tracing::info;
use async_trait::async_trait;

/// PreloadedEigenDABlobProvider ensures the following invariants
/// (P0) Validate validity proof for eigenda cert is correct, regardless if cert itself is correct
/// (P1) Given a cert is valid, then blob and the commitment in the cert must be consistent
/// (P2) Given a cert is invalid, then blob must be empty
#[derive(Clone, Debug, Default)]
pub struct PreloadedEigenDABlobProvider {
    /// The tuple contains EigenDAV2Cert, Blob, isValid cert.
    pub entries: Vec<(EigenDAV2Cert, Blob)>,
}

impl From<EigenDABlobWitnessData> for PreloadedEigenDABlobProvider {
    fn from(value: EigenDABlobWitnessData) -> Self {
        let mut blobs = vec![];
        let mut proofs = vec![];
        let mut commitments = vec![];

        let mut entries = vec![];

        for i in 0..blobs.len() {
            // always verify steel proof if in zkvm mode
            assert!(validate_validity_proof(
                &value.eigenda_certs[i],
                &value.validity_proofs[i]
            ));

            // if valid, check blob kzg integrity
            let is_valid = value.validity_proofs[i].0;
            if is_valid {
                blobs.push(value.eigenda_blobs[i].clone());
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
                value.eigenda_blobs[i].clone(),
            ));
        }

        // check (P1) if cert is not valie, the blob must be empty, assert that commitments in the cert and blobs are consistent
        assert!(batch_verify(blobs, commitments, proofs));

        PreloadedEigenDABlobProvider { entries }
    }
}

#[async_trait]
impl EigenDABlobProvider for PreloadedEigenDABlobProvider {
    // TODO investigate if create a speical error type EigenDABlobProviderError
    type Error = OracleProviderError;

    /// Fetches a blob for V1
    async fn get_blob(&mut self, _cert: &Bytes) -> Result<Bytes, Self::Error> {
        unimplemented!()
    }

    /// Fetches a blob for V2 using preloaded data
    /// Return an error if cert does not match the immeditate next item
    async fn get_blob_v2(&mut self, cert: &EigenDAV2Cert) -> Result<Blob, Self::Error> {
        let (eigenda_cert, eigenda_blob) = self.entries.pop().unwrap();
        if eigenda_cert == *cert {
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
    info!("lib_blobs len {:?}", eigenda_blobs.len());
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

/// Regardless of the validity of the eigenda cert, the steel proof must be valid in testing that the da cert
/// is either right or wrong
pub fn validate_validity_proof(
    _eigenda_certs: &EigenDAV2Cert,
    _validity_proofs: &(bool, Bytes),
) -> bool {
    // TODO: verify the steel proof is valid in a separete PR
    //
    // Current thought Bytes = zkvm seal receipt
    // construct journal part of receipt with _eigenda_certs and bool
    // then call receipt.verify(fpvm_image_id)
    // https://github.com/risc0/kailua/blob/448170c324c55be996e4541dbc3bbf5ef6d77e95/crates/common/src/stitching.rs#L73
    //
    // #[cfg(target_os = "zkvm")]
    // env::verify(DACERT_V2_VERIFIER_ID, &serde::to_vec(&n).unwrap()).unwrap();
    true
}
