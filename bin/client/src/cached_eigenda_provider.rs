use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use async_trait::async_trait;
use kona_preimage::errors::PreimageOracleError;
use kona_preimage::CommsClient;

use hokulea_eigenda::BlobInfo;
use hokulea_eigenda::EigenDABlobProvider;
use hokulea_proof::eigenda_provider::OracleEigenDAProvider;
use kona_proof::errors::OracleProviderError;

use crate::witness::EigenDABlobWitness;

use num::BigUint;
use rust_kzg_bn254::blob::Blob;
use rust_kzg_bn254::kzg::KZG;

/// CachedOracleEigenDAProvider is a wrapper outside OracleEigenDAProvider. Its intended use
/// case is to fetch all eigenda blobs received during the derivation pipeline. So that it
/// is able to compute and cache the kzg witnesses, which can be verified inside ZKVM by checking
/// the point opening at the random Fiat Shamir evaluation index.
#[derive(Debug, Clone)]
pub struct CachedOracleEigenDAProvider<T: CommsClient> {
    /// The preimage oracle client.
    oracle: OracleEigenDAProvider<T>,
    /// kzg proof witness
    witness: EigenDABlobWitness,
}

impl<T: CommsClient> CachedOracleEigenDAProvider<T> {
    /// Constructs a new oracle-backed EigenDA provider.
    pub fn new(oracle: OracleEigenDAProvider<T>, witness: EigenDABlobWitness) -> Self {
        Self { oracle, witness }
    }
}

#[async_trait]
impl<T: CommsClient + Sync + Send> EigenDABlobProvider for CachedOracleEigenDAProvider<T> {
    type Error = OracleProviderError;

    async fn get_blob(&mut self, cert: &Bytes) -> Result<Bytes, Self::Error> {
        let blob = self.oracle.get_blob(cert).await?;
        let cert_blob_info = match BlobInfo::decode(&mut &cert[4..]) {
            Ok(c) => c,
            Err(_) => {
                return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                    "does not contain header".into(),
                )))
            }
        };

        let output = self.compute_witness(&blob)?;
        // make sure locally computed proof equals to returned proof from the provider
        if output[..32] != cert_blob_info.blob_header.commitment.x[..]
            || output[32..64] != cert_blob_info.blob_header.commitment.y[..]
        {
            return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                "proxy commitment is different from computed commitment proxy".into(),
            )));
        };

        let commitment = Bytes::copy_from_slice(&output[..64]);

        let kzg_proof = Bytes::copy_from_slice(&output[64..128]);

        // push data into witness
        self.witness
            .write(blob.clone().into(), commitment, kzg_proof.into());

        Ok(blob)
    }
}

// nitro code https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L141
// could refactor in the future, such that both host and client can compute the proof
impl<T: CommsClient + Sync + Send> CachedOracleEigenDAProvider<T> {
    /// Return Bytes array so that the host can reuse the code
    fn compute_witness(&mut self, blob: &[u8]) -> Result<Vec<u8>, OracleProviderError> {
        // TODO remove the need for G2 access
        // Add command line to specify where are g1 and g2 path
        // In the future, it might make sense to let the proxy to return such
        // value, instead of local computation
        let mut kzg = KZG::setup(
            "resources/g1.32mb.point",
            "",
            "resources/g2.point.powerOf2",
            268435456,
            1024,
        )
        .map_err(|_| {
            OracleProviderError::Preimage(PreimageOracleError::Other(
                "does not contain header".into(),
            ))
        })?;

        let input = Blob::new(blob);
        let input_poly = input.to_polynomial_eval_form();

        kzg.data_setup_custom(1, input.len().try_into().unwrap())
            .unwrap();

        let mut commitment_and_proof = vec![0u8; 0];

        let commitment = kzg.commit_eval_form(&input_poly).map_err(|_| {
            OracleProviderError::Preimage(PreimageOracleError::Other("kzg.commit_eval_form".into()))
        })?;

        // TODO the library should have returned the bytes, or provide a helper
        // for conversion. For both proof and commitment
        let commitment_x_bigint: BigUint = commitment.x.into();
        let commitment_y_bigint: BigUint = commitment.y.into();

        self.append_left_padded_biguint_be(&mut commitment_and_proof, &commitment_x_bigint);
        self.append_left_padded_biguint_be(&mut commitment_and_proof, &commitment_y_bigint);

        let proof = kzg.compute_blob_proof(&input, &commitment).map_err(|_| {
            OracleProviderError::Preimage(PreimageOracleError::Other(
                "kzg.compute_blob_kzg_proof {}".into(),
            ))
        })?;
        let proof_x_bigint: BigUint = proof.x.into();
        let proof_y_bigint: BigUint = proof.y.into();

        self.append_left_padded_biguint_be(&mut commitment_and_proof, &proof_x_bigint);
        self.append_left_padded_biguint_be(&mut commitment_and_proof, &proof_y_bigint);

        Ok(commitment_and_proof)
    }

    pub fn append_left_padded_biguint_be(&self, vec: &mut Vec<u8>, biguint: &BigUint) {
        let bytes = biguint.to_bytes_be();
        let padding = 32 - bytes.len();
        vec.extend(std::iter::repeat(0).take(padding));
        vec.extend_from_slice(&bytes);
    }
}
