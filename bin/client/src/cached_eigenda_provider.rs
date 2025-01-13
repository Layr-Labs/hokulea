use kona_preimage::CommsClient;
use kona_preimage::errors::PreimageOracleError;
use alloy_primitives::Bytes;
use async_trait::async_trait;
use alloy_rlp::Decodable;

use kona_proof::errors::OracleProviderError;
use hokulea_proof::eigenda_provider::OracleEigenDAProvider;
use hokulea_eigenda::EigenDABlobProvider;
use hokulea_eigenda::BlobInfo;

use crate::witness::EigenDABlobWitness;

use rust_kzg_bn254::kzg::KZG;
use rust_kzg_bn254::blob::Blob;
use num::BigUint;


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
impl <T: CommsClient + Sync + Send> EigenDABlobProvider for CachedOracleEigenDAProvider<T> {
    type Error = OracleProviderError;

    async fn get_blob(&mut self, cert: &Bytes) -> Result<Bytes, Self::Error> {
        match self.oracle.get_blob(cert).await {
            Ok(b) => {
                let item_slice = cert.as_ref();
                let cert_blob_info = match BlobInfo::decode(&mut &item_slice[4..]) {
                    Ok(c) => c,
                    Err(_) => return Err(OracleProviderError::Preimage(
                        PreimageOracleError::Other("does not contain header".into(),
                    ))),
                };

                let output = self.compute_and_save_witness(&b)?;
                // make sure locally computed proof equals to returned proof from the provider
                if output[..32] != cert_blob_info.blob_header.commitment.x[..] ||
                   output[32..64] != cert_blob_info.blob_header.commitment.y[..]{
                    return Err(OracleProviderError::Preimage(
                        PreimageOracleError::Other("proxy commitment is different from computed commitment proxy".into())));
                };

                let commitment = Bytes::copy_from_slice(
                    &[cert_blob_info.blob_header.commitment.x, cert_blob_info.blob_header.commitment.y]
                    .concat());

                let kzg_proof = Bytes::copy_from_slice(&output[64..128]);

                // push data into witness
                self.witness.write(b.clone().into(), commitment, kzg_proof.into());

                Ok(b.into())
            },
            Err(e) => Err(e),
        }
    }
}


// nitro code https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L30
impl<T: CommsClient + Sync + Send> CachedOracleEigenDAProvider<T> {
    fn compute_and_save_witness(&mut self, blob: &[u8]) -> Result<Vec<u8>, OracleProviderError> {
        // TODO remove the need for G2 access
        // Add command line to specify where are g1 and g2 path
        // In the future, it might make sense to let the proxy to return such
        // value, instead of local computation
        let mut kzg = match KZG::setup(
            "resources/g1.32mb.point",
            "",
            "resources/g2.point.powerOf2",
            268435456,
            1024,
        ) {
            Ok(k) => k,
            Err(_) => return Err(OracleProviderError::Preimage(
                    PreimageOracleError::Other("does not contain header".into(),
                ))),
        };

        let input = Blob::new(blob);
        let input_poly = input.to_polynomial_eval_form();

        kzg.data_setup_custom(1, input.len().try_into().unwrap()).unwrap();

        let mut output = vec![0u8; 0];

        let commitment = match kzg.commit_eval_form(&input_poly) {
            Ok(c) => c,
            Err(_) => return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                        "kzg.commit_eval_form".into()))),
        };

        // TODO the library should have returned the bytes, or provide a helper
        // for conversion. For both proof and commitment
        let commitment_x_bigint: BigUint = commitment.x.into();
        let commitment_y_bigint: BigUint = commitment.y.into();

        self.append_left_padded_biguint_be(&mut output, &commitment_x_bigint);
        self.append_left_padded_biguint_be(&mut output, &commitment_y_bigint);

        let proof = match kzg.compute_blob_proof(&input, &commitment) {
            Ok(p) => p,
            Err(_) => return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                        "kzg.compute_blob_kzg_proof {}".into()))),
        };
        let proof_x_bigint: BigUint = proof.x.into();
        let proof_y_bigint: BigUint = proof.y.into();

        self.append_left_padded_biguint_be(&mut output, &proof_x_bigint);
        self.append_left_padded_biguint_be(&mut output, &proof_y_bigint);

        Ok(output)
    }

    pub fn append_left_padded_biguint_be(&self, vec: &mut Vec<u8>, biguint: &BigUint) {
        let bytes = biguint.to_bytes_be();
        let padding = 32 - bytes.len();
        vec.extend(std::iter::repeat(0).take(padding));
        vec.extend_from_slice(&bytes);
    }

}
