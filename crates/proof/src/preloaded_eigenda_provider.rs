use alloy_primitives::{B256, Bytes};
use kzg_crypto::EigenDABlobWitness;
use eigenda_v2_struct_rust::v2_cert::rs_struct::EigenDAV2Cert;


#[derive(Clone, Debug, Default)]
pub struct PreloadedEigenDABlobProvider {
    entries: Vec<(EigenDAV2Cert, Bytes, bool)>,
}

impl From<EigenDABlobWitness> for PreloadedBlobProvider {
    fn from(value: EigenDABlobWitness) -> Self {
        return PreloadedBlobProvider {
            entries: 
        }
    }
}
