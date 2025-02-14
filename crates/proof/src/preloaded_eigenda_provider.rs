use alloy_primitives::{B256, Bytes};

#[derive(Clone, Debug, Default)]
pub struct PreloadedEigenDABlobProvider {
    entries: Vec<(B256, Bytes)>,
}

impl From<EigenDABlobWitness> for PreloadedBlobProvider {

}