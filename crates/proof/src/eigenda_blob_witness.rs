extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::FixedBytes;

use eigenda_cert::AltDACommitment;

use crate::cert_validity::CertValidity;
use serde::{Deserialize, Serialize};

/// EigenDABlobWitnessData contains preimage data to be provided into
/// the zkVM as part of Preimage Oracle. Those data have three categories.
/// In each category, we group (DA cert, preimage data) into a tuple, such
/// that there is one-to-one mapping from DA cert to the value.
/// It is possible that the same DA certs are populated twice especially
/// batcher is misbehaving. The data structures preserve this information.
///
/// Two actors populates EigenDABlobWitnessData. One is the
/// OracleEigenDAWitnessProvider which takes preimage data from the
/// EigenDABlobProvider during the first run of the
/// derivation pipeline. OracleEigenDAWitnessProvider wraps around an
/// implementaion of EigenDABlobProvider trait to populate blob and recency.
///
/// The remaining validity part is populated by a separator actor, usually in the
/// zkVM host, which requests zk prover for generating zk validity proof.
/// Although it is possible to move this logics into OracleEigenDAWitnessProvider,
/// we can lose the benefit of proving aggregation. Moreover, it is up to
/// the zkVM host to choose its the proving backend. Baking validity generation
/// into the OracleEigenDAWitnessProvider is less ideal.
///
/// After witness is populated, PreloadedEigenDABlobProvider takes witness
/// and verify their correctness
///
/// It is important to note that the length of recency, validity and blob
/// might differ when there is stale cert, or a certificate is invalid
/// recency.len() >= validity.len() >= blob.len(), as there are layers of
/// filtering.
/// The vec data struct does not maintain the information about which cert
/// is filtered at which layer. As it does not matter, since the data will
/// be verified in the PreloadedEigenDABlobProvider. And when the derivation
/// pipeline calls for a preimage for a DA cert, the two DA certs must
/// match, and otherwise there is failures. See PreloadedEigenDABlobProvider
/// for more information
/// TODO, replace EigenDACertV2 to AltDACommitment, it saves the effort to
/// convert from AltDACommitment to EigenDACertV2 in all get methods.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EigenDABlobWitnessData {
    /// u64 containing the recency_window
    pub recency: Vec<(AltDACommitment, u64)>,
    /// validity of a da cert
    pub validity: Vec<(AltDACommitment, CertValidity)>,
    /// blobs corresponds to a da cert and its kzg proof
    pub blob: Vec<(AltDACommitment, Vec<u8>, FixedBytes<64>)>,
    /// used and populated at the end of canoe proof
    /// it should only deserialize to one zk proof that proves all DA certs are
    /// correct
    pub canoe_proof_bytes: Option<Vec<u8>>,
}

impl EigenDABlobWitnessData {
    /// require_canoe_proof checks if there is at least one canoe proof needed for any DAcerts
    /// in the eigenda blob derivation
    pub fn require_canoe_proof(&self) -> bool {
        !self.validity.is_empty()
    }
}
