extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::FixedBytes;

use eigenda_cert::AltDACommitment;
use hokulea_eigenda::EncodedPayload;

use crate::cert_validity::CertValidity;
use serde::{Deserialize, Serialize};

/// EigenDAWitness contains preimage and witness data to be provided into
/// the zkVM as part of Preimage Oracle. There are three types of preimages: 1. recency,
/// 2. validity, 3. encoded payload.
/// In each type, we group (DA cert, preimage data) into a tuple, such
/// that there is one-to-one mapping from DA cert to the value.
/// It is possible that the same DA certs are populated twice especially
/// batcher is misbehaving. The data structures preserve this information.
///
/// Two actors populates EigenDAWitness. One is the
/// OracleEigenDAWitnessProvider which takes preimage data from the
/// EigenDAPreimageProvider during the first run of the
/// derivation pipeline. OracleEigenDAWitnessProvider wraps around an
/// implementaion of EigenDAPreimageProvider trait to populate encoded_payloads and recencies.
///
/// The remaining validity part is populated by a separator actor, usually in the
/// zkVM host, which requests zk prover for generating zk validity proof.
/// Although it is possible to move this logics into OracleEigenDAWitnessProvider,
/// we can lose the benefit of proving aggregation. Moreover, it is up to
/// the zkVM host to choose its the proving backend. Baking validity generation
/// into the OracleEigenDAWitnessProvider is less ideal.
///
/// After witness is populated, PreloadedEigenDAPreimageProvider takes witness
/// and verify their correctness
///
/// It is important to note that the length of recencies, validities and encoded_payloads
/// might differ when there is stale cert, or a certificate is invalid
/// recencies.len() >= validities.len() >= encoded_payloads.len(), as there are layers of
/// filtering.
/// The vec data struct does not maintain the information about which cert
/// is filtered at which layer. As it does not matter, since the data will
/// be verified in the PreloadedEigenDAPreimageProvider. And when the derivation
/// pipeline calls for a preimage for a DA cert, the two DA certs must
/// match, and otherwise there is failures. See PreloadedEigenDAPreimageProvider
/// for more information
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EigenDAWitness {
    /// u64 containing the recency_window
    pub recencies: Vec<(AltDACommitment, u64)>,
    /// validity of a da cert
    pub validities: Vec<(AltDACommitment, CertValidity)>,
    /// encoded_payload corresponds to a da cert and its kzg proof
    pub encoded_payloads: Vec<(AltDACommitment, EncodedPayload, FixedBytes<64>)>,
    /// used and populated at the end of canoe proof
    /// it should only deserialize to one zk proof that proves all DA certs are
    /// correct
    pub canoe_proof_bytes: Option<Vec<u8>>,
}

impl EigenDAWitness {
    /// require_canoe_proof checks if there is at least one canoe proof needed for any DAcerts
    /// in the eigenda blob derivation
    pub fn require_canoe_proof(&self) -> bool {
        !self.validities.is_empty()
    }
}
