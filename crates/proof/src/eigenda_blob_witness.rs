extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::FixedBytes;

use eigenda_v2_struct::EigenDAV2Cert;

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
/// EigenDABlobProvider trait. The other is the zkVM host program, which
/// populates the zk validity proof for the validity
///
/// After witness is populated, PreloadedEigenDABlobProvider takes witness
/// and verify their correctness
///
/// It is important to note that the length of recency, validity and blob
/// might differ when there is stale cert, or a certificate is invalid
/// recency.len() >= validty.len() >= blob.len(), as there are layers of
/// filtering.
/// The vec data struct does not maintain the information about which cert
/// is filtered at which layer. As it does not matter, since the data will
/// be verified in the PreloadedEigenDABlobProvider. And when the derivation
/// pipeline calls for a preimage for a DA cert, the two DA certs must
/// match, and otherwise there is failures. See PreloadedEigenDABlobProvider
/// for more information
/// ToDo, replace EigenDAV2Cert to AltDACommitment, it saves the effort to
/// convert from AltDACommitment to EigenDAV2Cert in all get methods.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EigenDABlobWitnessData {
    /// recency window
    pub recency: Vec<(EigenDAV2Cert, u64)>,
    /// validity of a da cert
    pub validity: Vec<(EigenDAV2Cert, CertValidity)>,
    /// blobs corresponds to a da cert and its kzg proof
    pub blob: Vec<(EigenDAV2Cert, Vec<u8>, FixedBytes<64>)>,
}
