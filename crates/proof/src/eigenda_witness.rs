//! Define three data structures [EigenDAPreimage] [EigenDAWitness] [EigenDAWitnessWithTrustedData]
//! [EigenDAPreimage] contains purely eigenda preimage after running derivation pipeline. It can be
//! converted into [EigenDAWitness] with appropriate proofs. [EigenDAWitnessWithTrustedData] contains
//! in addition to a list of trusted input which are required for cert validity verification.
extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::{FixedBytes, B256};

use eigenda_cert::AltDACommitment;
use hokulea_eigenda::EncodedPayload;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EigenDAWitnessError {
    #[error("Missing canoe proof given there is at least one cert requiring validity proof")]
    MissingCanoeProof,
    #[error("The number of kzg proofs is different from number of encoded payload to be proven")]
    MismatchKzgProof,
}

/// [EigenDAPreimage] contains all preimages retrieved via preimage provider while
/// executing the eigenda blob derivation. It is [EigenDAWitness] without any proofs
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EigenDAPreimage {
    /// validity of a da cert
    pub validities: Vec<(AltDACommitment, bool)>,
    /// encoded_payload corresponds to a da cert and its kzg proof
    pub encoded_payloads: Vec<(AltDACommitment, EncodedPayload)>,
}

/// EigenDAWitness contains preimage and witness data to be provided into
/// the zkVM as part of Preimage Oracle. There are three types of preimages: 1. recency,
/// 2. validity, 3. encoded payload.
/// In each type, we group (DA cert, preimage data) into a tuple, such
/// that there is one-to-one mapping from DA cert to the value.
/// It is possible that the same DA certs are populated twice especially
/// batcher is misbehaving. The data structures preserve this information.
///
/// Two actors populates EigenDAWitness. One is the
/// OracleEigenDAPreimageProvider which takes preimage data from the
/// EigenDAPreimageProvider during the first run of the
/// derivation pipeline. OracleEigenDAPreimageProvider wraps around an
/// implementaion of EigenDAPreimageProvider trait to populate encoded_payloads and recencies.
///
/// The remaining validity part is populated by a separator actor, usually in the
/// zkVM host, which requests zk prover for generating zk validity proof.
/// Although it is possible to move this logics into OracleEigenDAPreimageProvider,
/// we can lose the benefit of proving aggregation. Moreover, it is up to
/// the zkVM host to choose its the proving backend. Baking validity generation
/// into the OracleEigenDAPreimageProvider is less ideal.
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
    /// validity of a da cert
    pub validities: Vec<(AltDACommitment, bool)>,
    /// encoded_payload corresponds to a da cert and its kzg proof
    pub encoded_payloads: Vec<(AltDACommitment, EncodedPayload, FixedBytes<64>)>,
    /// used and populated at the end of canoe proof
    /// it should only deserialize to one zk proof that proves all DA certs are
    /// correct
    pub canoe_proof_bytes: Option<Vec<u8>>,
}

impl EigenDAWitness {
    /// convert [EigenDAPreimage] into witnes data. It enforces there must be a canoe proof
    /// if there is at least one required validity proof, and the number of KZG proof must
    /// match number of encoded payload.
    pub fn from_preimage(
        preimage: EigenDAPreimage,
        kzg_proofs: Vec<FixedBytes<64>>,
        canoe_proof: Option<Vec<u8>>,
    ) -> Result<EigenDAWitness, EigenDAWitnessError> {
        if (!preimage.validities.is_empty()) && canoe_proof.is_none() {
            return Err(EigenDAWitnessError::MissingCanoeProof);
        }
        let mut encoded_payloads_with_kzg_proof = Vec::new();

        if kzg_proofs.len() != preimage.encoded_payloads.len() {
            return Err(EigenDAWitnessError::MismatchKzgProof);
        }

        for (i, proof) in kzg_proofs.iter().enumerate() {
            encoded_payloads_with_kzg_proof.push((
                preimage.encoded_payloads[i].0.clone(),
                preimage.encoded_payloads[i].1.clone(),
                *proof,
            ))
        }

        let witness = EigenDAWitness {
            validities: preimage.validities,
            encoded_payloads: encoded_payloads_with_kzg_proof,
            canoe_proof_bytes: canoe_proof,
        };
        Ok(witness)
    }
}

/// [EigenDAWitnessWithTrustedData] contains [EigenDAWitness] with a list of
/// trusted input data source. Those are either already verified or will be verified without
/// modification. In practice, all of data can be found in verified oracle BootInfo, or Header
/// corresponding to the l1_head from BootInfo.
/// zkVM crate provides an example method `eigenda_witness_to_preloaded_provider` to convert a
/// [EigenDAWitness] to [EigenDAWitnessWithTrustedData] using a trusted oracle, which has been
/// populated the trusted l1_head_block_hash and its corresponding header used to populate all
/// the fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EigenDAWitnessWithTrustedData {
    /// block hash where view call anchored at, it must be part of l1 canonical chain
    /// where l1_head from kona_cfg is also a part of
    pub l1_head_block_hash: B256,
    // l1_head_block_number for l1_head_block_hash
    pub l1_head_block_number: u64,
    // l1_head_block_timestamp for l1_head_block_hash
    pub l1_head_block_timestamp: u64,
    /// l1 chain id specifies the chain which implicitly along with l1_head_block_number
    /// indicates the current EVM version due to hardfork.
    pub l1_chain_id: u64,
    // eigenDA witness
    pub witness: EigenDAWitness,
}
