//! Define two data structures [EigenDAPreimage] and [EigenDAWitness].
//! [EigenDAPreimage] contains purely eigenda preimage after running derivation pipeline. It can be
//! converted into [EigenDAWitness] with appropriate proofs.
extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::FixedBytes;

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
/// the zkVM as part of Preimage Oracle. There are three types of preimages:
/// 1. validity of (da cert and consistent offchain derivation version),
/// 2. encoded payload
///
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
/// validities.len() >= encoded_payloads.len(), as there are layers of
/// filtering.
/// The vec data struct does not maintain the information about which cert
/// is filtered at which layer. As it does not matter, since the data will
/// be verified in the PreloadedEigenDAPreimageProvider. And when the derivation
/// pipeline calls for a preimage for a DA cert, the two DA certs must
/// match, and otherwise there is failures. See PreloadedEigenDAPreimageProvider
/// for more information
#[derive(Default, Debug, Clone, Serialize, Deserialize)] //
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)] //
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
    /// Constructs an [EigenDAWitness] from a preimage without validation. Use [Self::from_preimage]
    /// if the inputs have not been prechecked.
    pub fn from_preimage_unchecked(
        preimage: EigenDAPreimage,
        kzg_proofs: Vec<FixedBytes<64>>,
        canoe_proof_bytes: Option<Vec<u8>>,
    ) -> EigenDAWitness {
        EigenDAWitness {
            validities: preimage.validities,
            encoded_payloads: preimage
                .encoded_payloads
                .into_iter()
                .zip(kzg_proofs)
                .map(|((commitment, payload), proof)| (commitment, payload, proof))
                .collect(),
            canoe_proof_bytes,
        }
    }

    /// Constructs an [EigenDAWitness] from a preimage, validating that a canoe proof is present
    /// when there is at least one validity entry, and that the number of KZG proofs matches the
    /// number of encoded payloads.
    pub fn from_preimage(
        preimage: EigenDAPreimage,
        kzg_proofs: Vec<FixedBytes<64>>,
        canoe_proof: Option<Vec<u8>>,
    ) -> Result<EigenDAWitness, EigenDAWitnessError> {
        if (!preimage.validities.is_empty()) && canoe_proof.is_none() {
            return Err(EigenDAWitnessError::MissingCanoeProof);
        }
        if kzg_proofs.len() != preimage.encoded_payloads.len() {
            return Err(EigenDAWitnessError::MismatchKzgProof);
        }
        Ok(Self::from_preimage_unchecked(
            preimage,
            kzg_proofs,
            canoe_proof,
        ))
    }

    /// Deconstruct [EigenDAWitness] back into its component parts: preimage, KZG proofs, and canoe proof.
    /// This is the inverse operation of [Self::from_preimage].
    pub fn into_preimage(self) -> (EigenDAPreimage, Vec<FixedBytes<64>>, Option<Vec<u8>>) {
        let (encoded_payloads, kzg_proofs): (Vec<_>, Vec<_>) = self
            .encoded_payloads
            .into_iter()
            .map(|(commitment, payload, kzg_proof)| ((commitment, payload), kzg_proof))
            .unzip();

        let preimage = EigenDAPreimage {
            validities: self.validities,
            encoded_payloads,
        };

        (preimage, kzg_proofs, self.canoe_proof_bytes)
    }
}
