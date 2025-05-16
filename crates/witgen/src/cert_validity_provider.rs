use alloy_primitives::{BlockNumber, B256};
use canoe_provider::{CanoeInput, CanoeProvider};
use hokulea_proof::eigenda_blob_witness::EigenDABlobWitnessData;

/// Populate canoe proof into cert validity. It assumes that during the first run of derivation
/// pipeline that eigenda_certs, eigenda_blobs and kzg_proof are already populated. The complete
/// [EigenDABlobWitnessData] still misses cert validity field that requires a canoe proof.
/// The goal of this function is to populate such canoe proof proving the cert is correct.
/// It is placed inside the normal crate because canoe currently assumes serde_json for serialization.
/// But probably a better idea is to define the trait within canoe provider and verifier.
pub async fn populate_cert_validity_to_witness(
    witness: &mut EigenDABlobWitnessData,
    l1_head: B256,
    l1_head_number: BlockNumber,
    canoe_provider: impl CanoeProvider,
    l1_chain_id: u64,
) {
    let num_cert = witness.validity.len();
    for i in 0..num_cert {
        witness.validity[i].l1_head_block_hash = l1_head;

        let canoe_input = CanoeInput {
            eigenda_cert: witness.eigenda_certs[i].clone(),
            claimed_validity: witness.validity[i].claimed_validity,
            l1_head_block_hash: l1_head,
            l1_head_block_number: l1_head_number,
            l1_chain_id,
        };

        let canoe_proof = canoe_provider
            .create_cert_validity_proof(canoe_input)
            .await
            .expect("must be able generate a canoe zk proof attesting eth state");

        let canoe_proof_bytes = serde_json::to_vec(&canoe_proof).expect("serde error");
        witness.validity[i].canoe_proof = canoe_proof_bytes;
    }
}
