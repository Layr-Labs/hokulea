use alloy_primitives::{BlockNumber, B256};
use canoe_provider::CanoeProvider;
use hokulea_proof::eigenda_blob_witness::EigenDABlobWitnessData;

/// Populate canoe proof into cert validity
pub async fn populate_cert_validity_to_witness(
    witness: &mut EigenDABlobWitnessData,
    l1_head: B256,
    l1_head_number: BlockNumber,
    canoe_provider: impl CanoeProvider,
) {
    let num_cert = witness.validity.len();
    for i in 0..num_cert {
        witness.validity[i].l1_head_block_hash = l1_head;
        witness.validity[i].l1_head_block_number = l1_head_number;

        let cert = &witness.eigenda_certs[i];

        let canoe_proof = canoe_provider
            .create_cert_validity_proof(cert.clone(), witness.validity[i].clone())
            .await
            .expect("must be able generate a canoe zk proof attesting eth state");

        let canoe_proof_bytes = serde_json::to_vec(&canoe_proof).expect("serde error");
        witness.validity[i].receipt = canoe_proof_bytes;
    }
}
