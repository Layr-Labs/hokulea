use alloy_consensus::Header;
use alloy_rlp::Decodable;
use canoe_provider::{CanoeInput, CanoeProvider};
use core::fmt::Debug;
use hokulea_proof::canoe_verifier::cert_verifier_address;
use hokulea_proof::eigenda_blob_witness::EigenDABlobWitnessData;
use hokulea_proof::canoe_verifier::cert_verifier_address;
use kona_preimage::{CommsClient, PreimageKey};
use kona_proof::{BootInfo, FlushableCache};
use std::sync::Arc;

/// A helper function to create canoe proof by the provided canoe provider.
/// The function relies on data stored in the oracle, for l1_head, l1_head_header.number
/// and chain_id.
pub async fn from_boot_info_to_canoe_proof<P, O>(
    boot_info: &BootInfo,
    witness: &EigenDABlobWitnessData,
    oracle: Arc<O>,
    canoe_provider: P,
) -> anyhow::Result<P::Receipt>
where
    P: CanoeProvider,
    O: CommsClient + FlushableCache + Send + Sync + Debug,
{
    let header_rlp = oracle
        .get(PreimageKey::new_keccak256(*boot_info.l1_head))
        .await?;
    let l1_head_header = Header::decode(&mut header_rlp.as_slice())
        .map_err(|_| anyhow::Error::msg("cannot rlp decode header in canoe proof generation"))?;
    let l1_chain_id = boot_info.rollup_config.l1_chain_id;

    let mut wit = witness.clone();

    // generate canoe proof
    wit.validity.iter_mut().for_each(|(_, cert_validity)| {
        cert_validity.l1_head_block_hash = boot_info.l1_head;
    });

    let mut canoe_inputs = vec![];

    for (altda_commitment, cert_validity) in &mut wit.validity {
        let canoe_input = CanoeInput {
            altda_commitment: altda_commitment.clone(),
            claimed_validity: cert_validity.claimed_validity,
            l1_head_block_hash: boot_info.l1_head,
            l1_head_block_number: l1_head_header.number,
            l1_chain_id,
            verifier_address: cert_verifier_address(l1_chain_id, altda_commitment),
        };
        canoe_inputs.push(canoe_input);
    }

    let canoe_proof = canoe_provider
        .create_certs_validity_proof(canoe_inputs)
        .await?;

    Ok(canoe_proof)
}
