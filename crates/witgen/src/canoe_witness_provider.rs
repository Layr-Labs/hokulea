use alloy_consensus::Header;
use alloy_rlp::Decodable;
use canoe_provider::{CanoeInput, CanoeProvider};
use canoe_verifier_address_fetcher::CanoeVerifierAddressFetcher;
use hokulea_proof::eigenda_witness::EigenDAPreimage;
use kona_preimage::{PreimageKey, PreimageOracleClient};
use kona_proof::BootInfo;
use tracing::info;

/// A helper function to create canoe proof by the provided canoe provider.
/// The function relies on data stored in the oracle, for l1_head, l1_head_header.number
/// and chain_id.
///
/// If no canoe proof is needed, it returns Ok(None)
pub async fn from_boot_info_to_canoe_proof<A, P, O>(
    boot_info: &BootInfo,
    eigenda_preimage: &EigenDAPreimage,
    oracle: &O,
    canoe_provider: P,
    canoe_address_fetcher: A,
) -> anyhow::Result<Option<P::Receipt>>
where
    A: CanoeVerifierAddressFetcher,
    P: CanoeProvider,
    O: PreimageOracleClient,
{
    let header_rlp = oracle
        .get(PreimageKey::new_keccak256(*boot_info.l1_head))
        .await?;
    let l1_head_header = Header::decode(&mut header_rlp.as_slice())
        .map_err(|_| anyhow::Error::msg("cannot rlp decode header in canoe proof generation"))?;
    let l1_chain_id = boot_info.rollup_config.l1_chain_id;

    let mut canoe_inputs = vec![];

    if eigenda_preimage.validities.is_empty() {
        info!(target: "canoe witness provider", "no DA certs to process, skipping canoe proof generation");
    } else {
        info!(target: "canoe witness provider", "producing 1 canoe proof for {} DA certs", eigenda_preimage.validities.len());
    }

    for (altda_commitment, claimed_validity) in &eigenda_preimage.validities {
        let canoe_input = CanoeInput {
            altda_commitment: altda_commitment.clone(),
            claimed_validity: *claimed_validity,
            l1_head_block_hash: boot_info.l1_head,
            l1_head_block_number: l1_head_header.number,
            l1_chain_id,
            verifier_address: canoe_address_fetcher
                .fetch_address(l1_chain_id, &altda_commitment.versioned_cert, None)?,
        };
        canoe_inputs.push(canoe_input);
    }

    match canoe_provider
        .create_certs_validity_proof(canoe_inputs)
        .await
    {
        Some(result) => {
            let proof = result?;
            Ok(Some(proof))
        }
        None => Ok(None),
    }
}
