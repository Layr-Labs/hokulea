//! An example to test V3 cert against Sepolia
//! Note eigenda proxy has not yet supported V3 cert, but it would come soon

use alloy_provider::{Provider, ProviderBuilder};
use canoe_provider::{CanoeInput, CanoeProvider};
use canoe_verifier::{CanoeVerifier, CertValidity, HokuleaCanoeVerificationError};
use canoe_verifier_address_fetcher::{
    CanoeVerifierAddressFetcher, CanoeVerifierAddressFetcherDeployedByEigenLabs,
};

use canoe_steel_apps::apps::CanoeSteelProvider;
use canoe_steel_verifier::CanoeSteelVerifier;
use clap::Parser;
use eigenda_cert::AltDACommitment;

use std::str::FromStr;
use url::Url;

#[derive(Parser)]
struct Args {
    /// Ethereum RPC endpoint URL
    #[arg(long, env = "ETH_RPC_URL")]
    eth_rpc_url: String,
}

/// a rlp encoded V2 DA cert generated on June 2nd 2025 on Sepolia testnet
pub const V2_CERT_RLP_BYTES: &[u8] = include_bytes!("../data/v2_cert_rlp.bin");

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::try_parse()?;

    // parse the cert from the file and we know ahead of time that the cert is correct
    let v2_cert_rlp_vec = Vec::from(V2_CERT_RLP_BYTES);
    let validity = true;

    let canoe_address_fetcher = CanoeVerifierAddressFetcherDeployedByEigenLabs {};

    let canoe_input = get_canoe_input(
        &v2_cert_rlp_vec,
        validity,
        args.eth_rpc_url.clone(),
        canoe_address_fetcher.clone(),
    )
    .await?;

    // value to be used for zk verification
    let altda_commitment = canoe_input.altda_commitment.clone();
    let l1_head_block_hash = canoe_input.l1_head_block_hash;
    let claimed_validity = validity;

    // create canoe proof
    let canoe_provider = CanoeSteelProvider {
        eth_rpc_url: args.eth_rpc_url.clone(),
    };
    let receipt = canoe_provider
        .create_certs_validity_proof(vec![canoe_input])
        .await
        .unwrap()?;
    let canoe_proof_bytes = serde_json::to_vec(&receipt).expect("serde error");

    // prepare value to verify canoe proof
    let cert_validity = CertValidity {
        claimed_validity,
        l1_head_block_hash,
        l1_chain_id: 11155111,
        verifier_address: canoe_address_fetcher
            .fetch_address(11155111, &altda_commitment.versioned_cert)?,
    };
    verify_canoe_proof(
        cert_validity.clone(),
        altda_commitment.clone(),
        canoe_proof_bytes,
    )
    .expect("correct proof should have passed");
    println!("cert verification pass");

    Ok(())
}

// this function takes canoe proof and verify it
pub fn verify_canoe_proof(
    cert_validity: CertValidity,
    altda_commitment: AltDACommitment,
    canoe_proof_bytes: Vec<u8>,
) -> Result<(), HokuleaCanoeVerificationError> {
    // verify canoe proof
    let canoe_verifier = CanoeSteelVerifier {};
    let validity_cert_pair = (altda_commitment, cert_validity);
    canoe_verifier.validate_cert_receipt(vec![validity_cert_pair], Some(canoe_proof_bytes))
}

/// It is a helper function that prepares canoe input which can be used to generate a
/// zk validity or invalidity proof.
/// This function provides takes the latest block tip for l1_block_hash and block_number
pub async fn get_canoe_input(
    v2_cert_rlp_vec: &[u8],
    validity: bool,
    eth_rpc_url: String,
    canoe_address_fetcher: impl CanoeVerifierAddressFetcher,
) -> anyhow::Result<CanoeInput> {
    let altda_commitment = AltDACommitment::try_from(v2_cert_rlp_vec)
        .expect("should be able to convert bytes to altda commitment");

    let eth_rpc_url = Url::from_str(&eth_rpc_url).unwrap();

    let provider = ProviderBuilder::new().connect_http(eth_rpc_url);

    let provider_chain_id = provider
        .get_chain_id()
        .await
        .expect("should have received chain ID");
    if provider_chain_id != 11155111 {
        panic!("the provided rpc does not point to sepolia");
    }

    // Get the latest block number
    let block_number = provider.get_block_number().await?;
    println!("Latest block number: {block_number}");

    let block_opt = provider.get_block_by_number(block_number.into()).await?;

    let block = block_opt.ok_or_else(|| anyhow::anyhow!("block {block_number} not found"))?;

    let header = block.header.into_consensus();

    // get header
    let l1_block_hash = header.hash_slow();

    Ok(CanoeInput {
        altda_commitment: altda_commitment.clone(),
        claimed_validity: validity,
        l1_head_block_hash: l1_block_hash,
        l1_head_block_number: block_number,
        l1_chain_id: 11155111,
        verifier_address: canoe_address_fetcher
            .fetch_address(11155111, &altda_commitment.versioned_cert)?,
    })
}
