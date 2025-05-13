//! Main entrypoint for the example binary, which runs both host and client

use clap::Parser;
use hokulea_host_bin::{cfg::SingleChainHostWithEigenDA, init_tracing_subscriber};
use kona_client::fpvm_evm::FpvmOpEvmFactory;
use kona_preimage::{BidirectionalChannel, HintWriter, OracleReader};
use tokio::task;

use hokulea_example_common_preloader::run_witgen_and_zk_verification;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cfg = SingleChainHostWithEigenDA::try_parse()?;
    init_tracing_subscriber(cfg.verbose)?;

    let hint = BidirectionalChannel::new()?;
    let preimage = BidirectionalChannel::new()?;

    let server_task = cfg.start_server(hint.host, preimage.host).await?;

    cfg_if::cfg_if! {
        if #[cfg(feature = "steel")] {
            use canoe_steel_apps::apps::CanoeSteelProvider;
            use hokulea_proof::canoe_verifier::steel::CanoeSteelVerifier;
            let canoe_provider = CanoeSteelProvider{
                eth_rpc_url: cfg.kona_cfg.l1_node_address.clone().unwrap(),
            };
            let canoe_verifier = CanoeSteelVerifier{};
        } else if #[cfg(feature = "sp1-cc")] {
            use canoe_sp1_cc_host::CanoeSp1CCProvider;
            use hokulea_proof::canoe_verifier::sp1_cc::CanoeSp1CCVerifier;
            let canoe_provider = CanoeSp1CCProvider{
                eth_rpc_url: cfg.kona_cfg.l1_node_address.clone().unwrap(),
            };
            let canoe_verifier = CanoeSp1CCVerifier{};
        } else {
            use canoe_provider::CanoeNoOpProvider;
            use hokulea_proof::canoe_verifier::noop::CanoeNoOpVerifier;
            let canoe_provider = CanoeNoOpProvider{};
            let canoe_verifier = CanoeNoOpVerifier{};
        }
    }

    // Spawn the client logic as a concurrent task
    let client_task = task::spawn(run_witgen_and_zk_verification(
        OracleReader::new(preimage.client.clone()),
        HintWriter::new(hint.client.clone()),
        FpvmOpEvmFactory::new(
            HintWriter::new(hint.client),
            OracleReader::new(preimage.client),
        ),
        canoe_provider,
        canoe_verifier,
    ));

    let (_, client_result) = tokio::try_join!(server_task, client_task)?;

    // Bubble up the exit status of the client program if execution completes.
    std::process::exit(client_result.is_err() as i32)
}
