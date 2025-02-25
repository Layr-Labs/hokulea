use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct EigenDaArgs {
    #[clap(flatten)]
    pub kona_cfg: kona_host::HostCli,

    /// URL of the Ethereum RPC endpoint.
    #[clap(long, env)]
    #[arg(required = true)]
    pub eigenda_proxy_address: Option<String>,
}
