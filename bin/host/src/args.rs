use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct HostArgs {
    #[clap(flatten)]
    pub kona_cfg: kona_host::HostCli,

    /// URL of the Ethereum RPC endpoint.
    #[clap(flatten)]
    pub eigenda_args: EigenDaArgs,
}

#[derive(Parser, Debug, Clone)]
pub struct EigenDaArgs {
    /// URL of the Ethereum RPC endpoint.
    #[clap(long, env)]
    #[arg(required = false)]
    pub eigenda_proxy_address: Option<String>,
}
