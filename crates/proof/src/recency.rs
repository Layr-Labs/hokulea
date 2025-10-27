//! [RecencyWindowProvider] allows custom recency window
use tracing::warn;

pub trait RecencyWindowProvider: Clone + Send + 'static {
    /// fetch recency window. The return unit is measured in l1 block number
    fn fetch_recency_window(&self, chain_id: u64, blocknumber: u64, timestamp: u64) -> u64;
}

/// [ConstantRecencyWindowProvider] sets recency window to the
/// constant value supplied by the user
#[derive(Clone)]
pub struct ConstantRecencyWindowProvider {
    pub value: u64,
}

impl RecencyWindowProvider for ConstantRecencyWindowProvider {
    /// fetch recency window
    fn fetch_recency_window(&self, chain_id: u64, _blocknumber: u64, _timestamp: u64) -> u64 {
        match chain_id {
            // mainnet
            1 => self.value,
            // sepolia
            11155111 => self.value,
            // holesky
            17000 => self.value,
            // kurtosis devnet
            3151908 => self.value,
            _ => panic!("cannot fetch recency window for unsupported chain id {chain_id}"),
        }
    }
}

/// The [DisabledZeroRecencyWindowProvider] sets recency window to 0 in all cases.
/// It effectively disable the recency checks, allowing all altda commitment to
/// pass the derivation pipeline.
#[derive(Clone)]
pub struct DisabledZeroRecencyWindowProvider {}

impl RecencyWindowProvider for DisabledZeroRecencyWindowProvider {
    /// fetch recency window for
    fn fetch_recency_window(&self, chain_id: u64, _blocknumber: u64, _timestamp: u64) -> u64 {
        warn!(
            "Setting recency window to 0 disable the recency check. It opens the door for
            malicious batch posting valid certs whose data has been dropped by the DA network"
        );
        match chain_id {
            // mainnet
            1 => 0,
            // sepolia
            11155111 => 0,
            // holesky
            17000 => 0,
            // kurtosis devnet
            3151908 => 0,
            _ => panic!("cannot fetch recency window for unsupported chain id {chain_id}"),
        }
    }
}
