//! [RecencyWindowProvider] allows custom recency window
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum RecencyWindowProviderError {
    /// Invalid Cert validity response
    #[error("Unable to fetch recency for chain id {0}")]
    UnknownChainIDForRecencyWindow(u64),
}

pub trait RecencyWindowProvider: Clone + Send + 'static {
    /// fetch recency window. The return unit is measured in l1 block number
    fn fetch_recency_window(
        &self,
        chain_id: u64,
        blocknumber: u64,
        timestamp: u64,
    ) -> Result<u64, RecencyWindowProviderError>;
}

/// [ConnstantRecencyWindowProvider] sets recency window to the
/// constant value supplied by the user
#[derive(Clone)]
pub struct ConnstantRecencyWindowProvider {
    pub value: u64,
}

impl RecencyWindowProvider for ConnstantRecencyWindowProvider {
    /// fetch recency window
    fn fetch_recency_window(
        &self,
        chain_id: u64,
        _blocknumber: u64,
        _timestamp: u64,
    ) -> Result<u64, RecencyWindowProviderError> {
        match chain_id {
            // mainnet
            1 => Ok(self.value),
            // sepolia
            11155111 => Ok(self.value),
            // kurtosis devnet
            3151908 => Ok(self.value),
            _ => Err(RecencyWindowProviderError::UnknownChainIDForRecencyWindow(
                chain_id,
            )),
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
    fn fetch_recency_window(
        &self,
        chain_id: u64,
        _blocknumber: u64,
        _timestamp: u64,
    ) -> Result<u64, RecencyWindowProviderError> {
        warn!(
            "Setting recency window to 0 disable the recency check. It opens the door for
            malicious batch posting valid certs whose data has been dropped by the DA network"
        );
        match chain_id {
            // mainnet
            1 => Ok(0),
            // sepolia
            11155111 => Ok(0),
            // kurtosis devnet
            3151908 => Ok(0),
            _ => Err(RecencyWindowProviderError::UnknownChainIDForRecencyWindow(
                chain_id,
            )),
        }
    }
}
