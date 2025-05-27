use alloc::string::ToString;
use hokulea_eigenda::HokuleaErrorKind;
use kona_preimage::errors::PreimageOracleError;

/// Custom hokulea preimage error
#[derive(Debug, thiserror::Error)]
pub enum HokuleaOracleProviderError {
    /// Invalid Cert validity response
    #[error("Invalid Cert query response")]
    InvalidCertQueryResponse,
    /// Preimage informs the client that DA cert is wrong
    #[error("Invalid DA certificate")]
    InvalidCert,
    /// Preimage Oracle error from kona
    /// <https://github.com/op-rs/kona/blob/174b2ac5ad3756d4469553c7777b04056f9d151c/crates/proof/proof/src/errors.rs#L18>
    #[error("Preimage oracle error: {0}")]
    Preimage(#[from] PreimageOracleError),
}

impl From<HokuleaOracleProviderError> for HokuleaErrorKind {
    fn from(val: HokuleaOracleProviderError) -> Self {
        match val {
            HokuleaOracleProviderError::InvalidCertQueryResponse => {
                HokuleaErrorKind::Critical("Invalid certificate response".to_string())
            }
            HokuleaOracleProviderError::InvalidCert => {
                HokuleaErrorKind::Discard("Invalid certificate".to_string())
            }
            // in kona, all Preimage error are grouped into backend error <https://github.com/op-rs/kona/blob/4ef01882824b84d078ead9f834f4f78213dd6ef3/crates/protocol/derive/src/sources/blobs.rs#L136>
            // which is considered a temp issue
            HokuleaOracleProviderError::Preimage(e) => HokuleaErrorKind::Temporary(e.to_string()),
        }
    }
}
