use alloc::string::ToString;
use hokulea_eigenda::HokuleaErrorKind;
use kona_preimage::errors::PreimageOracleError;

#[derive(Debug, thiserror::Error)]
pub enum HokuleaOracleProviderError {
    #[error("Invalid DA certificate")]
    InvalidCert,
    #[error("Preimage oracle error: {0}")]
    Preimage(#[from] PreimageOracleError),
}

impl From<HokuleaOracleProviderError> for HokuleaErrorKind {
    fn from(val: HokuleaOracleProviderError) -> Self {
        match val {
            HokuleaOracleProviderError::InvalidCert => {
                HokuleaErrorKind::Discard("Invalid certificate".to_string())
            }
            HokuleaOracleProviderError::Preimage(e) => HokuleaErrorKind::Temporary(e.to_string()),
        }
    }
}
