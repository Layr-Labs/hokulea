
use kona_preimage::errors::PreimageOracleError;
use hokulea_eigenda::HokuleaErrorKind;

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
            HokuleaOracleProviderError::InvalidCert => HokuleaErrorKind::Discard,
            HokuleaOracleProviderError::Preimage(e) => HokuleaErrorKind::Temporary,
        }
    }
}