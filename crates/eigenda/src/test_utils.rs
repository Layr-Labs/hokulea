//! An implementation of the [EigenDAPreimageProvider] trait for tests.

use crate::errors::HokuleaErrorKind;
use crate::{EigenDAPreimageProvider, EncodedPayload};
use alloy_primitives::{map::HashMap, B256};
use eigenda_cert::AltDACommitment;

use alloc::boxed::Box;
use alloc::string::ToString;
use async_trait::async_trait;

/// Custom hokulea preimage error
#[derive(Debug, Clone, thiserror::Error)]
pub enum TestHokuleaProviderError {
    /// Preimage returned something, but the returned value is invalid
    #[error("Invalid Cert query response")]
    InvalidHokuleaPreimageQueryResponse,
    /// Preimage Oracle error from kona
    /// <https://github.com/op-rs/kona/blob/174b2ac5ad3756d4469553c7777b04056f9d151c/crates/proof/proof/src/errors.rs#L18>
    #[error("Preimage oracle error")]
    Preimage,
}

impl From<TestHokuleaProviderError> for HokuleaErrorKind {
    fn from(val: TestHokuleaProviderError) -> Self {
        match val {
            TestHokuleaProviderError::InvalidHokuleaPreimageQueryResponse => {
                HokuleaErrorKind::Critical("Invalid hokulea preimage response".to_string())
            }
            // in kona, all Preimage error are grouped into backend error <https://github.com/op-rs/kona/blob/4ef01882824b84d078ead9f834f4f78213dd6ef3/crates/protocol/derive/src/sources/blobs.rs#L136>
            // which is considered a temp issue
            TestHokuleaProviderError::Preimage => {
                HokuleaErrorKind::Temporary("Preimage temporary error".to_string())
            }
        }
    }
}

// a mock object implements the EigenDAPreimageProvider trait
#[derive(Debug, Clone, Default)]
pub(crate) struct TestEigenDAPreimageProvider {
    pub recencies: HashMap<B256, Result<u64, TestHokuleaProviderError>>,
    pub validities: HashMap<B256, Result<bool, TestHokuleaProviderError>>,
    pub encoded_payloads: HashMap<B256, Result<EncodedPayload, TestHokuleaProviderError>>,
    // a backend error propogated to the client
    pub should_preimage_err: bool,
    // an invalid response error
    pub should_response_err: bool,
}

impl TestEigenDAPreimageProvider {
    pub(crate) fn insert_recency(
        &mut self,
        altda_commitment: &AltDACommitment,
        recency: Result<u64, TestHokuleaProviderError>,
    ) {
        self.recencies.insert(altda_commitment.to_digest(), recency);
    }

    pub(crate) fn insert_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
        validity: Result<bool, TestHokuleaProviderError>,
    ) {
        self.validities
            .insert(altda_commitment.to_digest(), validity);
    }

    pub(crate) fn insert_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
        encoded_payload: Result<EncodedPayload, TestHokuleaProviderError>,
    ) {
        self.encoded_payloads
            .insert(altda_commitment.to_digest(), encoded_payload);
    }
}

#[async_trait]
impl EigenDAPreimageProvider for TestEigenDAPreimageProvider {
    type Error = TestHokuleaProviderError;

    async fn get_recency_window(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<u64, Self::Error> {
        if self.should_preimage_err {
            return Err(TestHokuleaProviderError::Preimage);
        }
        if self.should_response_err {
            return Err(TestHokuleaProviderError::InvalidHokuleaPreimageQueryResponse);
        }

        self.recencies
            .get(&altda_commitment.to_digest())
            .unwrap()
            .clone()
    }

    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        if self.should_preimage_err {
            return Err(TestHokuleaProviderError::Preimage);
        }
        if self.should_response_err {
            return Err(TestHokuleaProviderError::InvalidHokuleaPreimageQueryResponse);
        }

        self.validities
            .get(&altda_commitment.to_digest())
            .unwrap()
            .clone()
    }

    async fn get_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<EncodedPayload, Self::Error> {
        if self.should_preimage_err {
            return Err(TestHokuleaProviderError::Preimage);
        }
        if self.should_response_err {
            return Err(TestHokuleaProviderError::InvalidHokuleaPreimageQueryResponse);
        }

        self.encoded_payloads
            .get(&altda_commitment.to_digest())
            .unwrap()
            .clone()
    }
}
