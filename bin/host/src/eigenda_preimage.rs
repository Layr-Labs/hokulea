use alloy_primitives::{hex, Bytes};
use anyhow::{anyhow, Result};
use core::num::NonZeroUsize;
use lru::LruCache;
use reqwest::{self, Url};

use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_eigenda::{
    EigenDAPreimageProvider, EncodedPayload, HokuleaErrorKind, HokuleaPreimageError,
};

use crate::status_code::{DerivationError, HostHandlerError, HTTP_RESPONSE_STATUS_CODE_TEAPOT};

/// Currently Hokulea hosts relies on Eigenda-proxy for preimage retrieval.
/// It relies on the [DerivationError] status code returned by the proxy to decide when to stop retrieving
/// data and return early.  
#[derive(Debug, Clone)]
pub struct ProxyDerivationStage {
    // if cert has been attested by DA network and offchain derivation version is correct
    pub is_valid_cert: bool,
    // if recency test is passed
    pub pass_recency_check: bool,
    // encoded_payload
    pub encoded_payload: Vec<u8>,
}

/// Fetches preimage from EigenDA via an eigenda-proxy instance.
#[derive(Debug, Clone)]
pub struct OnlineEigenDAPreimageProvider {
    /// The base url.
    base: Url,
    /// The inner reqwest client. Used to talk to proxy
    inner: reqwest::Client,
    /// LRU cache with key being the serialized AltDA commitment
    lru: LruCache<Bytes, ProxyDerivationStage>,
}

// Query parameters configuration for proxy behavior:
// - commitment_mode=optimism_generic: Specifies the commitment mode (default even if not specified)
// - return_encoded_payload=true: Instructs proxy to return encoded payload instead of decoded rollup payload
// - Without these params: proxy returns decoded rollup payload by default
// - Secure integration requires encoded payload to allow derivation pipeline to handle decoding
const GET_QUERY_PARAMS_ENCODED_PAYLOAD: &str =
    "commitment_mode=optimism_generic&return_encoded_payload=true";

impl OnlineEigenDAPreimageProvider {
    /// Creates a new instance of the [OnlineEigenDAPreimageProvider].
    ///
    /// The `genesis_time` and `slot_interval` arguments are _optional_ and the
    /// [OnlineEigenDAPreimageProvider] will attempt to load them dynamically at runtime if they are not
    /// provided.
    pub fn new_http(base: String) -> Result<Self> {
        let base = Url::parse(&base).map_err(|e| anyhow!("invalid base URL: {e}"))?;
        let inner = reqwest::Client::new();
        // LRU cache holds the 8 most recent entries. The typical access pattern is:
        // 1. get_validity() populates the cache
        // 2. get_encoded_payload() retrieves the same entry immediately after
        // The size of 8 allows for parallel processing, though Hokulea currently processes serially.
        let lru = LruCache::new(NonZeroUsize::new(8).expect("N must be greater than 0"));
        Ok(Self { base, inner, lru })
    }

    /// Fetch data from proxy without caching (takes `&self` for handler usage).
    pub async fn fetch_data_from_proxy(
        &self,
        altda_commitment_bytes: &Bytes,
    ) -> Result<ProxyDerivationStage> {
        // Build URL with proper joining and query parameters
        let commitment_hex = hex::encode(altda_commitment_bytes);
        let mut url = self
            .base
            .join(&format!("get/{commitment_hex}"))
            .map_err(|e| anyhow!("failed to construct URL: {e}"))?;
        url.set_query(Some(GET_QUERY_PARAMS_ENCODED_PAYLOAD));

        // Fetch the encoded payload from the eigenda network
        let response = self
            .inner
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("failed to fetch eigenda encoded payload: {e}"))?;

        let mut is_valid_cert = true;
        let mut pass_recency_check = true;
        let mut encoded_payload = vec![];

        // Handle response based on status code
        if !response.status().is_success() {
            // Handle non-success responses. 400 errors are not possible here since the altda commitment
            // deserialized successfully to reach this point. All 500 errors trigger infinite retries.
            if response.status().as_u16() != HTTP_RESPONSE_STATUS_CODE_TEAPOT {
                // The error is handled by host library in kona, currently this triggers an infinite retry loop.
                // https://github.com/op-rs/kona/blob/98543fe6d91f755b2383941391d93aa9bea6c9ab/bin/host/src/backend/online.rs#L135
                return Err(anyhow!(
                    "failed to fetch eigenda encoded payload, status {:?}",
                    response.error_for_status()
                ));
            }

            // Handle teapot (418) status code with DerivationError
            let status_code: DerivationError = response
                .json()
                .await
                .map_err(|e| anyhow!("failed to deserialize 418 body: {e}"))?;

            match status_code.into() {
                HostHandlerError::HokuleaPreimageError(c) => match c {
                    HokuleaPreimageError::InvalidCert => is_valid_cert = false,
                },
                HostHandlerError::HokuleaRecencyCheckError => pass_recency_check = false,
                HostHandlerError::HokuleaEncodedPayloadDecodingError(e)
                | HostHandlerError::IllogicalStatusCodeError(e)
                | HostHandlerError::UndefinedStatusCodeError(e) => {
                    return Err(anyhow!("failed to handle http response: {e}"))
                }
            }
        } else {
            // Handle success response
            encoded_payload = response
                .bytes()
                .await
                .map_err(|e| {
                    anyhow!("should be able to get encoded payload from http response {e}")
                })?
                .into();
        }

        let derivation_stage = ProxyDerivationStage {
            pass_recency_check,
            is_valid_cert,
            encoded_payload,
        };

        Ok(derivation_stage)
    }

    /// Cached fetch. `&mut self` provides exclusive access, no Mutex needed.
    async fn get_or_fetch_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<ProxyDerivationStage, HokuleaErrorKind> {
        let altda_commitment_bytes = altda_commitment.to_rlp_bytes().into();

        // Check cache first
        if let Some(cached) = self.lru.get(&altda_commitment_bytes) {
            return Ok(cached.clone());
        }

        // Not in cache, fetch from proxy
        let derivation_stage = self
            .fetch_data_from_proxy(&altda_commitment_bytes)
            .await
            .map_err(|e| HokuleaErrorKind::Temporary(format!("fetch failed: {e}")))?;

        self.lru
            .put(altda_commitment_bytes.clone(), derivation_stage.clone());
        Ok(derivation_stage)
    }
}

#[async_trait]
impl EigenDAPreimageProvider for OnlineEigenDAPreimageProvider {
    type Error = HokuleaErrorKind;

    /// Query preimage about the validity of a DA cert
    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        let derivation_stage = self.get_or_fetch_payload(altda_commitment).await?;
        Ok(derivation_stage.is_valid_cert)
    }

    /// Get encoded payload
    async fn get_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<EncodedPayload, Self::Error> {
        let derivation_stage = self.get_or_fetch_payload(altda_commitment).await?;
        Ok(EncodedPayload {
            encoded_payload: derivation_stage.encoded_payload.into(),
        })
    }
}
