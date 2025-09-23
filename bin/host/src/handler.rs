use alloy_primitives::{keccak256, Bytes};

use crate::cfg::SingleChainHostWithEigenDA;
use crate::status_code::{DerivationError, HostHandlerError, HTTP_RESPONSE_STATUS_CODE_TEAPOT};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_eigenda::HokuleaPreimageError;
use hokulea_eigenda::{
    BYTES_PER_FIELD_ELEMENT, ENCODED_PAYLOAD_HEADER_LEN_BYTES,
    RESERVED_EIGENDA_API_BYTE_FOR_RECENCY, RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY,
    RESERVED_EIGENDA_API_BYTE_INDEX,
};
use hokulea_proof::hint::ExtendedHintType;
use kona_host::SharedKeyValueStore;
use kona_host::{single::SingleChainHintHandler, HintHandler, OnlineHostBackendCfg};
use kona_preimage::{PreimageKey, PreimageKeyType};
use kona_proof::Hint;
use tracing::{info, trace};

/// The [HintHandler] for the [SingleChainHostWithEigenDA].
#[derive(Debug, Clone, Copy)]
pub struct SingleChainHintHandlerWithEigenDA;

#[async_trait]
impl HintHandler for SingleChainHintHandlerWithEigenDA {
    type Cfg = SingleChainHostWithEigenDA;

    /// A wrapper that route eigenda hint and kona hint
    async fn fetch_hint(
        hint: Hint<<Self::Cfg as OnlineHostBackendCfg>::HintType>,
        cfg: &Self::Cfg,
        providers: &<Self::Cfg as OnlineHostBackendCfg>::Providers,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        // route the hint to the right fetcher based on the hint type.
        match hint.ty {
            ExtendedHintType::EigenDACert => {
                fetch_eigenda_hint(hint, cfg, providers, kv).await?;
            }
            ExtendedHintType::Original(ty) => {
                let hint_original = Hint {
                    ty,
                    data: hint.data,
                };
                SingleChainHintHandler::fetch_hint(
                    hint_original,
                    &cfg.kona_cfg,
                    &providers.kona_providers,
                    kv,
                )
                .await?;
            }
        }
        Ok(())
    }
}

/// Fetch the preimages for the given hint and insert then into the key-value store.
/// We insert the recency_window, cert_validity, and encoded_payload_data.
/// For all returned errors, they are handled by the kona host library, and currently this triggers an infinite retry loop.
/// <https://github.com/op-rs/kona/blob/98543fe6d91f755b2383941391d93aa9bea6c9ab/bin/host/src/backend/online.rs#L135>
pub async fn fetch_eigenda_hint(
    hint: Hint<<SingleChainHostWithEigenDA as OnlineHostBackendCfg>::HintType>,
    cfg: &SingleChainHostWithEigenDA,
    providers: &<SingleChainHostWithEigenDA as OnlineHostBackendCfg>::Providers,
    kv: SharedKeyValueStore,
) -> Result<()> {
    let hint_type = hint.ty;
    let altda_commitment_bytes = hint.data;
    trace!(target: "fetcher_with_eigenda_support", "Fetching hint: {hint_type} {altda_commitment_bytes}");

    // Convert commitment bytes to AltDACommitment
    let altda_commitment: AltDACommitment = altda_commitment_bytes
        .as_ref()
        .try_into()
        .map_err(|e| anyhow!("failed to parse AltDACommitment: {e}"))?;

    store_recency_window(kv.clone(), &altda_commitment, cfg).await?;

    // Fetch preimage data and process response
    let derivation_stage = fetch_data_from_proxy(providers, &altda_commitment_bytes).await?;

    // If cert is not recent, log and return early
    if !derivation_stage.is_recent_cert {
        info!(
            target = "hokulea-host",
            "discard a cert for not being recent {}",
            altda_commitment.to_digest(),
        );
        return Ok(());
    }

    // Write validity status to key-value store
    store_cert_validity(
        kv.clone(),
        &altda_commitment,
        derivation_stage.is_valid_cert,
    )
    .await?;

    // If cert is invalid, log and return early
    if !derivation_stage.is_valid_cert {
        info!(
            target = "hokulea-host",
            "discard an invalid cert {}",
            altda_commitment.to_digest(),
        );
        return Ok(());
    }

    // Store encoded payload data field-by-field in key-value store
    store_encoded_payload(
        kv.clone(),
        &altda_commitment,
        derivation_stage.encoded_payload,
    )
    .await?;

    Ok(())
}

/// Store recency window size in key-value store
async fn store_recency_window(
    kv: SharedKeyValueStore,
    altda_commitment: &AltDACommitment,
    cfg: &SingleChainHostWithEigenDA,
) -> Result<()> {
    // Acquire a lock on the key-value store
    let mut kv_write_lock = kv.write().await;

    let rollup_config = cfg
        .kona_cfg
        .read_rollup_config()
        .map_err(|e| anyhow!("should have been able to read rollup config {e}"))?;

    // We use the sequencer_window as the recency_window.
    // See https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#1-rbn-recency-validation
    // for the reasoning behind this choice.
    let recency = rollup_config.seq_window_size;
    let recency_be_bytes = recency.to_be_bytes();
    let mut recency_address = altda_commitment.digest_template();
    recency_address[RESERVED_EIGENDA_API_BYTE_INDEX] = RESERVED_EIGENDA_API_BYTE_FOR_RECENCY;

    kv_write_lock.set(
        PreimageKey::new(*keccak256(recency_address), PreimageKeyType::GlobalGeneric).into(),
        recency_be_bytes.to_vec(),
    )?;

    Ok(())
}

/// Currently Hokulea hosts relies on Eigenda-proxy for preimage retrieval.
/// It relies on the [DerivationError] status code returned by the proxy to decide when to stop retrieving
/// data and return early.  
#[derive(Debug, Clone)]
pub struct ProxyDerivationStage {
    // proxy derivation determines cert is recent
    pub is_recent_cert: bool,
    // proxy derivation determines cert is valid
    pub is_valid_cert: bool,
    // encoded_payload
    pub encoded_payload: Vec<u8>,
}

/// Process response from eigenda network
async fn fetch_data_from_proxy(
    providers: &<SingleChainHostWithEigenDA as OnlineHostBackendCfg>::Providers,
    altda_commitment_bytes: &Bytes,
) -> Result<ProxyDerivationStage> {
    // Fetch the encoded payload from the eigenda network
    let response = providers
        .eigenda_preimage_provider
        .fetch_eigenda_encoded_payload(altda_commitment_bytes)
        .await
        .map_err(|e| anyhow!("failed to fetch eigenda encoded payload: {e}"))?;

    let mut is_valid_cert = true;
    let mut is_recent_cert = true;
    let mut encoded_payload = vec![];

    // Handle response based on status code
    if !response.status().is_success() {
        // Handle non-success response
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
                HokuleaPreimageError::NotRecentCert => is_recent_cert = false,
            },
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
            .map_err(|e| anyhow!("should be able to get encoded payload from http response {e}"))?
            .into();
    }

    Ok(ProxyDerivationStage {
        is_recent_cert,
        is_valid_cert,
        encoded_payload,
    })
}

/// Store certificate validity in key-value store
async fn store_cert_validity(
    kv: SharedKeyValueStore,
    altda_commitment: &AltDACommitment,
    is_valid: bool,
) -> Result<()> {
    // Acquire a lock on the key-value store
    let mut kv_write_lock = kv.write().await;
    let mut validity_address = altda_commitment.digest_template();
    validity_address[RESERVED_EIGENDA_API_BYTE_INDEX] = RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY;

    kv_write_lock.set(
        PreimageKey::new(*keccak256(validity_address), PreimageKeyType::GlobalGeneric).into(),
        vec![is_valid as u8],
    )?;

    Ok(())
}

/// Store encoded payload data in key-value store
async fn store_encoded_payload(
    kv: SharedKeyValueStore,
    altda_commitment: &AltDACommitment,
    encoded_payload: Vec<u8>,
) -> Result<()> {
    // Acquire a lock on the key-value store
    let mut kv_write_lock = kv.write().await;
    // encoded_payload has identical length as eigenda blob
    let blob_length_fe = altda_commitment.get_num_field_element();
    // Verify encoded_payload data is properly formatted
    assert!(encoded_payload.len() % 32 == 0 && !encoded_payload.is_empty());

    // Preliminary defense check against malicious eigenda proxy host
    // Validate field elements (keeping existing field element validation for compatibility)
    let encoded_payload_body = &encoded_payload[ENCODED_PAYLOAD_HEADER_LEN_BYTES..];
    // verify there is an empty byte for every 31 bytes. This is a harder constraint than field element range check.
    for chunk in encoded_payload_body.chunks_exact(BYTES_PER_FIELD_ELEMENT) {
        // very conservative check on Field element range. It allows us to detect
        // misbehaving at the host side when providing the field element. So we can stop early.
        // the field element of on bn254 curve is some number less than 2^254
        // that means both 255 and 254 th bits must be 0. out of conservation, we require the
        // 253 bit to be 0. It aligns with our encoding scheme below that the first 8bits
        // should be 0.
        // Field elements are interpreted as big endian
        // We don't have the check that the first 8 bits are zero, because it is a more restrictive check, that might
        // affect future payload encoding scheme
        if chunk[0] & 0b1110_0000 != 0 {
            return Err(anyhow!("invalid field element encoding"));
        }
    }

    let fetch_num_element = (encoded_payload.len() / BYTES_PER_FIELD_ELEMENT) as u64;
    // Store each field element
    let mut field_element_key = altda_commitment.digest_template();
    for i in 0..blob_length_fe as u64 {
        field_element_key[72..].copy_from_slice(i.to_be_bytes().as_ref());
        let encoded_payload_key_hash = keccak256(field_element_key.as_ref());

        if i < fetch_num_element {
            // Store actual encoded payload data
            kv_write_lock.set(
                PreimageKey::new(*encoded_payload_key_hash, PreimageKeyType::GlobalGeneric).into(),
                encoded_payload[(i as usize) << 5..(i as usize + 1) << 5].to_vec(),
            )?;
        } else {
            // Fill remaining elements with zeros
            kv_write_lock.set(
                PreimageKey::new(*encoded_payload_key_hash, PreimageKeyType::GlobalGeneric).into(),
                vec![0u8; 32],
            )?;
        }
    }

    Ok(())
}
