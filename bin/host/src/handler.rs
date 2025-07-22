use alloy_primitives::{keccak256, Bytes};

use crate::cfg::SingleChainHostWithEigenDA;
use crate::status_code::{DerivationError, HostHandlerError, HTTP_RESPONSE_STATUS_CODE_TEAPOT};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_eigenda::{EigenDABlobData, HokuleaPreimageError};
use hokulea_eigenda::{
    BYTES_PER_FIELD_ELEMENT, PAYLOAD_ENCODING_VERSION_0, RESERVED_EIGENDA_API_BYTE_FOR_RECENCY,
    RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY, RESERVED_EIGENDA_API_BYTE_INDEX,
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

/// Fetch the preimage for the given hint and insert it into the key-value store.
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
        .expect("the hokulea client should have checked the AltDACommitment conversion");

    // Store recency window size based on sequencing window size
    set_recency_window(kv.clone(), &altda_commitment, cfg).await?;

    // Fetch blob data and process response
    let (is_valid, is_recent, rollup_data) =
        process_eigenda_response(providers, &altda_commitment_bytes).await?;

    // If cert is not recent, log and return early
    if !is_recent {
        info!(
            target = "hokulea-host",
            "discard a cert for not being recent {}",
            altda_commitment.to_digest(),
        );
        return Ok(());
    }

    // Write validity status to key-value store
    store_cert_validity(kv.clone(), &altda_commitment, is_valid).await?;

    // If cert is invalid, log and return early
    if !is_valid {
        info!(
            target = "hokulea-host",
            "discard an invalid cert {}",
            altda_commitment.to_digest(),
        );
        return Ok(());
    }

    // Store blob data field-by-field in key-value store
    store_blob_data(kv.clone(), &altda_commitment, rollup_data).await?;

    Ok(())
}

/// Store recency window size in key-value store
async fn set_recency_window(
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

/// Process response from eigenda network
async fn process_eigenda_response(
    providers: &<SingleChainHostWithEigenDA as OnlineHostBackendCfg>::Providers,
    altda_commitment_bytes: &Bytes,
) -> Result<(bool, bool, Vec<u8>)> {
    // Fetch the blob from the eigenda network
    let response = providers
        .eigenda_blob_provider
        .fetch_eigenda_blob(altda_commitment_bytes)
        .await
        .map_err(|e| anyhow!("failed to fetch eigenda blob: {e}"))?;

    let mut is_valid = true;
    let mut is_recent = true;
    let mut rollup_data = vec![];

    // Handle response based on status code
    if !response.status().is_success() {
        // Handle non-success response
        if response.status().as_u16() != HTTP_RESPONSE_STATUS_CODE_TEAPOT {
            // The error is handled by host library in kona, currently this triggers an infinite retry loop.
            // https://github.com/op-rs/kona/blob/98543fe6d91f755b2383941391d93aa9bea6c9ab/bin/host/src/backend/online.rs#L135
            return Err(anyhow!(
                "failed to fetch eigenda blob, status {:?}",
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
                HokuleaPreimageError::InvalidCert => is_valid = false,
                HokuleaPreimageError::NotRecentCert => is_recent = false,
            },
            HostHandlerError::HokuleaBlobDecodingError(e)
            | HostHandlerError::IllogicalStatusCodeError(e)
            | HostHandlerError::UndefinedStatusCodeError(e) => {
                return Err(anyhow!("failed to handle http response: {e}"))
            }
        }
    } else {
        // Handle success response
        rollup_data = response
            .bytes()
            .await
            .map_err(|e| anyhow!("should be able to get rollup payload from http response {e}"))?
            .into();
    }

    Ok((is_valid, is_recent, rollup_data))
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

/// Store blob data in key-value store
async fn store_blob_data(
    kv: SharedKeyValueStore,
    altda_commitment: &AltDACommitment,
    rollup_data: Vec<u8>,
) -> Result<()> {
    // Acquire a lock on the key-value store
    let mut kv_write_lock = kv.write().await;
    // Prepare blob data
    let blob_length_fe = altda_commitment.get_num_field_element();
    let eigenda_blob = EigenDABlobData::encode(rollup_data.as_ref(), PAYLOAD_ENCODING_VERSION_0);

    // Verify blob data is properly formatted
    assert!(eigenda_blob.blob.len() % 32 == 0);
    let fetch_num_element = (eigenda_blob.blob.len() / BYTES_PER_FIELD_ELEMENT) as u64;

    // Store each field element
    let mut field_element_key = altda_commitment.digest_template();
    for i in 0..blob_length_fe as u64 {
        field_element_key[72..].copy_from_slice(i.to_be_bytes().as_ref());
        let blob_key_hash = keccak256(field_element_key.as_ref());

        if i < fetch_num_element {
            // Store actual blob data
            kv_write_lock.set(
                PreimageKey::new(*blob_key_hash, PreimageKeyType::GlobalGeneric).into(),
                eigenda_blob.blob[(i as usize) << 5..(i as usize + 1) << 5].to_vec(),
            )?;
        } else {
            // Fill remaining elements with zeros
            kv_write_lock.set(
                PreimageKey::new(*blob_key_hash, PreimageKeyType::GlobalGeneric).into(),
                vec![0u8; 32],
            )?;
        }
    }

    Ok(())
}
