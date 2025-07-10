use alloy_primitives::keccak256;

use crate::cfg::SingleChainHostWithEigenDA;
use crate::status_code::{EigenDAStatusCode, HostHandlerError, HTTP_RESPONSE_STATUS_CODE_TEAPOT};
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
    // for eigenda specific config data, currently unused
    cfg: &SingleChainHostWithEigenDA,
    providers: &<SingleChainHostWithEigenDA as OnlineHostBackendCfg>::Providers,
    kv: SharedKeyValueStore,
) -> Result<()> {
    let hint_type = hint.ty;
    let altda_commitment_bytes = hint.data;
    trace!(target: "fetcher_with_eigenda_support", "Fetching hint: {hint_type} {altda_commitment_bytes}");

    // given the client sent the hint, the cert itself must have been deserialized and serialized,
    // so format of cert must be valid and the following try_into must not panic
    let altda_commitment: AltDACommitment = match altda_commitment_bytes.as_ref().try_into() {
        Ok(a) => a,
        Err(e) => {
            panic!("the hokulea client should have checked the AltDACommitment conversion {e}");
        }
    };

    // Acquire a lock on the key-value store and set the preimages.
    let mut kv_write_lock = kv.write().await;

    // pre-populate recency window size. Currently, it is set to sequencing window size
    let rollup_config = cfg
        .kona_cfg
        .read_rollup_config()
        .map_err(|e| anyhow!("should have been able to read rollup config {e}"))?;

    // ToDo (bx) fix the hack at eigenda-proxy. For now + 100_000_000 to avoid recency failure
    // currently, proxy only returns a rbn < 32
    // Always write recency
    let recency = rollup_config.seq_window_size + 100_000_000;
    let recency_be_bytes = recency.to_be_bytes();
    let mut recency_address = altda_commitment.digest_template();
    recency_address[RESERVED_EIGENDA_API_BYTE_INDEX] = RESERVED_EIGENDA_API_BYTE_FOR_RECENCY;

    kv_write_lock.set(
        PreimageKey::new(*keccak256(recency_address), PreimageKeyType::GlobalGeneric).into(),
        recency_be_bytes.to_vec(),
    )?;

    // Fetch the blob sidecar from the blob provider.
    let response = providers
        .eigenda_blob_provider
        .fetch_eigenda_blob(&altda_commitment_bytes)
        .await
        .map_err(|e| anyhow!("failed to fetch eigenda blob: {e}"))?;

    let mut is_valid = true;
    let mut is_recent = true;
    let mut rollup_data = vec![];

    // anything thst is not 2xx has a json body with status code for failure, the status code cannot be 1, i.e. success
    // TODO once the new verify and get endpoint is implemented, rework the following logic
    if !response.status().is_success() {
        if response.status().as_u16() != HTTP_RESPONSE_STATUS_CODE_TEAPOT {
            return Err(anyhow!(
                "failed to fetch eigenda blob, status {:?}",
                response.error_for_status()
            ));
        }
        let status_code: EigenDAStatusCode = response
            .json()
            .await
            .map_err(|e| anyhow!("failed to deserialize 418 body: {e}"))?;

        match status_code.into() {
            HostHandlerError::HokuleaClientError(c) => match c {
                HokuleaPreimageError::InvalidCert => is_valid = false,
                HokuleaPreimageError::NotRecentCert => is_recent = false,
            },
            HostHandlerError::IllogicalStatusCodeError(e)
            | HostHandlerError::UndefinedStatusCodeError(e) => {
                return Err(anyhow!("failed to handle http response: {e}"))
            }
        }
    } else {
        rollup_data = response
            .bytes()
            .await
            .map_err(|e| anyhow!("should be able to get rollup payload from http response {e}"))?
            .into();
    }

    // skip validity if the cert is not recent
    if !is_recent {
        info!(
            target = "hokulea-host",
            "discard a cert for not being recent {}",
            altda_commitment.to_digest(),
        );
        return Ok(());
    }

    // Write validity
    let mut validity_address = altda_commitment.digest_template();
    validity_address[RESERVED_EIGENDA_API_BYTE_INDEX] = RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY;
    kv_write_lock.set(
        PreimageKey::new(*keccak256(validity_address), PreimageKeyType::GlobalGeneric).into(),
        vec![is_valid as u8],
    )?;

    // if cert is invalid, return early
    if !is_valid {
        info!(
            target = "hokulea-host",
            "discard a cert for not being valid {}",
            altda_commitment.to_digest(),
        );
        return Ok(());
    }

    // pre-populate eigenda blob field element by field element
    let blob_length_fe = altda_commitment.get_num_field_element();

    let eigenda_blob = EigenDABlobData::encode(rollup_data.as_ref(), PAYLOAD_ENCODING_VERSION_0);

    // implementation requires eigenda_blob to be multiple of 32
    assert!(eigenda_blob.blob.len() % 32 == 0);
    let fetch_num_element = (eigenda_blob.blob.len() / BYTES_PER_FIELD_ELEMENT) as u64;

    let mut field_element_key = altda_commitment.digest_template();
    // populate every field element (fe) onto database
    for i in 0..blob_length_fe as u64 {
        field_element_key[72..].copy_from_slice(i.to_be_bytes().as_ref());

        let blob_key_hash = keccak256(field_element_key.as_ref());

        if i < fetch_num_element {
            kv_write_lock.set(
                PreimageKey::new(*blob_key_hash, PreimageKeyType::GlobalGeneric).into(),
                eigenda_blob.blob[(i as usize) << 5..(i as usize + 1) << 5].to_vec(),
            )?;
        } else {
            // empty bytes for the missing part between the re-encoded blob and claimed blob length from the header
            kv_write_lock.set(
                PreimageKey::new(*blob_key_hash, PreimageKeyType::GlobalGeneric).into(),
                vec![0u8; 32],
            )?;
        }
    }
    Ok(())
}
