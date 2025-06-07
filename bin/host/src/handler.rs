use alloy_primitives::keccak256;

use crate::cfg::SingleChainHostWithEigenDA;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use eigenda_cert::AltDACommitment;
use hokulea_eigenda::{EigenDABlobData, RESERVED_EIGENDA_API_BYTE_FOR_RECENCY};
use hokulea_eigenda::{
    BYTES_PER_FIELD_ELEMENT, PAYLOAD_ENCODING_VERSION_0, RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY,
    RESERVED_EIGENDA_API_BYTE_INDEX,
};
use hokulea_proof::hint::ExtendedHintType;
use kona_host::SharedKeyValueStore;
use kona_host::{single::SingleChainHintHandler, HintHandler, OnlineHostBackendCfg};
use kona_preimage::{PreimageKey, PreimageKeyType};
use kona_proof::Hint;
use tracing::trace;

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

    // Fetch the blob sidecar from the blob provider.
    let response = providers
        .eigenda_blob_provider
        .fetch_eigenda_blob(&altda_commitment_bytes)
        .await
        .map_err(|e| anyhow!("Failed to fetch eigenda blob: {e}"))?;

    // For now, failed at any non success
    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to fetch eigenda blob, status {:?}",
            response.error_for_status()
        ));
    }
    let rollup_data = response.bytes().await.unwrap();

    // given the client sent the hint, the cert itself must have been deserialized and serialized,
    // so format of cert must be valid and the following try_into must not panic
    let altda_commitment: AltDACommitment = match altda_commitment_bytes.as_ref().try_into() {
        Ok(a) => a,
        Err(e) => {
            panic!("the error message above should have handled the issue {e}");
        }
    };

    // Acquire a lock on the key-value store and set the preimages.
    let mut kv_write_lock = kv.write().await;

    // pre-populate recency window size. Currently, it is set to sequencing window size
    let rollup_config = cfg
        .kona_cfg
        .read_rollup_config()
        .expect("should have been able to read rollup config");
    // ToDo (bx) fix the hack at eigenda-proxy. For now + 100_000_000 to avoid recency failure
    // currently, proxy only returns a rbn < 32
    let recency = rollup_config.seq_window_size + 100_000_000;
    let recency_be_bytes = recency.to_be_bytes();
    let mut recency_address = altda_commitment.digest_template();
    recency_address[RESERVED_EIGENDA_API_BYTE_INDEX] = RESERVED_EIGENDA_API_BYTE_FOR_RECENCY;

    kv_write_lock.set(
        PreimageKey::new(*keccak256(recency_address), PreimageKeyType::GlobalGeneric).into(),
        recency_be_bytes.to_vec(),
    )?;

    // pre-populate validity address. Currently, assume everything is correct
    // (ToDo bx), after proxy returns error code indicating cert is wrong, route
    // with appropriate response false
    let claimed_validity = true;
    let mut validity_address = altda_commitment.digest_template();

    validity_address[RESERVED_EIGENDA_API_BYTE_INDEX] = RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY;

    kv_write_lock.set(
        PreimageKey::new(*keccak256(validity_address), PreimageKeyType::GlobalGeneric).into(),
        vec![claimed_validity as u8],
    )?;

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
