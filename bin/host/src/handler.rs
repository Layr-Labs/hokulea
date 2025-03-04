use alloy_primitives::keccak256;
//use alloy_primitives::B256;
use alloy_rlp::Decodable;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hokulea_proof::hint::ExtendedHintType;
use kona_host::SharedKeyValueStore;
use kona_host::{single::SingleChainHintHandler, HintHandler, OnlineHostBackendCfg};

use crate::cfg::SingleChainHostWithEigenDA;

use kona_preimage::{PreimageKey, PreimageKeyType};
use kona_proof::Hint;
use tracing::trace;

use eigenda_v2_struct_rust::EigenDAV2Cert;
//use hokulea_compute_kzg_proof::compute_kzg_proof;
use hokulea_eigenda::BlobInfo;
use hokulea_eigenda::EigenDABlobData;
use hokulea_eigenda::{BYTES_PER_FIELD_ELEMENT, PAYLOAD_ENCODING_VERSION_0};

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
            ExtendedHintType::EigenDACertV1 | ExtendedHintType::EigenDACertV2 => {
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
    _cfg: &SingleChainHostWithEigenDA,
    providers: &<SingleChainHostWithEigenDA as OnlineHostBackendCfg>::Providers,
    kv: SharedKeyValueStore,
) -> Result<()> {
    let hint_type = hint.ty;
    let hint_data = hint.data;

    trace!(target: "fetcher_with_eigenda_support", "Fetching hint: {hint_type} {hint_data}");

    let cert = hint_data;
    // Fetch the blob sidecar from the blob provider.
    let rollup_data = providers
        .eigenda_blob_provider
        .fetch_eigenda_blob(&cert)
        .await
        .map_err(|e| anyhow!("Failed to fetch eigenda blob: {e}"))?;

    // TODO define an error message from proxy that if the view call is wrong
    // https://github.com/Layr-Labs/eigenda/blob/master/contracts/src/core/EigenDACertVerifier.sol#L165
    // then store empty byte in the kv_store

    let (eigenda_blob, blob_length_fe, mut blob_key) = match hint_type {
        ExtendedHintType::EigenDACertV1 => {
            // the fourth because 0x01010000 in the beginning is metadata
            let item_slice = cert.as_ref();
            let cert_blob_info = BlobInfo::decode(&mut &item_slice[4..]).unwrap();

            // Proxy should return a cert whose data_length measured in symbol (i.e. 32 Bytes)
            let blob_length_fe = cert_blob_info.blob_header.data_length as usize;

            let eigenda_blob = EigenDABlobData::encode(rollup_data.as_ref(), PAYLOAD_ENCODING_VERSION_0);

            if eigenda_blob.blob.len() > blob_length_fe * BYTES_PER_FIELD_ELEMENT {
                return Err(
                    anyhow!("data size from cert is less than locally crafted blob cert data size {} locally crafted size {}", 
                        eigenda_blob.blob.len(), blob_length_fe * BYTES_PER_FIELD_ELEMENT));
            }

            //  TODO figure out the key size, most likely dependent on smart contract parsing
            let mut blob_key = [0u8; 96];
            blob_key[..32].copy_from_slice(cert_blob_info.blob_header.commitment.x.as_ref());
            blob_key[32..64].copy_from_slice(cert_blob_info.blob_header.commitment.y.as_ref());
            (eigenda_blob, blob_length_fe, blob_key)
        },
        ExtendedHintType::EigenDACertV2 => {
            // the fourth because 0x01010000 in the beginning is metadata
            let item_slice = cert.as_ref();
            let v2_cert = EigenDAV2Cert::decode(&mut &item_slice[4..]).unwrap();

            let blob_length_fe = v2_cert.blob_inclusion_info.blob_certificate.blob_header.commitment.length as usize;

            let eigenda_blob = EigenDABlobData::encode(rollup_data.as_ref(), PAYLOAD_ENCODING_VERSION_0);

            if eigenda_blob.blob.len() > blob_length_fe * BYTES_PER_FIELD_ELEMENT {
                return Err(
                    anyhow!("data size from cert is less than locally crafted blob cert data size {} locally crafted size {}", 
                        eigenda_blob.blob.len(), blob_length_fe * BYTES_PER_FIELD_ELEMENT));
            }

            let x: [u8; 32] = v2_cert.blob_inclusion_info.blob_certificate.blob_header.commitment.commitment.x.to_be_bytes();
            let y: [u8; 32] = v2_cert.blob_inclusion_info.blob_certificate.blob_header.commitment.commitment.y.to_be_bytes();

            let mut blob_key = [0u8; 96];
            blob_key[..32].copy_from_slice(&x);
            blob_key[32..64].copy_from_slice(&y);
            (eigenda_blob, blob_length_fe, blob_key)
        },
        _ => panic!("Invalid hint type: {hint_type}. SingleChainHintHandlerWithEigenDA.prefetch only supports EigenDACommitment hints."),
    };

    // Acquire a lock on the key-value store and set the preimages.
    let mut kv_write_lock = kv.write().await;

    // implementation requires eigenda_blob to be multiple of 32
    assert!(eigenda_blob.blob.len() % 32 == 0);
    let fetch_num_element = (eigenda_blob.blob.len() / BYTES_PER_FIELD_ELEMENT) as u64;

    // populate every field element (fe) onto database
    for i in 0..blob_length_fe as u64 {
        blob_key[88..].copy_from_slice(i.to_be_bytes().as_ref());
        let blob_key_hash = keccak256(blob_key.as_ref());

        kv_write_lock.set(
            PreimageKey::new(*blob_key_hash, PreimageKeyType::Keccak256).into(),
            blob_key.into(),
        )?;

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
    /*    Compute KZG proof
    // Compute kzg proof for the entire blob on a deterministic random point
    let kzg_proof = match compute_kzg_proof(&eigenda_blob.blob) {
        Ok(p) => p,
        Err(e) => return Err(anyhow!("cannot compute kzg proof {}", e)),
    };

    // Write the KZG Proof as the last element, needed for ZK
    blob_key[88..].copy_from_slice((blob_length_fe as u64).to_be_bytes().as_ref());
    let blob_key_hash = keccak256(blob_key.as_ref());
    kv_write_lock.set(
        PreimageKey::new(*blob_key_hash, PreimageKeyType::Keccak256).into(),
        blob_key.into(),
    )?;
    kv_write_lock.set(
        PreimageKey::new(*blob_key_hash, PreimageKeyType::GlobalGeneric).into(),
        kzg_proof.to_vec(),
    )?;
    */
    Ok(())
}
