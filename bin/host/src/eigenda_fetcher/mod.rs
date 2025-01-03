//! This module contains the [Fetcher] struct, which is responsible for fetching preimages from a
//! remote source.

use crate::eigenda_blobs::OnlineEigenDABlobProvider;
use alloy_primitives::{keccak256, B256};
use alloy_provider::ReqwestProvider;
use alloy_rlp::Decodable;
use anyhow::{anyhow, Result};
use core::panic;
use hokulea_eigenda::BlobInfo;
use hokulea_eigenda::BLOB_ENCODING_VERSION_0;
use hokulea_proof::hint::{ExtendedHint, ExtendedHintType};
use kona_host::{blobs::OnlineBlobProvider, fetcher::Fetcher, kv::KeyValueStore};
use kona_preimage::{PreimageKey, PreimageKeyType};
use rust_kzg_bn254::helpers;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, trace, warn};

/// The [FetcherWithEigenDASupport] struct wraps and extends kona's [Fetcher] struct with the ability
/// to fetch preimages from EigenDA.
/// TODO: Kona is planning to change the fetcher interface to allow registering extra hints
/// without needing a new type. We will probably want to switch when possible.
/// See <https://github.com/anton-rs/kona/issues/369>
#[derive(Debug)]
pub struct FetcherWithEigenDASupport<KV>
where
    KV: KeyValueStore + ?Sized,
{
    /// Kona's Fetcher
    fetcher: Fetcher<KV>,
    /// Key-value store for eigenda preimages.
    kv_store: Arc<RwLock<KV>>,
    /// The eigenda provider
    eigenda_blob_provider: OnlineEigenDABlobProvider,
    /// The last hint that was received. [None] if no hint has been received yet.
    last_eigenda_hint: Option<String>,
}

impl<KV> FetcherWithEigenDASupport<KV>
where
    KV: KeyValueStore + ?Sized,
{
    /// Create a new [Fetcher] with the given [KeyValueStore].
    pub const fn new(
        fetcher: Fetcher<KV>,
        kv_store: Arc<RwLock<KV>>,
        eigenda_blob_provider: OnlineEigenDABlobProvider,
    ) -> Self {
        Self {
            fetcher,
            kv_store,
            eigenda_blob_provider,
            last_eigenda_hint: None,
        }
    }

    pub fn new_from_parts(
        kv_store: Arc<RwLock<KV>>,
        l1_provider: ReqwestProvider,
        blob_provider: OnlineBlobProvider,
        eigenda_blob_provider: OnlineEigenDABlobProvider,
        l2_provider: ReqwestProvider,
        l2_head: B256,
    ) -> Self {
        let fetcher = Fetcher::new(
            Arc::clone(&kv_store),
            l1_provider,
            blob_provider,
            l2_provider,
            l2_head,
        );
        Self {
            fetcher,
            kv_store,
            eigenda_blob_provider,
            last_eigenda_hint: None,
        }
    }

    /// Set the last hint to be received.
    pub fn hint(&mut self, hint: &str) -> Result<()> {
        trace!(target: "fetcher_with_eigenda_support", "Received hint: {hint}");
        let (hint_type, _) = ExtendedHint::parse(hint)?.split();
        // We route the hint to the right fetcher based on the hint type.
        match hint_type {
            ExtendedHintType::EigenDACommitment => {
                self.last_eigenda_hint = Some(hint.to_string());
            }
            _ => {
                self.fetcher.hint(hint);
                // get_preimage will fetch from the underlying fetcher when last_eigenda_hint = None
                self.last_eigenda_hint = None;
            }
        }
        Ok(())
    }

    /// Fetch the preimage for the given key. The requested is routed to the appropriate fetcher
    /// based on the last hint that was received (see hint() above).
    /// FetcherWithEigenDASupport -> get_preimage_eigenda -> prefetch that only understands eigenda hints
    ///     \-> Fetcher -> get_preimage -> prefetch that understands all other hints
    pub async fn get_preimage(&self, key: B256) -> Result<Vec<u8>> {
        match self.last_eigenda_hint.as_ref() {
            Some(hint) => self.get_preimage_eigenda(key, hint).await,
            None => self.fetcher.get_preimage(key).await,
        }
    }

    async fn get_preimage_eigenda(&self, key: B256, hint: &str) -> Result<Vec<u8>> {
        trace!(target: "fetcher_with_eigenda_support", "Pre-image requested. Key: {key}");

        // Acquire a read lock on the key-value store.
        let kv_lock = self.kv_store.read().await;
        let mut preimage = kv_lock.get(key);

        // Drop the read lock before beginning the retry loop.
        drop(kv_lock);

        // Use a loop to keep retrying the prefetch as long as the key is not found
        while preimage.is_none() {
            if let Err(e) = self.prefetch(hint).await {
                error!(target: "fetcher_with_eigenda_support", "Failed to prefetch hint: {e}");
                warn!(target: "fetcher_with_eigenda_support", "Retrying hint fetch: {hint}");
                continue;
            }

            let kv_lock = self.kv_store.read().await;
            preimage = kv_lock.get(key);
        }

        preimage.ok_or_else(|| anyhow!("Preimage not found."))
    }

    /// Fetch the preimage for the given hint and insert it into the key-value store.
    async fn prefetch(&self, hint: &str) -> Result<()> {
        trace!(target: "fetcher_with_eigenda_support", "prefetch: {hint}");
        let hint = ExtendedHint::parse(hint)?;
        let (hint_type, hint_data) = hint.split();
        trace!(target: "fetcher_with_eigenda_support", "Fetching hint: {hint_type} {hint_data}");

        if hint_type == ExtendedHintType::EigenDACommitment {
            let cert = hint_data;
            info!(target: "fetcher_with_eigenda_support", "Fetching eigenda commitment cert: {:?}", cert);
            // Fetch the blob sidecar from the blob provider.
            let rollup_data = self
                .eigenda_blob_provider
                .fetch_eigenda_blob(&cert)
                .await
                .map_err(|e| anyhow!("Failed to fetch eigenda blob: {e}"))?;

            // Acquire a lock on the key-value store and set the preimages.
            let mut kv_write_lock = self.kv_store.write().await;

            // the fourth because 0x01010000 in the beginning is metadata
            let rollup_data_len = rollup_data.len() as u32;
            let item_slice = cert.as_ref();
            let cert_blob_info = BlobInfo::decode(&mut &item_slice[4..]).unwrap();

            // Todo ensure data_length is always power of 2. Proxy made mistake
            let data_size = cert_blob_info.blob_header.data_length as u64;
            let blob_length: u64 = data_size / 32;

            // encode to become raw blob
            let codec_rollup_data = helpers::convert_by_padding_empty_byte(rollup_data.as_ref());
            let codec_rollup_data_len = codec_rollup_data.len() as u32;

            let mut raw_blob = vec![0u8; data_size as usize];

            if 32 + codec_rollup_data_len as u64 > data_size {
                return Err(anyhow!("data size is less than reconstructed data codec_rollup_data_len {} data_size {}", codec_rollup_data_len, data_size));
            }

            // blob header
            // https://github.com/Layr-Labs/eigenda/blob/f8b0d31d65b29e60172507074922668f4ca89420/api/clients/codecs/default_blob_codec.go#L25
            // raw blob the immediate data just before taking IFFT
            raw_blob[1] = BLOB_ENCODING_VERSION_0;
            raw_blob[2..6].copy_from_slice(&rollup_data_len.to_be_bytes());

            // encode length as uint32
            raw_blob[32..(32 + codec_rollup_data_len as usize)].copy_from_slice(&codec_rollup_data);

            // Write all the field elements to the key-value store.
            // The preimage oracle key for each field element is the keccak256 hash of
            // `abi.encodePacked(cert.KZGCommitment, uint256(i))`

            //  TODO figure out the key size, most likely dependent on smart contract parsing
            let mut blob_key = [0u8; 96];
            blob_key[..32].copy_from_slice(cert_blob_info.blob_header.commitment.x.as_ref());
            blob_key[32..64].copy_from_slice(cert_blob_info.blob_header.commitment.y.as_ref());

            info!("cert_blob_info blob_length {:?}", blob_length);

            for i in 0..blob_length {
                blob_key[88..].copy_from_slice(i.to_be_bytes().as_ref());
                let blob_key_hash = keccak256(blob_key.as_ref());

                kv_write_lock.set(
                    PreimageKey::new(*blob_key_hash, PreimageKeyType::Keccak256).into(),
                    blob_key.into(),
                )?;
                kv_write_lock.set(
                    PreimageKey::new(*blob_key_hash, PreimageKeyType::GlobalGeneric).into(),
                    raw_blob[(i as usize) << 5..(i as usize + 1) << 5].to_vec(),
                )?;
            }

            // TODO proof is at the random point, but we need to figure out where to generate
            //
            // Write the KZG Proof as the last element, needed for ZK
            //blob_key[88..].copy_from_slice((blob_length).to_be_bytes().as_ref());
            //let blob_key_hash = keccak256(blob_key.as_ref());

            //kv_write_lock.set(
            //    PreimageKey::new(*blob_key_hash, PreimageKeyType::Keccak256).into(),
            //    blob_key.into(),
            //)?;
            // proof to be done
            //kv_write_lock.set(
            //    PreimageKey::new(*blob_key_hash, PreimageKeyType::GlobalGeneric).into(),
            //    [1, 2, 3].to_vec(),
            //)?;
        } else {
            panic!("Invalid hint type: {hint_type}. FetcherWithEigenDASupport.prefetch only supports EigenDACommitment hints.");
        }
        // We don't match against the other enum case because fetcher.prefetch is private,
        // so we can't make the below code compile.
        // TODO: do we want to change the Fetcher api to make this possible?
        // ExtendedHintType::Original(hint_type) => {
        //     self.fetcher.prefetch(hint_type, hint_data).await?;
        // }

        Ok(())
    }
}
