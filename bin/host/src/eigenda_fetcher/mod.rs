//! This module contains the [Fetcher] struct, which is responsible for fetching preimages from a
//! remote source.

use crate::eigenda_blobs::OnlineEigenDABlobProvider;
use alloy_primitives::{keccak256, B256};
use alloy_provider::ReqwestProvider;
use anyhow::{anyhow, Result};
use core::panic;
use hokulea_proof::hint::{ExtendedHint, ExtendedHintType};
use kona_host::{blobs::OnlineBlobProvider, fetcher::Fetcher, kv::KeyValueStore};
use kona_preimage::{PreimageKey, PreimageKeyType};
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
    /// FetcherWithEigenDASupport -> get_preimage_altda -> prefetch that only understands altda hints
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
            info!(target: "fetcher_with_eigenda_support", "Fetching AltDACommitment cert: {:?}", cert);
            // Fetch the blob sidecar from the blob provider.
            let eigenda_blob = self
                .eigenda_blob_provider
                .fetch_eigenda_blob(&cert)
                .await
                .map_err(|e| anyhow!("Failed to fetch eigenda blob: {e}"))?;

            info!(target: "fetcher_with_eigenda_support", "eigenda_blob len {}", eigenda_blob.len());
            // Acquire a lock on the key-value store and set the preimages.
            let mut kv_write_lock = self.kv_store.write().await;

            // Set the preimage for the blob commitment.
            kv_write_lock.set(
                PreimageKey::new(*keccak256(cert), PreimageKeyType::GlobalGeneric).into(),
                eigenda_blob.to_vec(),
            )?;
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
