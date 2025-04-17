use alloy_primitives::Bytes;
use reqwest;

/// Fetches blobs from EigenDA via an eigenda-proxy instance.
#[derive(Debug, Clone)]
pub struct OnlineEigenDABlobProvider {
    /// The base url.
    base: String,
    /// The inner reqwest client. Used to talk to proxy
    inner: reqwest::Client,
}

const GET_METHOD: &str = "get";

impl OnlineEigenDABlobProvider {
    /// Creates a new instance of the [OnlineEigenDABlobProvider].
    ///
    /// The `genesis_time` and `slot_interval` arguments are _optional_ and the
    /// [OnlineEigenDABlobProvider] will attempt to load them dynamically at runtime if they are not
    /// provided.
    pub fn new_http(base: String) -> Self {
        let inner = reqwest::Client::new();
        Self { base, inner }
    }

    pub async fn fetch_eigenda_blob(
        &self,
        cert: &Bytes,
    ) -> Result<alloy_rlp::Bytes, reqwest::Error> {
        let url = format!("{}/{}/{}", self.base, GET_METHOD, cert);

        let raw_response = self.inner.get(url).send().await?;

        raw_response.bytes().await
    }
}
