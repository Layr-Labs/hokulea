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
// Query parameters configuration for proxy behavior:
// - commitment_mode=optimism_generic: Specifies the commitment mode (default even if not specified)
// - return_encoded_payload=true: Instructs proxy to return encoded payload instead of decoded rollup payload
// - Without these params: proxy returns decoded rollup payload by default
// - Secure integration requires encoded payload to allow derivation pipeline to handle decoding
const GET_QUERY_PARAMS_ENCODED_PAYLOAD: &str =
    "commitment_mode=optimism_generic&return_encoded_payload=true";

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
    ) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!(
            "{}/{}/{}?{}",
            self.base, GET_METHOD, cert, GET_QUERY_PARAMS_ENCODED_PAYLOAD
        );
        self.inner.get(url).send().await
    }
}
