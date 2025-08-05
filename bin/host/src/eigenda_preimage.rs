use alloy_primitives::Bytes;
use reqwest;

/// Fetches blobs (encoded payload) from EigenDA via an eigenda proxy instance.
#[derive(Debug, Clone)]
pub struct OnlineEigenDAPreimageProvider {
    /// The base url.
    base: String,
    /// The inner reqwest client. Used to talk to proxy
    inner: reqwest::Client,
}

const GET_METHOD: &str = "get";
const QUERY_PARAM_ENCODED_PAYLOAD: &str =
    "commitment_mode=optimism_generic&return_encoded_payload=true";

impl OnlineEigenDAPreimageProvider {
    /// Creates a new instance of the [OnlineEigenDAPreimageProvider].
    ///
    /// The `genesis_time` and `slot_interval` arguments are _optional_ and the
    /// [OnlineEigenDAPreimageProvider] will attempt to load them dynamically at runtime if they are not
    /// provided.
    pub fn new_http(base: String) -> Self {
        let inner = reqwest::Client::new();
        Self { base, inner }
    }

    pub async fn fetch_eigenda_encoded_payload(
        &self,
        cert: &Bytes,
    ) -> Result<reqwest::Response, reqwest::Error> {
        // the query params instructs proxy to return encoded payload
        // without the query params, the proxy by default uses optimism_generic even without specifying commitment_mode
        // the proxy by default returns the decoded rollup payload if without the [QUERY_PARAM_ENCODED_PAYLOAD]
        // the secure integration expects encoded paload to allow eigenda derivation pipeline to cover the decoding procedures
        let url = format!(
            "{}/{}/{}?{}",
            self.base, GET_METHOD, cert, QUERY_PARAM_ENCODED_PAYLOAD
        );
        //let resp1 = self.inner.get(url1).send().await.unwrap();
        self.inner.get(url).send().await
    }
}
