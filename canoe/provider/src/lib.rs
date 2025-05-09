use anyhow::Result;
use async_trait::async_trait;
use hokulea_proof::cert_validity::CertValidity;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait CanoeProvider: Clone + Send + 'static {
    type Receipt: Serialize + for<'de> Deserialize<'de>;

    async fn create_cert_validity_proof(
        &self,
        eigenda_cert: eigenda_v2_struct::EigenDAV2Cert,
        cert_validity: CertValidity,
    ) -> Result<Self::Receipt>;

    fn get_eth_rpc_url(&self) -> String;
}

#[derive(Clone)]
pub struct CanoeNoOpProvider {}

#[async_trait]
impl CanoeProvider for CanoeNoOpProvider {
    type Receipt = ();

    async fn create_cert_validity_proof(
        &self,
        _eigenda_cert: eigenda_v2_struct::EigenDAV2Cert,
        _claimed_validity: CertValidity,
    ) -> Result<Self::Receipt> {
        Ok(())
    }

    fn get_eth_rpc_url(&self) -> String {
        "".to_string()
    }
}
