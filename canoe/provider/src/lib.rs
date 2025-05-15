use alloy_primitives::B256;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub struct CanoeInput {
    /// eigenda cert
    pub eigenda_cert: eigenda_v2_struct::EigenDAV2Cert,
    /// the claim about if the cert is valid
    pub claimed_validity: bool,
    /// block hash where view call anchored at, l1_head comes from kona_cfg    
    pub l1_head_block_hash: B256,
    /// block number corresponding to the hash above. This is checked against l1_head_block_hash in the zk view proof
    pub l1_head_block_number: u64,
}

#[async_trait]
pub trait CanoeProvider: Clone + Send + 'static {
    type Receipt: Serialize + for<'de> Deserialize<'de>;

    async fn create_cert_validity_proof(&self, input: CanoeInput) -> Result<Self::Receipt>;

    fn get_eth_rpc_url(&self) -> String;
}

#[derive(Clone)]
pub struct CanoeNoOpProvider {}

#[async_trait]
impl CanoeProvider for CanoeNoOpProvider {
    type Receipt = ();

    async fn create_cert_validity_proof(&self, _canoe_input: CanoeInput) -> Result<Self::Receipt> {
        Ok(())
    }

    fn get_eth_rpc_url(&self) -> String {
        "".to_string()
    }
}
