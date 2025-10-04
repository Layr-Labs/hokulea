use crate::CanoeInput;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait CanoeProvider: Clone + Send + 'static {
    type Receipt: Serialize + for<'de> Deserialize<'de>;

    /// create_certs_validity_proof takes a vector of canoe inputs and produces one zk proof attesting
    /// all the claimed validity in vector are indeed correct.
    /// The correctness is defined by evaluating result of applying the DAcert on the specified chain
    /// at a certain block number on the verifier address.
    ///
    /// If the input does not contain any canoe_input to prove against, it returns None
    /// All canoe CanoeInput must share common (l1_chain_id, l1_head_block_number)
    async fn create_certs_validity_proof(
        &self,
        _canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>>;
}

#[derive(Clone)]
pub struct CanoeNoOpProvider {}

#[async_trait]
impl CanoeProvider for CanoeNoOpProvider {
    type Receipt = ();

    async fn create_certs_validity_proof(
        &self,
        _canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>> {
        None
    }
}
