use eigenda_v2_struct;
use std::future::Future;
use anyhow::Result;

pub trait CanoeProvider: Clone + Send + 'static {
    type Receipt;

    fn create_cert_validity_proof(
        eigenda_cert: eigenda_v2_struct::EigenDAV2Cert,
        claimed_validity: bool,
        l1_node_address: String,
    ) -> impl Future<Output = Result<Self::Receipt> > + Send;

}