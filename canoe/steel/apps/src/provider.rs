use canoe_provider::CanoeProvider;
use risc0_zkvm;
use anyhow::Result;
use crate::apps::create_cert_validity_proof;


#[derive(Clone)]
pub struct CanoeSteelProvider {}

impl CanoeProvider for CanoeSteelProvider {
    type Receipt = risc0_zkvm::Receipt;

    async fn create_cert_validity_proof(
        eigenda_cert: eigenda_v2_struct::EigenDAV2Cert,
        claimed_validity: bool,
        l1_node_address: String,
    ) -> Result<Self::Receipt> {
        create_cert_validity_proof(
            eigenda_cert.batch_header_v2.clone(),
            eigenda_cert.nonsigner_stake_and_signature.clone(),
            eigenda_cert.blob_inclusion_info.clone(),
            claimed_validity,
            l1_node_address,
        ).await
    }    
}