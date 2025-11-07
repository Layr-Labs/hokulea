use alloy_genesis::Genesis;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder, HOLESKY, MAINNET, SEPOLIA};
use reth_evm::spec_by_timestamp_and_block_number;
use revm_primitives::hardfork::SpecId;

/// derive_chain_spec_id by locating the active fork with timestamp and block number
pub fn derive_chain_spec_id(
    l1_chain_id: u64,
    l1_head_block_timestamp: u64,
    l1_head_block_number: u64,
) -> SpecId {
    match l1_chain_id {
        // mainnet
        1 => spec_by_timestamp_and_block_number(
            MAINNET.as_ref(),
            l1_head_block_timestamp,
            l1_head_block_number,
        ),
        // sepolia
        11155111 => spec_by_timestamp_and_block_number(
            SEPOLIA.as_ref(),
            l1_head_block_timestamp,
            l1_head_block_number,
        ),
        // holesky
        17000 => spec_by_timestamp_and_block_number(
            HOLESKY.as_ref(),
            l1_head_block_timestamp,
            l1_head_block_number,
        ),
        // kurtosis devnet
        3151908 => {
            let chain_spec = create_kurtosis_chain_spec();
            spec_by_timestamp_and_block_number(
                &chain_spec,
                l1_head_block_timestamp,
                l1_head_block_number,
            )
        }
        _ => panic!("unsupported chain id"),
    }
}

/// create_kurtosis_chain_spec provides a testing utility for kurtosis devnet.
/// the latest active fork is prague
pub fn create_kurtosis_chain_spec() -> ChainSpec {
    ChainSpecBuilder::default()
        .chain(Chain::from_id(3151908))
        .genesis(Genesis::default())
        .homestead_activated()
        .byzantium_activated()
        .constantinople_activated()
        .petersburg_activated()
        .istanbul_activated()
        .berlin_activated()
        .london_activated()
        .shanghai_activated()
        .cancun_activated()
        .prague_activated()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_kurtosis_chain_spec() {
        let chain_spec = create_kurtosis_chain_spec();
        let spec_id = spec_by_timestamp_and_block_number(&chain_spec, 100, 100);
        assert_eq!(spec_id, SpecId::PRAGUE);
    }
}
