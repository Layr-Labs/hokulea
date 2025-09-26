//! This tool generates verification key for an ELF file with sp1_sdk
//! cargo run --bin canoe-sp1-cc-vkey-bin --release
use sp1_sdk::{HashableKey, ProverClient};

fn main() {
    const CANOE_SP1CC_ELF: &[u8] = canoe_sp1_cc_host::ELF;
    let client = ProverClient::from_env();

    // from succinct lab, the vkey stays the same for all major release version
    // regardless minor changes. For example, 5.2.1 and 5.0.8 produce identical vkey
    // for the same ELF.
    let (_pk, canoe_vk) = client.setup(CANOE_SP1CC_ELF);

    println!("canoe sp1cc v_key {:?}", canoe_vk.vk.hash_u32());
}
