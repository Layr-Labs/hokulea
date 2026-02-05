//! This tool generates verification key for an ELF file with `sp1_sdk`
//! ```
//! cargo run --bin canoe-sp1-cc-vkey-bin --release -- /path/to/elf-file
//! ```
use alloy_primitives::B256;
use clap::Parser;
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey};

use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(about = "Generate verification key for an ELF file with sp1_sdk")]
struct Cli {
    /// Path to the ELF file
    elf: PathBuf,

    /// Print the verification key as a simple hex string
    #[arg(long)]
    hex: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let canoe_client_elf: Vec<u8> = fs::read(&cli.elf).expect("Failed to read ELF file");
    let client = ProverClient::from_env().await;

    // from succinct lab, the vkey stays the same for all major release version
    // regardless minor changes. For example, 5.2.1 and 5.0.8 produce identical vkey
    // for the same ELF.
    let pk = client.setup(Elf::from(canoe_client_elf)).await.unwrap();
    let canoe_vk = pk.verifying_key();

    if cli.hex {
        println!("{}", B256::from(canoe_vk.hash_bytes()));
    } else {
        println!("canoe sp1cc v_key {:?}", canoe_vk.vk.hash_u32());
    }
}
