#![no_std]
#![cfg_attr(any(target_arch = "mips64", target_arch = "riscv64"), no_main)]

extern crate alloc;

use alloc::string::String;
use hokulea_client_bin::client::run_direct_client;
use kona_preimage::{HintWriter, OracleReader};
use kona_std_fpvm::{FileChannel, FileDescriptor};
use kona_std_fpvm_proc::client_entry;

use kona_client::fpvm_evm::FpvmOpEvmFactory;

/// The global preimage oracle reader pipe.
static ORACLE_READER_PIPE: FileChannel =
    FileChannel::new(FileDescriptor::PreimageRead, FileDescriptor::PreimageWrite);

/// The global hint writer pipe.
static HINT_WRITER_PIPE: FileChannel =
    FileChannel::new(FileDescriptor::HintRead, FileDescriptor::HintWrite);

/// The global preimage oracle reader.
static ORACLE_READER: OracleReader<FileChannel> = OracleReader::new(ORACLE_READER_PIPE);

/// The global hint writer.
static HINT_WRITER: HintWriter<FileChannel> = HintWriter::new(HINT_WRITER_PIPE);

#[client_entry(100_000_000)]
fn main() -> Result<(), String> {
    kona_proof::block_on(run_direct_client(
        ORACLE_READER,
        HINT_WRITER,
        FpvmOpEvmFactory::new(HINT_WRITER, ORACLE_READER),
    ))
}
