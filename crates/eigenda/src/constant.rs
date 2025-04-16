/// This minimal blob encoding contains a 32 byte header = [0x00, version byte, uint32 len of data, 0x00, 0x00,...]
/// followed by the encoded data [0x00, 31 bytes of data, 0x00, 31 bytes of data,...]
pub const PAYLOAD_ENCODING_VERSION_0: u8 = 0x0;
/// TODO: make it part of rollup config
/// Maximum distance (in L1 blocks) we accept between a certificate's
/// `reference_block_number` and the current L1 block before the cert is
/// considered **stale** and the blob is treated as temporarily
/// unavailable.
///
/// The default value (100) is suitable for main‑net assumptions.  Dev‑nets
/// often have very small reference block numbers; to make prototyping
/// easier the gap can be overridden with an environment variable
/// `EIGENDA_STALE_GAP`.
pub const DEFAULT_STALE_GAP: u64 = 100;

/// Returns the configured stale gap.
///
/// * In `std` builds (host binaries) this reads the `EIGENDA_STALE_GAP`
///   environment variable if present.  
/// * In `no_std` contexts (risc‑v client) it always falls back to the
///   default because environment look‑ups are unavailable.
/// Returns the stale‑gap value.
/// 
/// The gap can be overridden at **compile‑time** by setting the environment
/// variable `EIGENDA_STALE_GAP` while building Hokulea (the build scripts do
/// not need to change; `option_env!` makes the value available to the
/// compiler).  This mechanism works in both `std` and `no_std` builds and
/// does not require runtime access to the operating‑system environment.
#[inline(always)]
pub fn stale_gap() -> u64 {
    match option_env!("EIGENDA_STALE_GAP") {
        Some(val) => val.parse::<u64>().unwrap_or(DEFAULT_STALE_GAP),
        None => DEFAULT_STALE_GAP,
    }
}

/// Back‑compat alias for code that imported the constant directly.
pub const STALE_GAP: u64 = DEFAULT_STALE_GAP;
/// Number of fields for field element on bn254
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
