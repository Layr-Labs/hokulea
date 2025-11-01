//! Contains the [EigenDAPreimageSource] and EigenDA blob derivation, which is a concrete
//! implementation of the [DataAvailabilityProvider] trait for the EigenDA protocol.
use crate::traits::EigenDAPreimageProvider;
use crate::{eigenda_preimage::EigenDAPreimageSource, HokuleaErrorKind, ALTDA_DERIVATION_VERSION};
use eigenda_cert::AltDACommitment;
use kona_derive::PipelineErrorKind;

use alloc::{boxed::Box, fmt::Debug};
use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use kona_derive::{
    BlobProvider, ChainProvider, DataAvailabilityProvider, EthereumDataSource, PipelineError,
    PipelineResult,
};
use kona_protocol::BlockInfo;
use tracing::warn;

/// A factory for creating an EigenDADataSource iterator. The internal behavior is that
/// data is fetched from eigenda or stays as it is if Eth calldata is desired. Those data
/// are cached. When next() is called it just returns the next cached encoded payload.
/// Otherwise, EOF is sent if iterator is empty
#[derive(Debug, Clone)]
pub struct EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Clone,
    B: BlobProvider + Send + Clone,
    A: EigenDAPreimageProvider + Send + Clone,
{
    /// The ethereum source.
    pub ethereum_source: EthereumDataSource<C, B>,
    /// The eigenda preimage source.
    pub eigenda_source: EigenDAPreimageSource<A>,
    /// altda commitment, if we step in by calling next and it is Some, it means previous
    /// call has a temporary error
    pub altda_commitment: Option<AltDACommitment>,
}

impl<C, B, A> EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Clone + Debug,
    B: BlobProvider + Send + Clone + Debug,
    A: EigenDAPreimageProvider + Send + Clone + Debug,
{
    /// Instantiates a new [EigenDADataSource].
    pub const fn new(
        ethereum_source: EthereumDataSource<C, B>,
        eigenda_source: EigenDAPreimageSource<A>,
    ) -> Self {
        Self {
            ethereum_source,
            eigenda_source,
            altda_commitment: None,
        }
    }
}

#[async_trait]
impl<C, B, A> DataAvailabilityProvider for EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Sync + Clone + Debug,
    B: BlobProvider + Send + Sync + Clone + Debug,
    A: EigenDAPreimageProvider + Send + Sync + Clone + Debug,
{
    type Item = Bytes;

    async fn next(
        &mut self,
        block_ref: &BlockInfo,
        batcher_addr: Address,
    ) -> PipelineResult<Self::Item> {
        debug!("Data Available Source next {} {}", block_ref, batcher_addr);
        // if there is no data, fetch one from ethereum source.
        // the fetched data can either be an altda commitment which can be used to retrieve from eigenda source
        // or a ethereum blob or calldata
        if self.altda_commitment.is_none() {
            let local_data = match self.ethereum_source.next(block_ref, batcher_addr).await {
                Ok(d) => d,
                Err(e) => {
                    // if ethereum source for that block exhausted, reset the ethereum source and itself
                    // before returning error
                    if let PipelineErrorKind::Temporary(PipelineError::Eof) = e {
                        self.clear();
                    }
                    return Err(e);
                }
            };

            // if data length is 0, return early. It implies the data is skipped
            if local_data.is_empty() {
                // see handling in go implementation
                // OP develop branch https://github.com/ethereum-optimism/optimism/blob/4317c093fbe951c57c0e36037a9aa281e8e0795c/op-node/rollup/derive/altda_data_source.go#L56
                // EigenLabs  branch https://github.com/Layr-Labs/optimism/blob/34e5ce8416de529b8a57b0c55e1635ebe89805dc/op-node/rollup/derive/altda_data_source.go#L58
                return Err(PipelineErrorKind::Temporary(PipelineError::NotEnoughData));
            }

            // it is not intended for altDA
            if local_data[0] != ALTDA_DERIVATION_VERSION {
                return Ok(local_data);
            }

            match self.eigenda_source.parse(&local_data) {
                // set the state only we has parsed an altda commitment
                Ok(altda_commitment) => self.altda_commitment = Some(altda_commitment),
                // OP develop branch https://github.com/ethereum-optimism/optimism/blob/4317c093fbe951c57c0e36037a9aa281e8e0795c/op-node/rollup/derive/altda_data_source.go#L69
                // EigenLabs  branch https://github.com/Layr-Labs/optimism/blob/34e5ce8416de529b8a57b0c55e1635ebe89805dc/op-node/rollup/derive/altda_data_source.go#L72
                Err(_) => return Err(PipelineErrorKind::Temporary(PipelineError::NotEnoughData)),
            }
        }

        // keep the altda_commitment, in case eigenda source encounters a temporary error. When next function is called
        // again, we can retry this altda commiment without losing it, because ethereum no longer keeps this data after
        // popping it
        let local_altda_commitment = self
            .altda_commitment
            .clone()
            .expect("should have altda commitment");

        match self
            .eigenda_source
            .next(&local_altda_commitment, block_ref.number)
            .await
        {
            Err(e) => match e {
                HokuleaErrorKind::Temporary(e) => {
                    warn!("Hokulea derivation encounters temporary issue, retrying the derivation step {}", e);
                    Err(PipelineError::Provider(e).temp())
                }
                HokuleaErrorKind::Discard(e) => {
                    // altda commitment is discarded and try next one
                    // EigenLabs branch https://github.com/Layr-Labs/optimism/blob/34e5ce8416de529b8a57b0c55e1635ebe89805dc/op-node/rollup/derive/altda_data_source.go#L103
                    warn!(
                        "Hokulea derivation discards due to recency or validity {}",
                        e
                    );
                    self.altda_commitment = None;
                    return self.next(block_ref, batcher_addr).await;
                }
            },
            Ok(encoded_payload) => {
                match encoded_payload.decode() {
                    Ok(c) => {
                        // EigenLabs branch https://github.com/Layr-Labs/optimism/blob/34e5ce8416de529b8a57b0c55e1635ebe89805dc/op-node/rollup/derive/altda_data_source.go#L117
                        self.altda_commitment = None;
                        return Ok(c);
                    }
                    Err(e) => {
                        // encoded payload cannot be decoded, data is discarded and try next one
                        // EigenLabs branch https://github.com/Layr-Labs/optimism/blob/34e5ce8416de529b8a57b0c55e1635ebe89805dc/op-node/rollup/derive/altda_data_source.go#L103
                        warn!("Hokulea derivation discards due to decoding error {}", e);
                        self.altda_commitment = None;
                        return self.next(block_ref, batcher_addr).await;
                    }
                }
            }
        }
    }

    fn clear(&mut self) {
        self.altda_commitment = None;
        self.ethereum_source.clear();
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{self, TestEigenDAPreimageProvider};

    use super::*;
    use crate::eigenda_data::EncodedPayload;
    use crate::test_utils::TestHokuleaProviderError;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use alloc::{collections::VecDeque, vec};
    use alloy_consensus::TxEnvelope;
    use alloy_primitives::B256;
    use alloy_rlp::Decodable;
    use eigenda_cert::AltDACommitment;
    use kona_derive::test_utils::{TestBlobProvider, TestChainProvider};
    use kona_derive::{BlobSource, CalldataSource};
    use kona_genesis::{HardForkConfig, RollupConfig};

    const L1_INBOX_ADDRESS: Address =
        alloy_primitives::address!("0x000faef0a3d9711c3e9bbc4f3e2730dd75167da3");
    const BATCHER_ADDRESS: Address =
        alloy_primitives::address!("0x15F447c49D9eAC8ecA80ce12c5620278E7F59d2F");
    // All three pairs of data are valid and corresponds to the addresses above, with rbn 9300876
    // https://sepolia.etherscan.io/getRawTx?tx=0x9a22ccb0029bc8b0ddd073be1a1d923b7ae2b2ea52100bae0db4424f9107e9c0
    const CALLDATA_1: &str = "0x02f904f583aa36a78212f2843b9aca0084b2d05e008301057294000faef0a3d9711c3e9bbc4f3e2730dd75167da380b9048301010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001c001a0445ab87abefec130d63733b3bcafc7ee0c0f8367e61b580be4f0cf0c3d21a03aa02d054c857c76e9dbf47d63d0b70b58200e14e9f9ba2eb47343c3b67faab93a72";
    const ALTDA_COMMITMENT_BYTES_1: &str = "0x010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001";
    const ENCODED_PAYLOAD_1: &str = "00000000009100000000000000000000000000000000000000000000000000000000ab80c99f814a3541886f8f4a65f61b67000000000079011b6501f88f532c00998d4648d239b1ce87da27450caaab705a5c8412149720e6dd229a4b97d25600ca7222a7ae434145a5d1440229000106a45bd00f3e0e33b07a5c23ad927eaa00f98a77e7818ff59e2c3b2c03d5ffaeb6dba4cb08b9fa2d122e8acbe726c4a70009ae086496e0d3ac00d70438c034e1f1314b70c0010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    // https://sepolia.etherscan.io/getRawTx?tx=0x30321b4b3815e95627aa4ad91c8b14a56558d0fc9cd17976723384d178f01e1e, with rbn 9528135
    const CALLDATA_2: &str = "0x02f903d883aa36a78226a8843b9aca0084b2d05e0082d93094000faef0a3d9711c3e9bbc4f3e2730dd75167da380b9036701010002f90360e5a079b1d7d15095ff732f8443d96b6d293494b003e9b4377ac1c51375908afb2e9e83916347f901cef901c9f9018180820001f90159f842a008d79f9a46a4183f1d64c45fdedc36be33efc4cd27ffc9f85ac02987c2a5dddca004df46272276ced58d65a56b9a6dfa24102f066d3f0bba07e35992ede22aa4bcf888f842a0018fe73cb24305b7df1fc808f65c15d0f7921758cef87d9f38d31db4236eb9f4a01125fd3aa13adb27759b01c954dd641ad2174374f8e4cb3333970eda9fa011ecf842a00a0dd6223eed09f283a20429a7e03449c7d38b4fe674913c67e0f02d16949a41a00f52bab320eeb037ad223e361512350e35e373c79cf7f2ba1ec2aa036b49adbef888f842a02ecf0e30ff9ce9696c6c1ce5c341bfdfb56f589d3da7925fe54ee43a6667a09aa023a35883de2716167810bfca0c14af9530321908c4b78b572e9308161bb2d402f842a01fd1844a0e0f37f3c9edc39d0e14c8a4214afa7b017843dba1f467c8765df23fa004a01126fe1d6b57d7b985c61a3cb9a57f6c2e86d4dd0da956ad613bef0bcda708a000feeb6796b97a3f0179ef436770791068b9fdc15866f53af08f6d649083952eb841af27b4b47fd17adb76d6bb38831a19df88ee027ceaf22c88d846daff41ce2c7e5a814c8d0aa8034d1626e00d1c711087f412d4ccb35cacb0d490fbaa582493cb01c1808080f90163c0c0f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a027b90b5da16ef02417ad5820223e680d2c2d19a3f1d30566cfbb7b9aa30abf6da022432d9b57d271b8dd84bfb4ccd9df36b84e422cb471b35d50d55ae83a03f16ef842a0018ed79d6c0707cc6f4ec81bcea6c4cc0096f0e3635961caf3271c3c9a36a9dfa0179360dc4646a7c49bf730e1789c00622facd7836faa3c747be0f2d824cb1412f842a029273db955f9532f7b1ffe0eead7b85ac277534c892f73f0d9cf4403be36b5c6a022895e02ab90d618987ee5bf2818c93b9c5fac931d2af2b42a2d207c9d3d4966c20705c20805c2c0c0820001c080a0d8bcdbee635bd0836d858f6da41e289529956b463700fa1a886eee4019e2a2c0a045f9ddd72ebf7c56766a0bb9fbcb234fa987859273a98df8ea9d5af199b494df";
    const ALTDA_COMMITMENT_BYTES_2: &str = "0x010002f90360e5a079b1d7d15095ff732f8443d96b6d293494b003e9b4377ac1c51375908afb2e9e83916347f901cef901c9f9018180820001f90159f842a008d79f9a46a4183f1d64c45fdedc36be33efc4cd27ffc9f85ac02987c2a5dddca004df46272276ced58d65a56b9a6dfa24102f066d3f0bba07e35992ede22aa4bcf888f842a0018fe73cb24305b7df1fc808f65c15d0f7921758cef87d9f38d31db4236eb9f4a01125fd3aa13adb27759b01c954dd641ad2174374f8e4cb3333970eda9fa011ecf842a00a0dd6223eed09f283a20429a7e03449c7d38b4fe674913c67e0f02d16949a41a00f52bab320eeb037ad223e361512350e35e373c79cf7f2ba1ec2aa036b49adbef888f842a02ecf0e30ff9ce9696c6c1ce5c341bfdfb56f589d3da7925fe54ee43a6667a09aa023a35883de2716167810bfca0c14af9530321908c4b78b572e9308161bb2d402f842a01fd1844a0e0f37f3c9edc39d0e14c8a4214afa7b017843dba1f467c8765df23fa004a01126fe1d6b57d7b985c61a3cb9a57f6c2e86d4dd0da956ad613bef0bcda708a000feeb6796b97a3f0179ef436770791068b9fdc15866f53af08f6d649083952eb841af27b4b47fd17adb76d6bb38831a19df88ee027ceaf22c88d846daff41ce2c7e5a814c8d0aa8034d1626e00d1c711087f412d4ccb35cacb0d490fbaa582493cb01c1808080f90163c0c0f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a027b90b5da16ef02417ad5820223e680d2c2d19a3f1d30566cfbb7b9aa30abf6da022432d9b57d271b8dd84bfb4ccd9df36b84e422cb471b35d50d55ae83a03f16ef842a0018ed79d6c0707cc6f4ec81bcea6c4cc0096f0e3635961caf3271c3c9a36a9dfa0179360dc4646a7c49bf730e1789c00622facd7836faa3c747be0f2d824cb1412f842a029273db955f9532f7b1ffe0eead7b85ac277534c892f73f0d9cf4403be36b5c6a022895e02ab90d618987ee5bf2818c93b9c5fac931d2af2b42a2d207c9d3d4966c20705c20805c2c0c0820001";
    const ENCODED_PAYLOAD_2: &str = "00000000009500000000000000000000000000000000000000000000000000000000bdcf2fd9b7d8767b4dff28e8fdba9a7200000000007d011b5e01f8bf1cc8006b5bd7432114a72c3aac44bf6f9d30f86ca72f2ae64aa3a769a9e84d0d4ab500e9e21b8dfff777693a3aaf83068082e7050b4c42007837016bf1b4266000e0009a2b83da791a259074888d35115a378d560e902075e06065876d315ba365f1004b83275c22c744560f3389561e2359a65f4150b0b1837a000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    // https://sepolia.etherscan.io/tx/0xa3976df26e75725f2feb1b365caf121c7a2475c1c69d6f8ac8e018c2cb70f95b, with rbn 9528091
    const CALLDATA_3: &str = "0x02f9046683aa36a78226a7843b9aca0084b2d05e0082ef0694000faef0a3d9711c3e9bbc4f3e2730dd75167da380b903f501010002f903eee5a098eb692e5d190ff4458583187f335be454e47df2912152fe1200c9c3505ac4208391631bf901cef901c9f9018180820001f90159f842a00b24de07075954f38be4b14a6321d98cbbc07fc19737263774c763fb900cc7e4a01a76894605331379abaf50fdff37828c6cbe638ebe5376eaa4c250e053328fa2f888f842a009f7e88880c8e646cd234a162fc07dd5dd298092a714e9b5c8f2f473ca1afa56a0176c98504ed52e2dbc8fec1d1cd2c19f1f7d4c4a0d5584e479ce1034a571305df842a018135e9b7e4a1821ad2607a3cdc801b2a4cb1c9d641767428e8bc96f4a9c77bea00eba497b2195b825b817876f24c08d11ae30f6712c9d19255ec8d2a10b970c68f888f842a008e8f0db2324bdfef9af18c94a7aab5d68e5a485728281a5276b6519b5e99e83a00d1d6a357bb7baa967608929c192da0e15086b44e8557c672bd0f82763d0a43af842a002c20947d2e8628096d5ac30f0a48200f43960789064fe2f5c7c0b0e0c867a64a022b1240ea86dec625bb4a6db9c31769b7d7a894c4d2db565d5f215afaa8de11008a05f5f8a015a8ea873f35b68b5c829b2d8cb966785e50fb77b89da4dc177008f68b8419dadf3f532d1ed8a986d5091476945242710d9ee38ed6aa91472ad8c37170d8820fb9b0d59b3ee08b1a5a9ed8c3c4728b5a9dbf74104cec747e7ff43ae42be8600c1808080f901f1c28001f887f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a02b1528a6792412f62e605d184a86c5831f5eb62fe8b8a55ab734379af46ecd10a01c99445cf70539613357bf7770d2e9780abf080531bfdc8cc1e74171f7c43eb5f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a021a96430d1ee4b86b3dd912911a5a0128793f5d17242b49af0963126281656b2a02c138443b35d1038b341db4d3e3883efa7b335c91768c2796b852d3e747a2f3ff842a02517000c28dda7a87164dccc0cd1829bdd6014f5a020297f3cbed3993ce2107ca022591d582daa491dba1642862e37218d71d3492fa9ba22fec5347f22d72ae389f842a0102d793353afc14a8c4faf4df2d013db0c8c03d0f00028a5f142182b8b13359ca029bb1669d1a25dbbd48b5de886200d3e8e01d40c1405c51f79d952f9cb540833c20705c20805c6c28001c28080820001c001a00a05ee1c9e4e50490109af4853b1fe2d282262615944260233b39cf513ab98bca00335594224e7c236c1651b9fafb49f68299906c8c51a3512a7190f2ebb5d8059";
    const ALTDA_COMMITMENT_BYTES_3: &str = "0x010002f903eee5a098eb692e5d190ff4458583187f335be454e47df2912152fe1200c9c3505ac4208391631bf901cef901c9f9018180820001f90159f842a00b24de07075954f38be4b14a6321d98cbbc07fc19737263774c763fb900cc7e4a01a76894605331379abaf50fdff37828c6cbe638ebe5376eaa4c250e053328fa2f888f842a009f7e88880c8e646cd234a162fc07dd5dd298092a714e9b5c8f2f473ca1afa56a0176c98504ed52e2dbc8fec1d1cd2c19f1f7d4c4a0d5584e479ce1034a571305df842a018135e9b7e4a1821ad2607a3cdc801b2a4cb1c9d641767428e8bc96f4a9c77bea00eba497b2195b825b817876f24c08d11ae30f6712c9d19255ec8d2a10b970c68f888f842a008e8f0db2324bdfef9af18c94a7aab5d68e5a485728281a5276b6519b5e99e83a00d1d6a357bb7baa967608929c192da0e15086b44e8557c672bd0f82763d0a43af842a002c20947d2e8628096d5ac30f0a48200f43960789064fe2f5c7c0b0e0c867a64a022b1240ea86dec625bb4a6db9c31769b7d7a894c4d2db565d5f215afaa8de11008a05f5f8a015a8ea873f35b68b5c829b2d8cb966785e50fb77b89da4dc177008f68b8419dadf3f532d1ed8a986d5091476945242710d9ee38ed6aa91472ad8c37170d8820fb9b0d59b3ee08b1a5a9ed8c3c4728b5a9dbf74104cec747e7ff43ae42be8600c1808080f901f1c28001f887f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a02b1528a6792412f62e605d184a86c5831f5eb62fe8b8a55ab734379af46ecd10a01c99445cf70539613357bf7770d2e9780abf080531bfdc8cc1e74171f7c43eb5f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a021a96430d1ee4b86b3dd912911a5a0128793f5d17242b49af0963126281656b2a02c138443b35d1038b341db4d3e3883efa7b335c91768c2796b852d3e747a2f3ff842a02517000c28dda7a87164dccc0cd1829bdd6014f5a020297f3cbed3993ce2107ca022591d582daa491dba1642862e37218d71d3492fa9ba22fec5347f22d72ae389f842a0102d793353afc14a8c4faf4df2d013db0c8c03d0f00028a5f142182b8b13359ca029bb1669d1a25dbbd48b5de886200d3e8e01d40c1405c51f79d952f9cb540833c20705c20805c6c28001c28080820001";
    const ENCODED_PAYLOAD_3: &str = "00000000009d00000000000000000000000000000000000000000000000000000000507e76bda9280c0c5571a765a841e93b000000000085011b6901f83f14d800c6b493fad51647317c089e5d748df8fb056c31e9b3bae60933979fbbbfa2270079d4cef288030b6e1e51e4615b54cb5a4041c05f7e128071b6208854d03600000214d4017e83865a24ac735f375282ca4b51dbe044c0a6cdca01125223b4b2007573b0e5fb49d62b85df33fcef32d1ebd576d29ba2094d0167191834945c3900040100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    const PASSING_RECENCY_WINDOW: u64 = 1000000000;
    const NOT_PASSING_RECENCY_WINDOW: u64 = 1; // 0 recency triggers the ignore case
    const BLOCK_INFO: BlockInfo = BlockInfo {
        // used by all recency related test
        hash: B256::new([0u8; 32]),
        number: 9600000, // to be able to pass or reject based on the value above and rbn from altda commimtents
        parent_hash: B256::new([0u8; 32]),
        timestamp: 0,
    };

    const NOT_DECODABLE_ENCODED_PAYLOAD: EncodedPayload = EncodedPayload {
        encoded_payload: Bytes::new(),
    };

    // prepare a list of tuple (eip1559 tx, parsed altda commitment, and encoded payload for the altda commitment)
    pub(crate) fn valid_eip1559_txs_with_altda_commitment_encoded_payload(
        num: usize,
    ) -> (Vec<TxEnvelope>, Vec<AltDACommitment>, Vec<EncodedPayload>) {
        // https://sepolia.etherscan.io/getRawTx?tx=0x9a22ccb0029bc8b0ddd073be1a1d923b7ae2b2ea52100bae0db4424f9107e9c0
        let mut txs = vec![];
        let mut altda_commitments = vec![];
        let mut encoded_payloads = vec![];

        let raw_tx = alloy_primitives::hex::decode(CALLDATA_1).unwrap();
        let eip1559 = TxEnvelope::decode(&mut raw_tx.as_slice()).unwrap();
        let calldata: Bytes = alloy_primitives::hex::decode(ALTDA_COMMITMENT_BYTES_1)
            .unwrap()
            .into();
        let altda_commitment = calldata[..].try_into().unwrap();
        txs.push(eip1559);
        altda_commitments.push(altda_commitment);
        let raw_eigenda_blob = alloy_primitives::hex::decode(ENCODED_PAYLOAD_1).unwrap();
        let encoded_payload = EncodedPayload {
            encoded_payload: raw_eigenda_blob.into(),
        };
        encoded_payloads.push(encoded_payload);

        let raw_tx = alloy_primitives::hex::decode(CALLDATA_2).unwrap();
        let eip1559 = TxEnvelope::decode(&mut raw_tx.as_slice()).unwrap();
        let calldata: Bytes = alloy_primitives::hex::decode(ALTDA_COMMITMENT_BYTES_2)
            .unwrap()
            .into();
        let altda_commitment = calldata[..].try_into().unwrap();
        txs.push(eip1559);
        altda_commitments.push(altda_commitment);
        let raw_eigenda_blob = alloy_primitives::hex::decode(ENCODED_PAYLOAD_2).unwrap();
        let encoded_payload = EncodedPayload {
            encoded_payload: raw_eigenda_blob.into(),
        };
        encoded_payloads.push(encoded_payload);

        let raw_tx = alloy_primitives::hex::decode(CALLDATA_3).unwrap();
        let eip1559 = TxEnvelope::decode(&mut raw_tx.as_slice()).unwrap();
        let calldata: Bytes = alloy_primitives::hex::decode(ALTDA_COMMITMENT_BYTES_3)
            .unwrap()
            .into();
        let altda_commitment = calldata[..].try_into().unwrap();
        txs.push(eip1559);
        altda_commitments.push(altda_commitment);
        let raw_eigenda_blob = alloy_primitives::hex::decode(ENCODED_PAYLOAD_3).unwrap();
        let encoded_payload = EncodedPayload {
            encoded_payload: raw_eigenda_blob.into(),
        };
        encoded_payloads.push(encoded_payload);

        (
            txs[..num].to_vec(),
            altda_commitments[..num].to_vec(),
            encoded_payloads[..num].to_vec(),
        )
    }

    pub(crate) fn valid_eip1559_txs_with_ethda() -> Vec<TxEnvelope> {
        // https://etherscan.io/tx/0x0a46467fb3e037d0970761041da078929d7c700a7dd5becf11bfe014fb9feafd
        let raw_tx = alloy_primitives::hex::decode("0x02f901bf0183023e0b82613a841cf0e96082874f94ffeeddccbbaa000000000000000000000000000080b90152ed12ce02188e94a60b2202000128b5de02aa06bd02010000f90137f852f842a000d799bcf9d5e378a8d54b3226a4f4aa090352e0a804f5f4cfe1ed6b3118dba1a01a77098770a7dd0ee513877480657c0bb6bb92edc6ed3b8964ef2b3ed5dca7e5820800cac480213704c401213704f8e18302086c80f875eca01d93b7b8b6dc6955c98ca0c8fae72bad8f0922831458751fe2e00751b65b0f958200018264648401698a0ea04f8af94b6bde70c9ff4c5891192d33cfc711946dac85ef9ff8fd7cf75f2d909b008401698a41a046efdfad35da81ca44f686cb59568bece690928ee701e9895167cd97ce404c44b860188541ec0f491d19c9852b8fdea430650fe226ebad16d3bdd10a8477bb7e648f317aef4a3af990b8b4d258c1b6b6adf5b74ba495ae235a90f60b5bc1a147c60af3b8fef0f246098360f353b45e456ea407240182278103835f42551dc38bb645820001c001a012f41e9220687dc938961e7b0438e85fbf69c19dfa176d8e28d14607444450a3a05708cc14d41e53db2f143b0aaec0826f3fc8f8ddef0c58321b696697c31914aa").unwrap();
        let eip1559 = TxEnvelope::decode(&mut raw_tx.as_slice()).unwrap();
        vec![eip1559.clone(); 1]
    }

    pub(crate) fn default_test_preimage_source(
    ) -> EigenDAPreimageSource<TestEigenDAPreimageProvider> {
        let preimage_provider = test_utils::TestEigenDAPreimageProvider::default();
        EigenDAPreimageSource::new(preimage_provider)
    }

    fn default_test_blob_source() -> BlobSource<TestChainProvider, TestBlobProvider> {
        let chain_provider = TestChainProvider::default();
        let blob_fetcher = TestBlobProvider::default();
        let batcher_address = Address::default();
        BlobSource::new(chain_provider, blob_fetcher, batcher_address)
    }

    fn default_test_eigenda_data_source(
    ) -> EigenDADataSource<TestChainProvider, TestBlobProvider, TestEigenDAPreimageProvider> {
        let chain = TestChainProvider::default();
        let blob = default_test_blob_source();

        let calldata = CalldataSource::new(chain.clone(), Address::ZERO);
        let cfg = RollupConfig {
            hardforks: HardForkConfig {
                // all tests are post ecotone hardfork
                ecotone_time: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };

        let ethereum_data_source = EthereumDataSource::new(blob, calldata, &cfg);
        let eigenda_preimage_source = default_test_preimage_source();

        EigenDADataSource::new(ethereum_data_source, eigenda_preimage_source)
    }

    fn default_altda_commitment() -> AltDACommitment {
        let calldata: Bytes = alloy_primitives::hex::decode(ALTDA_COMMITMENT_BYTES_1)
            .unwrap()
            .into();
        calldata[..].try_into().unwrap()
    }

    fn configure_chain_provider_with_txs(
        source: &mut EigenDADataSource<
            TestChainProvider,
            TestBlobProvider,
            TestEigenDAPreimageProvider,
        >,
        num: usize,
        block_info: &BlockInfo,
    ) -> (Vec<TxEnvelope>, Vec<AltDACommitment>, Vec<EncodedPayload>) {
        // inbox addr
        source.ethereum_source.blob_source.batcher_address = L1_INBOX_ADDRESS;
        let (txs, altda_commitments, encoded_payloads) =
            valid_eip1559_txs_with_altda_commitment_encoded_payload(num);
        source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(block_info.number, *block_info, txs.clone());

        (txs, altda_commitments, encoded_payloads)
    }

    fn set_eigenda_preimage_provider_value(
        source: &mut EigenDADataSource<
            TestChainProvider,
            TestBlobProvider,
            TestEigenDAPreimageProvider,
        >,
        altda_commitments: Vec<AltDACommitment>,
        recencies: Vec<Result<u64, TestHokuleaProviderError>>,
        validities: Vec<Result<bool, TestHokuleaProviderError>>,
        encoded_payloads: Vec<Result<EncodedPayload, TestHokuleaProviderError>>,
    ) {
        let len = altda_commitments.len();
        for i in 0..len {
            // artificially maps altda commitment to provided preimage
            source
                .eigenda_source
                .eigenda_fetcher
                .insert_recency(&altda_commitments[i], recencies[i].clone());
            source
                .eigenda_source
                .eigenda_fetcher
                .insert_validity(&altda_commitments[i], validities[i].clone());
            source
                .eigenda_source
                .eigenda_fetcher
                .insert_encoded_payload(&altda_commitments[i], encoded_payloads[i].clone());
        }
    }

    // first populate all sources with data then clear them
    #[test]
    fn test_clear() {
        let chain = TestChainProvider::default();
        // populate blob source with data
        let mut blob = default_test_blob_source();
        blob.open = true;
        blob.data = vec![Default::default()];

        // populate calldata source with data
        let mut calldata = CalldataSource::new(chain.clone(), Address::ZERO);
        calldata.open = true;
        calldata.calldata = VecDeque::new();
        calldata.calldata.push_back(Bytes::default());

        let cfg = RollupConfig {
            hardforks: HardForkConfig {
                ecotone_time: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        let ethereum_data_source = EthereumDataSource::new(blob, calldata, &cfg);

        let eigenda_preimage_source = default_test_preimage_source();
        let mut eigenda_data_source =
            EigenDADataSource::new(ethereum_data_source, eigenda_preimage_source);

        // populate eigen source with data
        eigenda_data_source.altda_commitment = Some(default_altda_commitment());

        // clear all data
        eigenda_data_source.clear();

        // check if all is cleared
        assert!(!eigenda_data_source.ethereum_source.blob_source.open);
        assert!(!eigenda_data_source.ethereum_source.calldata_source.open);
        assert!(eigenda_data_source.altda_commitment.is_none());
        assert!(eigenda_data_source
            .ethereum_source
            .blob_source
            .data
            .is_empty());
        assert!(eigenda_data_source
            .ethereum_source
            .calldata_source
            .calldata
            .is_empty());
    }

    // not providing the data for ethereum chain provider, but try to pull data
    #[tokio::test]
    async fn test_next_chain_provider_err() {
        let mut source = default_test_eigenda_data_source();
        // call terminates at https://github.com/op-rs/kona/blob/1133800fcb23c4515ed919407742a22f222d88b1/crates/protocol/derive/src/sources/blobs.rs#L125
        // which maps to temporary error
        // https://github.com/op-rs/kona/blob/a7446de410a1c40597d44a7f961e46bbbf0576bc/crates/protocol/derive/src/errors/sources.rs#L49
        assert!(matches!(
            source.next(&BlockInfo::default(), Address::ZERO).await,
            Err(PipelineErrorKind::Temporary(_)),
        ));
    }

    // load chain provider with empty data and derive empty data
    #[tokio::test]
    async fn test_next_empty_data_err() {
        let mut eigenda_data_source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        eigenda_data_source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(block_info.number, block_info, Vec::new());

        assert!(eigenda_data_source.altda_commitment.is_none());

        // kona would return EOF because Vec is empty above, when extracting return empty vec
        // and next_data will return EOF
        // https://github.com/Layr-Labs/kona/blob/fa982a0d2406ed2bbca0682d958a6cd087db4ed7/crates/protocol/derive/src/sources/blobs.rs#L45
        let err = eigenda_data_source
            .next(&block_info, Address::ZERO)
            .await
            .unwrap_err();

        // because eof is returned, altda commitment isn't set to Some
        assert!(eigenda_data_source.altda_commitment.is_none());

        assert!(matches!(
            err,
            PipelineErrorKind::Temporary(PipelineError::Eof),
        ));
    }

    #[tokio::test]
    async fn test_next_with_eigenda_preimage_provider_preimage_fetch_error() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        // inbox addr
        source.ethereum_source.blob_source.batcher_address = L1_INBOX_ADDRESS;

        let (txs, _, _) = valid_eip1559_txs_with_altda_commitment_encoded_payload(1);
        source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(block_info.number, block_info, txs);

        // test temporary error
        source.eigenda_source.eigenda_fetcher.should_preimage_err = true;
        // see load_encoded_payload::HokuleaErrorKind::Temporary
        assert!(matches!(
            source.next(&block_info, BATCHER_ADDRESS).await,
            Err(PipelineErrorKind::Temporary(PipelineError::Provider(_)))
        ));

        // altda commitment is not consumed yet
        assert!(source.altda_commitment.is_some());
    }

    // derive a 1559 tx from chain provider, where the tx contains an altda commitment
    // which can be used to run eigenda blob derivation
    #[tokio::test]
    async fn test_next_chain_provider_1559_tx_succeeds() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BLOCK_INFO;
        let (_, altda_commitments, encoded_payloads) =
            configure_chain_provider_with_txs(&mut source, 1, &block_info);
        set_eigenda_preimage_provider_value(
            &mut source,
            altda_commitments,
            vec![Ok(PASSING_RECENCY_WINDOW)],
            vec![Ok(true)],
            vec![Ok(encoded_payloads[0].clone())],
        );

        let data = source
            .next(&block_info, BATCHER_ADDRESS)
            .await
            .expect("should be ok");
        assert!(source.altda_commitment.is_none());

        // encoded payload corresponding to the data
        let payload = encoded_payloads[0].decode().unwrap();

        assert!(data == payload);
    }

    // inject temporary errors eigenda preimage, before finally derive output
    // derive a 1559 tx from chain provider, where the tx contains an altda commitment
    // which can be used to run eigenda blob derivation
    #[tokio::test]
    async fn test_next_chain_provider_1559_txs_succeeds_after_temporary_error() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BLOCK_INFO;
        let (_, altda_commitments, encoded_payloads) =
            configure_chain_provider_with_txs(&mut source, 1, &block_info);
        set_eigenda_preimage_provider_value(
            &mut source,
            altda_commitments,
            vec![Ok(PASSING_RECENCY_WINDOW)],
            vec![Ok(true)],
            vec![Ok(encoded_payloads[0].clone())],
        );

        source.eigenda_source.eigenda_fetcher.should_preimage_err = true;
        assert!(matches!(
            source.next(&block_info, BATCHER_ADDRESS).await,
            Err(PipelineErrorKind::Temporary(PipelineError::Provider(_)))
        ));

        // altda commitment is not consumed yet
        assert!(source.altda_commitment.is_some());

        // after last error, the op derivation pipeline would try again
        assert!(matches!(
            source.next(&block_info, BATCHER_ADDRESS).await,
            Err(PipelineErrorKind::Temporary(PipelineError::Provider(_)))
        ));

        // altda commitment is not consumed yet
        assert!(source.altda_commitment.is_some());

        // and finally it is good
        source.eigenda_source.eigenda_fetcher.should_preimage_err = false;

        let payload = source
            .next(&block_info, BATCHER_ADDRESS)
            .await
            .expect("should be ok");

        // altda commitment is consumed
        assert!(source.altda_commitment.is_none());
        assert!(payload == encoded_payloads[0].decode().unwrap());
    }

    // Eth failover
    #[tokio::test]
    async fn test_load_eigenda_or_calldata_chain_provider_1559_tx_with_ethda_failover() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        // inbox addr
        source.ethereum_source.blob_source.batcher_address =
            alloy_primitives::address!("0xffeeddccbbaa0000000000000000000000000000");
        let txs = valid_eip1559_txs_with_ethda();
        // inject invalid 1559 transaction
        source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(block_info.number, block_info, txs);

        assert!(source
            .next(
                &block_info,
                alloy_primitives::address!("0x2f40d796917ffb642bd2e2bdd2c762a5e40fd749")
            )
            .await
            .is_ok());
        assert!(source.altda_commitment.is_none());
    }

    // calldata is empty. This transaction has no calldata nor blobhash, testing
    // if local_data.is_empty() {
    //    return Err(PipelineErrorKind::Temporary(PipelineError::NotEnoughData));
    // }
    #[tokio::test]
    async fn test_next_chain_provider_1559_tx_with_empty_calldata() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        // inbox addr
        source.ethereum_source.blob_source.batcher_address =
            alloy_primitives::address!("0xc25276A375ec96e7F494A04e4f74a1d4C3EE223A");
        // https://sepolia.etherscan.io/tx/0x717e912c4bd0ead87819d8f36ce9e6efc14255900560c6bc05b77dfb7fdb9dc8
        let raw_tx = alloy_primitives::hex::decode("0x02f87583aa36a7098459682f008459bb530b82520894c25276a375ec96e7f494a04e4f74a1d4c3ee223a8803782dace9d9000080c001a08737f84218a42d53cb3ec202fae278a881ddbe9f5e1740ccbdfd5bd74c9878e4a0714b7b5f2f73d6fa6c3edd1474928c678d0f18e96ec9143d1b961c3cd6240d2a").unwrap();
        let eip1559 = TxEnvelope::decode(&mut raw_tx.as_slice()).unwrap();

        source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(block_info.number, block_info, vec![eip1559]);

        let err = source
            .next(
                &block_info,
                alloy_primitives::address!("0x6AD3463563C8ad4bd42906FaD8aF00c9Ae509Ce5"),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            PipelineErrorKind::Temporary(PipelineError::NotEnoughData),
        ));
    }

    // parsing has problem, testing
    // match self.eigenda_source.parse(&local_data)
    #[tokio::test]
    async fn test_next_chain_provider_1559_tx_with_altda_commitment_parse_error() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        // inbox addr
        source.ethereum_source.blob_source.batcher_address =
            alloy_primitives::address!("0x582D8c8675f58430581F2aEd0BE486Bf2576D8DA");
        // https://sepolia.etherscan.io/tx/0xcad3c60b0de05a09ba1c91777ee8b218ba1c1ff74d6996ecf8569b951bf03196
        let raw_tx = alloy_primitives::hex::decode("0x02f89b83aa36a783026826843b9aca0084b2d05e0082582a94582d8c8675f58430581f2aed0be486bf2576d8da80ab01010ccedd8300000000001d24960a699284cc26f4ec4d2f22eca56b6401f4225f4b3785818ff7cdb1273ac080a016ee79d3de3df53c4a2687036a39017676cbaa016a143be8e435bcda056fd6a2a066e7987856632908c57339a0e6da0a340c8633e8a9a5f4cf38a0cafec4e3b1e4").unwrap();
        let eip1559 = TxEnvelope::decode(&mut raw_tx.as_slice()).unwrap();

        let txs = vec![eip1559.clone()];
        // inject 1559 transaction with invalid altda commitment
        source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(block_info.number, block_info, txs);

        assert!(matches!(
            source
                .next(
                    &block_info,
                    alloy_primitives::address!("0xD1a823bF5c7DB22A2dA0cB9Cef9330930805a472")
                )
                .await
                .unwrap_err(),
            PipelineErrorKind::Temporary(PipelineError::NotEnoughData),
        ));
    }

    // test loading two altda commitment from a single block
    #[tokio::test]
    async fn test_next_with_two_1559_txs_succeeds() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BLOCK_INFO;
        let (_, altda_commitments, encoded_payloads) =
            configure_chain_provider_with_txs(&mut source, 2, &block_info);
        set_eigenda_preimage_provider_value(
            &mut source,
            altda_commitments,
            vec![Ok(PASSING_RECENCY_WINDOW); 2],
            vec![Ok(true); 2],
            encoded_payloads.into_iter().map(Ok).collect(),
        );

        source
            .next(&block_info, BATCHER_ADDRESS)
            .await
            .expect("should be ok");
        // just populate the first one out of total two altda commitment data
        assert!(source.altda_commitment.is_none());
        // ethereum source should still have data
        assert!(source.ethereum_source.blob_source.open);
        source
            .next(&block_info, BATCHER_ADDRESS)
            .await
            .expect("should be ok");
        // should be empty unless a temporary error
        assert!(source.altda_commitment.is_none());

        // ethereum source should still open, even though it does not have data
        assert!(source.ethereum_source.blob_source.open);
        assert!(source.ethereum_source.blob_source.data.is_empty());

        // now we shuold get eof, because there isn't data anymore
        let err = source.next(&block_info, BATCHER_ADDRESS).await.unwrap_err();
        assert!(matches!(
            err,
            PipelineErrorKind::Temporary(PipelineError::Eof)
        ));
        // chain should be close now because of eof is emitted
        assert!(!source.ethereum_source.blob_source.open);
    }

    // test provider related error resulting in temporary issues
    #[tokio::test]
    async fn test_next_with_temporary_error() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BLOCK_INFO;
        let (_, altda_commitments, encoded_payloads) =
            configure_chain_provider_with_txs(&mut source, 1, &block_info);

        struct Case {
            altda_commitment: AltDACommitment,
            recency: Result<u64, TestHokuleaProviderError>,
            validity: Result<bool, TestHokuleaProviderError>,
            encoded_payload: Result<EncodedPayload, TestHokuleaProviderError>,
        }

        let cases = vec![
            Case {
                altda_commitment: altda_commitments[0].clone(),
                recency: Err(TestHokuleaProviderError::Preimage),
                validity: Ok(true),
                encoded_payload: Ok(encoded_payloads[0].clone()),
            },
            Case {
                altda_commitment: altda_commitments[0].clone(),
                recency: Ok(PASSING_RECENCY_WINDOW),
                validity: Err(TestHokuleaProviderError::Preimage),
                encoded_payload: Ok(encoded_payloads[0].clone()),
            },
            Case {
                altda_commitment: altda_commitments[0].clone(),
                recency: Ok(PASSING_RECENCY_WINDOW),
                validity: Ok(true),
                encoded_payload: Err(TestHokuleaProviderError::Preimage),
            },
        ];

        assert!(source.altda_commitment.is_none());
        for case in cases {
            // temporarily does not have recency
            set_eigenda_preimage_provider_value(
                &mut source,
                vec![case.altda_commitment],
                vec![case.recency],
                vec![case.validity],
                vec![case.encoded_payload],
            );

            // all preimage provider error are temporary
            assert!(matches!(
                source.next(&block_info, BATCHER_ADDRESS).await.unwrap_err(),
                PipelineErrorKind::Temporary(PipelineError::Provider(_)),
            ));
            // altda commitment should be used for the next time
            assert!(source.altda_commitment.is_some());
        }
    }

    #[tokio::test]
    async fn test_next_with_discarded_altda_commitment() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BLOCK_INFO;
        let (_, altda_commitments, encoded_payloads) =
            configure_chain_provider_with_txs(&mut source, 3, &block_info);

        struct Case {
            altda_commitment: AltDACommitment,
            recency: Result<u64, TestHokuleaProviderError>,
            validity: Result<bool, TestHokuleaProviderError>,
            encoded_payload: Result<EncodedPayload, TestHokuleaProviderError>,
        }

        let cases = vec![
            Case {
                altda_commitment: altda_commitments[0].clone(),
                recency: Ok(NOT_PASSING_RECENCY_WINDOW),
                validity: Ok(true),
                encoded_payload: Ok(encoded_payloads[0].clone()),
            },
            Case {
                altda_commitment: altda_commitments[1].clone(),
                recency: Ok(PASSING_RECENCY_WINDOW),
                validity: Ok(false),
                encoded_payload: Ok(encoded_payloads[1].clone()),
            },
            Case {
                altda_commitment: altda_commitments[2].clone(),
                recency: Ok(PASSING_RECENCY_WINDOW),
                validity: Ok(true),
                encoded_payload: Ok(NOT_DECODABLE_ENCODED_PAYLOAD),
            },
        ];

        assert!(source.altda_commitment.is_none());
        for case in cases {
            // temporarily does not have recency
            set_eigenda_preimage_provider_value(
                &mut source,
                vec![case.altda_commitment],
                vec![case.recency],
                vec![case.validity],
                vec![case.encoded_payload],
            );
        }
        // all data is discarded, drives until EOF
        assert!(matches!(
            source.next(&block_info, BATCHER_ADDRESS).await.unwrap_err(),
            PipelineErrorKind::Temporary(PipelineError::Eof),
        ));
        // unlike temporary error, altda commitment is consumed
        assert!(source.altda_commitment.is_none());
    }

    #[tokio::test]
    async fn test_next_with_keep_and_discard_multiple_altda_commitment() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BLOCK_INFO;
        let (_, altda_commitments, encoded_payloads) =
            configure_chain_provider_with_txs(&mut source, 3, &block_info);
        let payloads: Vec<Bytes> = encoded_payloads
            .clone()
            .into_iter()
            .map(|e| e.decode().unwrap())
            .collect();

        struct Case {
            altda_commitment: AltDACommitment,
            recency: Result<u64, TestHokuleaProviderError>,
            validity: Result<bool, TestHokuleaProviderError>,
            encoded_payload: Result<EncodedPayload, TestHokuleaProviderError>,
        }

        struct Scenario {
            cases: Vec<Case>,
            // number of next and result for each next
            results: Vec<PipelineResult<Bytes>>,
            altda_commitment_is_some: Vec<bool>,
        }

        let scenarios = [
            // drop, drop, take
            Scenario {
                cases: vec![
                    Case {
                        altda_commitment: altda_commitments[0].clone(),
                        recency: Ok(NOT_PASSING_RECENCY_WINDOW),
                        validity: Ok(true),
                        encoded_payload: Ok(encoded_payloads[0].clone()),
                    },
                    Case {
                        altda_commitment: altda_commitments[1].clone(),
                        recency: Ok(PASSING_RECENCY_WINDOW),
                        validity: Ok(true),
                        encoded_payload: Ok(NOT_DECODABLE_ENCODED_PAYLOAD),
                    },
                    Case {
                        altda_commitment: altda_commitments[2].clone(),
                        recency: Ok(PASSING_RECENCY_WINDOW),
                        validity: Ok(true),
                        encoded_payload: Ok(encoded_payloads[2].clone()),
                    },
                ],
                results: vec![
                    Ok(payloads[2].clone()),
                    Err(PipelineErrorKind::Temporary(PipelineError::Eof)),
                ],
                altda_commitment_is_some: vec![false, false],
            },
            // take, retry -> drop, take
            Scenario {
                cases: vec![
                    Case {
                        altda_commitment: altda_commitments[0].clone(),
                        recency: Ok(PASSING_RECENCY_WINDOW),
                        validity: Ok(true),
                        encoded_payload: Ok(encoded_payloads[0].clone()),
                    },
                    Case {
                        altda_commitment: altda_commitments[1].clone(),
                        recency: Ok(PASSING_RECENCY_WINDOW),
                        validity: Err(TestHokuleaProviderError::Preimage),
                        encoded_payload: Ok(encoded_payloads[1].clone()),
                    },
                    Case {
                        altda_commitment: altda_commitments[2].clone(),
                        recency: Ok(0),
                        validity: Ok(true),
                        encoded_payload: Ok(encoded_payloads[2].clone()),
                    },
                ],
                results: vec![
                    Ok(payloads[0].clone()),
                    Err(PipelineErrorKind::Temporary(PipelineError::Provider(
                        "Preimage temporary error".to_string(),
                    ))),
                    Ok(payloads[2].clone()),
                    Err(PipelineErrorKind::Temporary(PipelineError::Eof)),
                ],
                altda_commitment_is_some: vec![false, true, false, false],
            },
            // drop, retry -> drop, drop
            Scenario {
                cases: vec![
                    Case {
                        altda_commitment: altda_commitments[0].clone(),
                        recency: Ok(NOT_PASSING_RECENCY_WINDOW),
                        validity: Ok(true),
                        encoded_payload: Ok(encoded_payloads[0].clone()),
                    },
                    Case {
                        altda_commitment: altda_commitments[1].clone(),
                        recency: Err(TestHokuleaProviderError::Preimage),
                        validity: Ok(true),
                        encoded_payload: Ok(encoded_payloads[1].clone()),
                    },
                    Case {
                        altda_commitment: altda_commitments[2].clone(),
                        recency: Ok(PASSING_RECENCY_WINDOW),
                        validity: Ok(true),
                        encoded_payload: Ok(NOT_DECODABLE_ENCODED_PAYLOAD),
                    },
                ],
                results: vec![
                    Err(PipelineErrorKind::Temporary(PipelineError::Provider(
                        "Preimage temporary error".to_string(),
                    ))),
                    Err(PipelineErrorKind::Temporary(PipelineError::Eof)),
                ],
                altda_commitment_is_some: vec![true, false],
            },
        ];

        for scenario in scenarios {
            for case in scenario.cases {
                set_eigenda_preimage_provider_value(
                    &mut source,
                    vec![case.altda_commitment],
                    vec![case.recency],
                    vec![case.validity],
                    vec![case.encoded_payload],
                );
            }
            for i in 0..scenario.results.len() {
                match source.next(&block_info, BATCHER_ADDRESS).await {
                    Ok(payload) => assert_eq!(Ok(payload), scenario.results[i]),
                    Err(e) => assert_eq!(Err(e), scenario.results[i]),
                }
                assert_eq!(
                    source.altda_commitment.is_some(),
                    scenario.altda_commitment_is_some[i]
                );

                // automatically remove any preimage error, translate it into drop
                if source.altda_commitment.is_some() {
                    source.eigenda_source.eigenda_fetcher.insert_recency(
                        &source.altda_commitment.clone().unwrap(),
                        Ok(NOT_PASSING_RECENCY_WINDOW),
                    );
                    source
                        .eigenda_source
                        .eigenda_fetcher
                        .insert_validity(&source.altda_commitment.clone().unwrap(), Ok(false));
                    source
                        .eigenda_source
                        .eigenda_fetcher
                        .insert_encoded_payload(
                            &source.altda_commitment.clone().unwrap(),
                            Ok(NOT_DECODABLE_ENCODED_PAYLOAD),
                        );
                }
            }
            source.clear();
        }

        // create a scenario where all the temporary retry resulting, a successful retrieval of payload
        let scenario = Scenario {
            // retry -> take, retry -> take, drop
            cases: vec![
                Case {
                    altda_commitment: altda_commitments[0].clone(),
                    recency: Err(TestHokuleaProviderError::Preimage),
                    validity: Ok(true),
                    encoded_payload: Ok(encoded_payloads[0].clone()),
                },
                Case {
                    altda_commitment: altda_commitments[1].clone(),
                    recency: Err(TestHokuleaProviderError::Preimage),
                    validity: Ok(true),
                    encoded_payload: Ok(encoded_payloads[1].clone()),
                },
                Case {
                    altda_commitment: altda_commitments[2].clone(),
                    recency: Ok(PASSING_RECENCY_WINDOW),
                    validity: Ok(false),
                    encoded_payload: Ok(NOT_DECODABLE_ENCODED_PAYLOAD),
                },
            ],
            results: vec![
                Err(PipelineErrorKind::Temporary(PipelineError::Provider(
                    "Preimage temporary error".to_string(),
                ))),
                Ok(payloads[0].clone()),
                Err(PipelineErrorKind::Temporary(PipelineError::Provider(
                    "Preimage temporary error".to_string(),
                ))),
                Ok(payloads[1].clone()),
                Err(PipelineErrorKind::Temporary(PipelineError::Eof)),
            ],
            // first retry holds an altda commitment, next call will return payload and set to false,
            // third time call has temporary err, and have it to true, fourth time call set it to false,
            // and return payload. The last call see a drop, then recursively derive to end of file
            altda_commitment_is_some: vec![true, false, true, false, false],
        };

        for case in scenario.cases {
            set_eigenda_preimage_provider_value(
                &mut source,
                vec![case.altda_commitment],
                vec![case.recency],
                vec![case.validity],
                vec![case.encoded_payload],
            );
        }
        for i in 0..scenario.results.len() {
            match source.next(&block_info, BATCHER_ADDRESS).await {
                Ok(payload) => assert_eq!(Ok(payload), scenario.results[i]),
                Err(e) => assert_eq!(Err(e), scenario.results[i]),
            }
            assert_eq!(
                source.altda_commitment.is_some(),
                scenario.altda_commitment_is_some[i]
            );

            // automatically remove any preimage error, translate it into drop
            // we take a short cut that only set retry on recency and validity, but not on payload
            if source.altda_commitment.is_some() {
                source.eigenda_source.eigenda_fetcher.insert_recency(
                    &source.altda_commitment.clone().unwrap(),
                    Ok(PASSING_RECENCY_WINDOW),
                );
                source
                    .eigenda_source
                    .eigenda_fetcher
                    .insert_validity(&source.altda_commitment.clone().unwrap(), Ok(true));
            }
        }
    }
}
