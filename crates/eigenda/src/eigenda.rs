//! Contains the [EigenDAPreimageSource] and EigenDA blob derivation, which is a concrete
//! implementation of the [DataAvailabilityProvider] trait for the EigenDA protocol.
use crate::traits::EigenDAPreimageProvider;
use crate::{eigenda_preimage::EigenDAPreimageSource, HokuleaErrorKind};
use kona_derive::errors::PipelineErrorKind;

use crate::eigenda_data::EncodedPayload;
use alloc::vec::Vec;
use alloc::{boxed::Box, fmt::Debug};
use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use kona_derive::{
    errors::PipelineError,
    sources::EthereumDataSource,
    traits::{BlobProvider, ChainProvider, DataAvailabilityProvider},
    types::PipelineResult,
};
use kona_protocol::{BlockInfo, DERIVATION_VERSION_0};
use tracing::warn;

#[derive(Debug, Clone, PartialEq)]
pub enum EigenDAOrCalldata {
    EigenDA(EncodedPayload),
    Calldata(Bytes),
}

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
    /// Whether the source is open. When it is open, the next() call will consume data
    /// at this current stage, as opposed to pull it from the next stage
    pub open: bool,
    /// eigenda encoded payload or ethereum calldata that does not use eigenda in failover mode
    pub data: Vec<EigenDAOrCalldata>,
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
            open: false,
            data: Vec::new(),
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
        // this is the only function that depends on external IO. No data is consumed at this point,
        // and if loading failed for IO provider reason, then next time all data are reloaded again.
        // if it ever succeed, this function is skipped due to channel being open
        self.load_eigenda_or_calldata(block_ref, batcher_addr)
            .await?;

        match self.next_data()? {
            EigenDAOrCalldata::Calldata(c) => return Ok(c),
            EigenDAOrCalldata::EigenDA(encoded_payload) => {
                match encoded_payload.decode() {
                    Ok(c) => return Ok(c),
                    // if encodoed payload cannot be decoded, try next data, since load_encoded_payload
                    // has openned the stage already, it won't load the l1 block again
                    Err(_) => self.next(block_ref, batcher_addr).await,
                }
            }
        }
    }

    fn clear(&mut self) {
        self.data.clear();
        self.ethereum_source.clear();
        self.open = false;
    }
}

impl<C, B, A> EigenDADataSource<C, B, A>
where
    C: ChainProvider + Send + Sync + Clone + Debug,
    B: BlobProvider + Send + Sync + Clone + Debug,
    A: EigenDAPreimageProvider + Send + Sync + Clone + Debug,
{
    // load calldata, currenly there is only one cert per calldata
    // this is still required, in case the provider returns error
    // the open variable ensures we don't have to load the ethereum source again
    // If this function returns early with error, no state is corrupted
    async fn load_eigenda_or_calldata(
        &mut self,
        block_ref: &BlockInfo,
        batcher_addr: Address,
    ) -> PipelineResult<()> {
        if self.open {
            return Ok(());
        }

        let mut calldata_list: Vec<Bytes> = Vec::new();
        // drain all the ethereum calldata from the l1 block
        loop {
            match self.ethereum_source.next(block_ref, batcher_addr).await {
                Ok(d) => calldata_list.push(d),
                Err(e) => {
                    // break out the loop after having all batcher calldata for that block number
                    if let PipelineErrorKind::Temporary(PipelineError::Eof) = e {
                        break;
                    }
                    return Err(e);
                }
            };
        }

        // all data returnable to l1 retriever, including both eigenda encoded payload and Derivation version 0
        // eth data defined
        let mut self_contained_data: Vec<EigenDAOrCalldata> = Vec::new();
        for data in &calldata_list {
            // if data is op channel frame
            if data[0] == DERIVATION_VERSION_0 {
                info!(
                    target = "eth-datasource",
                    stage = "hokulea_load_encoded_payload",
                    "use ethda at l1 block number {}",
                    block_ref.number
                );
                self_contained_data.push(EigenDAOrCalldata::Calldata(data.clone()));
            } else {
                // retrieve all data from eigenda
                match self.eigenda_source.next(data, block_ref.number).await {
                    Err(e) => match e {
                        HokuleaErrorKind::Discard(e) => {
                            warn!("Hokulea derivation discard {}", e);
                            continue;
                        }
                        HokuleaErrorKind::Temporary(e) => {
                            return Err(PipelineError::Provider(e).temp())
                        }
                        HokuleaErrorKind::Critical(e) => {
                            return Err(PipelineError::Provider(e).crit())
                        }
                    },
                    Ok(encoded_payload) => {
                        self_contained_data.push(EigenDAOrCalldata::EigenDA(encoded_payload));
                    }
                }
            }
        }

        self.data = self_contained_data;
        self.open = true;
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn next_data(&mut self) -> Result<EigenDAOrCalldata, PipelineErrorKind> {
        // if all eigenda encoded payload are processed, send signal to driver to advance
        if self.data.is_empty() {
            return Err(PipelineError::Eof.temp());
        }
        Ok(self.data.remove(0))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{self, TestEigenDAPreimageSource};

    use super::*;
    use alloc::{collections::VecDeque, vec};
    use alloy_consensus::TxEnvelope;
    use alloy_rlp::Decodable;
    use eigenda_cert::AltDACommitment;
    use kona_derive::sources::{BlobSource, CalldataSource};
    use kona_derive::test_utils::{TestBlobProvider, TestChainProvider};
    use kona_genesis::{HardForkConfig, RollupConfig};

    pub(crate) fn default_test_preimage_source() -> EigenDAPreimageSource<TestEigenDAPreimageSource>
    {
        let preimage_provider = test_utils::TestEigenDAPreimageSource::default();
        EigenDAPreimageSource::new(preimage_provider)
    }

    pub(crate) fn valid_blob_txs() -> Vec<TxEnvelope> {
        // https://sepolia.etherscan.io/getRawTx?tx=0x9a22ccb0029bc8b0ddd073be1a1d923b7ae2b2ea52100bae0db4424f9107e9c0
        let raw_tx = alloy_primitives::hex::decode("0x03f9011d83aa36a7820fa28477359400852e90edd0008252089411e9ca82a3a762b4b5bd264d4173a242e7a770648080c08504a817c800f8a5a0012ec3d6f66766bedb002a190126b3549fce0047de0d4c25cffce0dc1c57921aa00152d8e24762ff22b1cfd9f8c0683786a7ca63ba49973818b3d1e9512cd2cec4a0013b98c6c83e066d5b14af2b85199e3d4fc7d1e778dd53130d180f5077e2d1c7a001148b495d6e859114e670ca54fb6e2657f0cbae5b08063605093a4b3dc9f8f1a0011ac212f13c5dff2b2c6b600a79635103d6f580a4221079951181b25c7e654901a0c8de4cced43169f9aa3d36506363b2d2c44f6c49fc1fd91ea114c86f3757077ea01e11fdd0d1934eda0492606ee0bb80a7bf8f35cc5f86ec60fe5031ba48bfd544").unwrap();
        let eip4844 = TxEnvelope::decode(&mut raw_tx.as_slice()).unwrap();
        vec![eip4844]
    }

    // corresponds to 0x02f904f583aa36a78212f2843b9aca0084b2d05e008301057294000faef0a3d9711c3e9bbc4f3e2730dd75167da380b9048301010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001c001a0445ab87abefec130d63733b3bcafc7ee0c0f8367e61b580be4f0cf0c3d21a03aa02d054c857c76e9dbf47d63d0b70b58200e14e9f9ba2eb47343c3b67faab93a72
    // whose altda commitment data is 0x010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001
    pub(crate) fn valid_encoded_payload_with_altda_commitment() -> (AltDACommitment, EncodedPayload)
    {
        let calldata: Bytes = alloy_primitives::hex::decode("0x010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001").unwrap().into();
        let altda_commitment = calldata[..].try_into().unwrap();
        let raw_eigenda_blob = alloy_primitives::hex::decode("00000000009100000000000000000000000000000000000000000000000000000000ab80c99f814a3541886f8f4a65f61b67000000000079011b6501f88f532c00998d4648d239b1ce87da27450caaab705a5c8412149720e6dd229a4b97d25600ca7222a7ae434145a5d1440229000106a45bd00f3e0e33b07a5c23ad927eaa00f98a77e7818ff59e2c3b2c03d5ffaeb6dba4cb08b9fa2d122e8acbe726c4a70009ae086496e0d3ac00d70438c034e1f1314b70c0010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let encoded_payload = EncodedPayload {
            encoded_payload: raw_eigenda_blob.into(),
        };
        (altda_commitment, encoded_payload)
    }

    // eigenda failover to eth calldata only, which uses eip 1559 tx
    // see https://github.com/Layr-Labs/optimism/blob/24baeb1c87879ee1900551aabbb7c154dc058d14/op-service/txmgr/txmgr.go#L342
    pub(crate) fn valid_eip1559_txs() -> Vec<TxEnvelope> {
        // https://sepolia.etherscan.io/getRawTx?tx=0x9a22ccb0029bc8b0ddd073be1a1d923b7ae2b2ea52100bae0db4424f9107e9c0
        let raw_tx = alloy_primitives::hex::decode("0x02f904f583aa36a78212f2843b9aca0084b2d05e008301057294000faef0a3d9711c3e9bbc4f3e2730dd75167da380b9048301010002f9047ce5a04c617ac0dcf14f58a1d58e80c9902e2c199474989563dc59566d5bd5ad1b640a838deb8cf901cef901c9f9018180820001f90159f842a02f79ec81c41b992e9dec0c96fe5d970657bd5699560b1eaca902b6d8d95b69d9a014aee8fa5e2bd3a23ce376c537248acce7c29a74962218a4cc19c483d962dcf7f888f842a01c4c0eec183bf264a5b96b2ddc64e400a3f03752fb9d4296f3b4729e237ea40da01303695a7e9cba15f6ecb2e5da94826c94e557d94a491b61b42e2fb577bf5983f842a00c4bb24f65dd9d63401f8fb5aa680c36c3a18c06996511ce14544d77bc3659bba01a201aef9dceb92540f58243194aeae5c4b5953dddf17925c5a56bcb57ec19adf888f842a02a71a11141df9d0a5158602444003491763859afb77b1566a3eabafc162d4617a027bfbe487a7507ab70b6b42433850f8b7be21ab2c268f415cb68608506da9114f842a013002e07d4f2259193d9aa06a01866dc527221d65cc5c49c4c05cfc281d873c1a02d47dba83902698378718ab5c589eb9c7daa5f9641a5ce160f112bc65b40227308a0731bd6915a6ccea1380db7f0695ad67ee03bfbd59ac8c7976ee25f7ec9515037b8414cd74a3034296d0e2d63ce879dbe578e0715c29fd388c9babb38bd99ef45c64d548d60eec508758c6101b4b01ff2b65ff503fa485a8035a54edd1bc71d84430e00c1808080f9027fc401808080f9010ff842a01cd040b326ae7cd372763fafb595470d3613f6fb3d824582bf02edcb735ccb0fa017bbe7ebc3167abad8710ecd335b37a1b63d1f0119569bcf3f84d2125810a294f842a0297ac518058025f67f0c0cc4d735965f242540ddbf998491e5b66a5c9d56c712a00dc76d3bfe805d8ad41c96a5d3696ecd22c44049057fbb2b2f3e0c204f5dd745f8419f9a9a3504786f979f4011c180069d0127599773df85c02f550c8bcd4336d150a02bf5de7c6791a70185eb0eef04661bbf6f3596569843dbd9172eea27ad484249f842a020304749b8c2e65c4a82035cf1c559ea8b8d7ab9a94b6dc7d4b79299be445ae9a02b4d5e4ecb245d94af3d6c279c1a86fb452401355be715ac4887fcdcf7642ce4f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a0171e10f7d012c823ceb26e40245a97375804a82ca8f92e0dd49fc5f76c3b093ea028946cc01b7092bb709a72c07184d84821125632337d4c8f9a063afcefdc57c0f842a00df37a0480625fa5ab86d78e4664d2bacfed6c4e7562956bfc95f2b9efd1977ca0121ae7669b68221699c6b4eb057acbf2e58d4fb4b4da7aa5e4deaaac513f6ce0f842a01abcc37d2cbe680d5d6d3ebeddc3f5b09f103e2fa3a20a887c573f2ac5ab6e36a01a23d0ac964f04643eb3206db5a81e678fc484f362d3c7442657735e678298c3c20705c20805c9c3018080c480808080820001c001a0445ab87abefec130d63733b3bcafc7ee0c0f8367e61b580be4f0cf0c3d21a03aa02d054c857c76e9dbf47d63d0b70b58200e14e9f9ba2eb47343c3b67faab93a72").unwrap();
        let eip1559 = TxEnvelope::decode(&mut raw_tx.as_slice()).unwrap();
        println!("eip1559 {:?}", eip1559);
        vec![eip1559]
    }

    fn default_test_blob_source() -> BlobSource<TestChainProvider, TestBlobProvider> {
        let chain_provider = TestChainProvider::default();
        let blob_fetcher = TestBlobProvider::default();
        let batcher_address = Address::default();
        BlobSource::new(chain_provider, blob_fetcher, batcher_address)
    }

    fn default_test_eigenda_data_source(
    ) -> EigenDADataSource<TestChainProvider, TestBlobProvider, TestEigenDAPreimageSource> {
        let chain = TestChainProvider::default();
        let blob = default_test_blob_source();

        let calldata = CalldataSource::new(chain.clone(), Address::ZERO);
        let cfg = RollupConfig {
            hardforks: HardForkConfig {
                ecotone_time: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };

        let ethereum_data_source = EthereumDataSource::new(blob, calldata, &cfg);
        let eigenda_preimage_source = default_test_preimage_source();

        EigenDADataSource::new(ethereum_data_source, eigenda_preimage_source)
    }

    #[test]
    fn test_next_data() {
        let mut eigenda_data_source = default_test_eigenda_data_source();

        let data = EigenDAOrCalldata::Calldata(Bytes::default());

        eigenda_data_source.data = vec![data];

        if let Ok(d) = eigenda_data_source.next_data() {
            assert_eq!(d, EigenDAOrCalldata::Calldata(Bytes::default()))
        }

        if let Err(e) = eigenda_data_source.next_data() {
            assert_eq!(e, PipelineError::Eof.temp())
        }
    }

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
        eigenda_data_source.open = true;
        eigenda_data_source.data = vec![EigenDAOrCalldata::Calldata(Bytes::default())];

        // clear all data
        eigenda_data_source.clear();
        assert!(!eigenda_data_source.open);
        assert!(!eigenda_data_source.ethereum_source.blob_source.open);
        assert!(!eigenda_data_source.ethereum_source.calldata_source.open);
        assert!(eigenda_data_source.data.is_empty());
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

    #[tokio::test]
    async fn test_load_eigenda_or_calldata_open() {
        let mut source = default_test_eigenda_data_source();
        source.open = true;
        assert!(source
            .load_eigenda_or_calldata(&BlockInfo::default(), Address::ZERO)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_load_eigenda_or_calldata_chain_provider_err() {
        let mut source = default_test_eigenda_data_source();
        // call terminates at https://github.com/op-rs/kona/blob/1133800fcb23c4515ed919407742a22f222d88b1/crates/protocol/derive/src/sources/blobs.rs#L125
        // which maps to temporary error
        // https://github.com/op-rs/kona/blob/a7446de410a1c40597d44a7f961e46bbbf0576bc/crates/protocol/derive/src/errors/sources.rs#L49
        assert!(matches!(
            source
                .load_eigenda_or_calldata(&BlockInfo::default(), Address::ZERO)
                .await,
            Err(PipelineErrorKind::Temporary(_)),
        ));
    }

    // see https://github.com/op-rs/kona/blob/1133800fcb23c4515ed919407742a22f222d88b1/crates/protocol/derive/src/sources/blobs.rs#L252
    #[tokio::test]
    async fn test_load_eigenda_or_calldata_empty_data() {
        let mut eigenda_data_source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        eigenda_data_source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(0, block_info, Vec::new());

        assert!(!eigenda_data_source.open); // source isn't open by default
        assert!(eigenda_data_source
            .load_eigenda_or_calldata(&BlockInfo::default(), Address::ZERO)
            .await
            .is_ok());
        assert!(eigenda_data_source.data.is_empty());
        assert!(eigenda_data_source.open); // open until it is cleared
    }

    // questionable in the original test, it should have given critcial
    // (ToDo bx) double check
    #[tokio::test]
    async fn test_load_eigenda_or_calldata_chain_provider_4844_txs_blob_fetch_error() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        let batcher_address =
            alloy_primitives::address!("A83C816D4f9b2783761a22BA6FADB0eB0606D7B2");
        source.ethereum_source.blob_source.batcher_address =
            alloy_primitives::address!("11E9CA82A3a762b4B5bd264d4173a242e7a77064");
        let txs = valid_blob_txs();
        source.ethereum_source.blob_source.blob_fetcher.should_error = true;
        source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(1, block_info, txs);

        assert!(matches!(
            source
                .load_eigenda_or_calldata(&BlockInfo::default(), batcher_address)
                .await,
            Err(PipelineErrorKind::Temporary(_))
        ));
    }

    // we could in practice test with 4844 transaction that has blob, but kona test suite only
    // provide Blob that is un-decodable, making it problematic to test the eigenda source
    // because it would fail the decoding part, and not generate any payload to the downstream
    // users i.e. eigenda source that pulls ethereum data. Although altda commitment is only
    // stored as calldata, the blob can be submitted in case EthDA is used. That being said,
    // current batcher only uses calldata as failover. But the code can handle both calldata or
    // blob, it is just we won't be able to test it.
    #[tokio::test]
    async fn test_load_eigenda_or_calldata_chain_provider_1559_txs_succeeds() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        // batcher account
        let batcher_address =
            alloy_primitives::address!("0x15F447c49D9eAC8ecA80ce12c5620278E7F59d2F");
        // inbox addr
        source.ethereum_source.blob_source.batcher_address =
            alloy_primitives::address!("0x000faef0a3d9711c3e9bbc4f3e2730dd75167da3");
        let txs = valid_eip1559_txs();
        source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(1, block_info, txs);

        let (altda_commitment, encoded_payload) = valid_encoded_payload_with_altda_commitment();

        source
            .eigenda_source
            .eigenda_fetcher
            .insert_recency(&altda_commitment, Ok(200));
        source
            .eigenda_source
            .eigenda_fetcher
            .insert_validity(&altda_commitment, Ok(true));
        source
            .eigenda_source
            .eigenda_fetcher
            .insert_encoded_payload(&altda_commitment, Ok(encoded_payload));

        source
            .load_eigenda_or_calldata(&BlockInfo::default(), batcher_address)
            .await
            .expect("should be ok");
        assert!(source.open);
        // Blob::with_last_byte(1) cannot be decoded correctly
        // it is pretty strange that kona chooses a test that cannot be decoded
        assert!(!source.data.is_empty());
    }

    #[tokio::test]
    async fn test_open_empty_data_eof() {
        let mut source = default_test_eigenda_data_source();
        source.open = true;

        let err = source
            .next(&BlockInfo::default(), Address::ZERO)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PipelineErrorKind::Temporary(PipelineError::Eof)
        ));
    }

    // once source is opened, we don't need to injest data from Ethereum source
    #[tokio::test]
    async fn test_open_calldata() {
        let mut source = default_test_eigenda_data_source();
        source.open = true;
        source
            .data
            .push(EigenDAOrCalldata::Calldata(Bytes::default()));

        let data = source
            .next(&BlockInfo::default(), Address::ZERO)
            .await
            .unwrap();
        assert_eq!(data, Bytes::default());
    }

    #[tokio::test]
    async fn test_open_eigenda_blob() {
        let mut source = default_test_eigenda_data_source();
        source.open = true;
        let encoded_payload = EncodedPayload {
            encoded_payload: vec![
                0, 0, 0, 0, 0, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1,
            ]
            .into(),
        };
        source
            .data
            .push(EigenDAOrCalldata::EigenDA(encoded_payload));

        let data = source
            .next(&BlockInfo::default(), Address::ZERO)
            .await
            .unwrap();
        assert_eq!(data, vec![1; 31]);
    }

    #[tokio::test]
    async fn test_open_blob_data_decode_encoded_payload() {
        let mut source = default_test_eigenda_data_source();
        source.open = true;
        // the default does not satisfy length requirement
        source
            .data
            .push(EigenDAOrCalldata::EigenDA(EncodedPayload::default()));

        let err = source
            .next(&BlockInfo::default(), Address::ZERO)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PipelineErrorKind::Temporary(PipelineError::Eof)
        ));
    }

    #[tokio::test]
    async fn test_eigenda_blob_source_pipeline_error() {
        let mut source = default_test_eigenda_data_source();
        let err = source
            .next(&BlockInfo::default(), Address::ZERO)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PipelineErrorKind::Temporary(PipelineError::Provider(_))
        ));
    }

    #[tokio::test]
    async fn test_load_eigenda_or_calldata_chain_provider_1559_txs_succeeds_two_txs() {
        let mut source = default_test_eigenda_data_source();
        let block_info = BlockInfo::default();
        // batcher account
        let batcher_address =
            alloy_primitives::address!("0x15F447c49D9eAC8ecA80ce12c5620278E7F59d2F");
        // inbox addr
        source.ethereum_source.blob_source.batcher_address =
            alloy_primitives::address!("0x000faef0a3d9711c3e9bbc4f3e2730dd75167da3");
        let mut txs = valid_eip1559_txs();
        txs.push(txs[0].clone());
        source
            .ethereum_source
            .blob_source
            .chain_provider
            .insert_block_with_transactions(0, block_info, txs);
        //source.ethereum_source.blob_source.chain_provider.insert_block_with_transactions(1, block_info, txs);

        let (altda_commitment, encoded_payload) = valid_encoded_payload_with_altda_commitment();

        source
            .eigenda_source
            .eigenda_fetcher
            .insert_recency(&altda_commitment, Ok(200));
        source
            .eigenda_source
            .eigenda_fetcher
            .insert_validity(&altda_commitment, Ok(true));
        source
            .eigenda_source
            .eigenda_fetcher
            .insert_encoded_payload(&altda_commitment, Ok(encoded_payload));

        source
            .next(&BlockInfo::default(), batcher_address)
            .await
            .expect("should be ok");
        assert!(!source.data.is_empty());
        source
            .next(&BlockInfo::default(), batcher_address)
            .await
            .expect("should be ok");
        assert!(source.open);
        // Blob::with_last_byte(1) cannot be decoded correctly
        // it is pretty strange that kona chooses a test that cannot be decoded
        assert!(source.data.is_empty());
    }
}
