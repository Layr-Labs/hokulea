//! EigenDAPreimageSource Source

use crate::eigenda_data::EncodedPayload;
use crate::traits::EigenDAPreimageProvider;
use crate::HokuleaPreimageError;

use crate::errors::{HokuleaErrorKind, HokuleaStatelessError};
use alloy_primitives::Bytes;
use eigenda_cert::AltDACommitment;

/// A data iterator that reads from a preimage.
#[derive(Debug, Clone)]
pub struct EigenDAPreimageSource<B>
where
    B: EigenDAPreimageProvider + Send,
{
    /// Fetches eigenda preimage.
    pub eigenda_fetcher: B,
}

impl<B> EigenDAPreimageSource<B>
where
    B: EigenDAPreimageProvider + Send,
{
    /// Creates a new preimage source.
    pub const fn new(eigenda_fetcher: B) -> Self {
        Self { eigenda_fetcher }
    }

    /// Fetches the preimages from the source for calldata.
    pub async fn next(
        &mut self,
        calldata: &Bytes,
        l1_inclusion_bn: u64,
    ) -> Result<EncodedPayload, HokuleaErrorKind> {
        let altda_commitment = self.parse(calldata)?;

        info!(target: "eigenda_preimage_source", "parsed an altda commitment of version {}", altda_commitment.cert_version_str());

        // get recency window size, discard the old cert if necessary
        match self
            .eigenda_fetcher
            .get_recency_window(&altda_commitment)
            .await
        {
            Ok(recency) => {
                // see spec <https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#1-rbn-recency-validation>
                if l1_inclusion_bn > altda_commitment.get_rbn() + recency {
                    warn!(
                        "da cert is not recent enough l1_inclusion_bn:{} rbn:{} recency:{}",
                        l1_inclusion_bn,
                        altda_commitment.get_rbn(),
                        recency
                    );
                    return Err(HokuleaPreimageError::NotRecentCert.into());
                }
            }
            Err(e) => return Err(e.into()),
        };

        // get cert validty via preimage oracle, discard cert if invalid
        match self.eigenda_fetcher.get_validity(&altda_commitment).await {
            Ok(true) => (),
            Ok(false) => return Err(HokuleaPreimageError::InvalidCert.into()),
            Err(e) => return Err(e.into()),
        }

        // get encoded payload via preimage oracle
        self.eigenda_fetcher
            .get_encoded_payload(&altda_commitment)
            .await
            .map_err(|e| e.into())
    }

    fn parse(&mut self, data: &Bytes) -> Result<AltDACommitment, HokuleaStatelessError> {
        if data.len() <= 2 {
            // recurse if data is mailformed
            warn!(target: "preimage_source", "Failed to decode altda commitment, skipping");
            return Err(HokuleaStatelessError::InsufficientLengthAltDACommimtment);
        }
        let altda_commitment: AltDACommitment = match data[1..].try_into() {
            Ok(a) => a,
            Err(e) => {
                error!("failed to parse altda commitment {}", e);
                return Err(HokuleaStatelessError::ParseError(e));
            }
        };
        Ok(altda_commitment)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{self, TestEigenDAPreimageSource, TestHokuleaProviderError};

    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use alloy_primitives::hex;
    use eigenda_cert::AltDACommitmentParseError;

    const CALLDATA_HEX: &str = "0x01010001f9035ef901cdf901c8f9018080820001f90158f842a013cb9a6e004f28a193672a95b2ee4a2addc14bfe705eb3c1695f34dccfdf4d7fa01de675df78f68e6f40643f148b7dcf7b30e7bbb5ec5ed66efcf82e02a148b45ef888f842a00ca1a4b18243aed65a6887cb3da7ab7a9b8138261ad5fa7a7ef61fcf45ad0f77a012969add06ec97e0b24ef9f69633114966952c02150f8bb28a55a5fac60c7644f842a00c137feb7cf2cf625b826eebd5a1ffd400446e03336c6ff07061b7a9adc32376a00cd9277cc3e8c2a6c896c4e7c045504d1cff34ec9e8a6648e8ef4f335ae5b943f887f842a02b977c12979aed6688323f70e2d5ca9e2640fe14bf0a5e26ddfac95134d9c09ea02c204a0405fb9c3cb890219c6fccff0a9a265415656c5896449884c6a64caedef841a00104c001661c0169aac0fb16db9f30b70f8e13da88c539904b61895d3494c7889fca145e3f25f772c7e951708a541d8d14bb923edea351eeb0bbc928ae5b798508a0676a73762570ea5c17427aed9db14a85b268fafc282cbbe0c3db9165487133c9b84118cf5bd976613bb6a63009b15613d137f2555d2418da654a11781ac2cf5bf2fb63d44a580d2f15628f4b1cdb9526e1f774360b8ef2e5e451f18a80411d06b42b01c1808080e5a05e27869d58bd1fe21f34d0e9120abe775896df7c0829cf4d870f576f188cbe30838a8d05f90162c0c0f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a027b90b5da16ef02417ad5820223e680d2c2d19a3f1d30566cfbb7b9aa30abf6da022432d9b57d271b8dd84bfb4ccd9df36b84e422cb471b35d50d55ae83a03f16ef842a0018ed79d6c0707cc6f4ec81bcea6c4cc0096f0e3635961caf3271c3c9a36a9dfa0179360dc4646a7c49bf730e1789c00622facd7836faa3c747be0f2d824cb1412f841a02147a377c426a6b91bd27342dfe180882d130d9fbbdcb147477f025082135c189f468884960c4e83243b3aeb52ef2eb017fa81ec4b98f63bedc7c1dc27ec0bfec20705c20805c2c0c0820001";

    pub(crate) fn default_test_preimage_source() -> EigenDAPreimageSource<TestEigenDAPreimageSource>
    {
        let preimage_provider = test_utils::TestEigenDAPreimageSource::default();
        EigenDAPreimageSource::new(preimage_provider)
    }

    #[test]
    fn test_parse_altda_commitment() {
        let mut preimage_source = default_test_preimage_source();
        struct Case {
            input: vec::Vec<u8>,
            result: Result<(), HokuleaStatelessError>,
        }
        let cases = [
            // not long enough such that there is no bytes for altda commitment
            Case {
                input: vec![1],
                result: Err(HokuleaStatelessError::InsufficientLengthAltDACommimtment),
            },
            // invalid altda commitment to cover the altda commitment header
            Case {
                input: vec![1, 1, 1],
                result: Err(HokuleaStatelessError::ParseError(
                    AltDACommitmentParseError::InsufficientData,
                )),
            },
            // 0x01 (OP derivation version byte) ++ valid altda commitment
            Case {
                input: hex::decode(CALLDATA_HEX).unwrap(),
                result: Ok(()),
            },
        ];

        for case in cases {
            if let Err(e) = preimage_source.parse(&case.input.into()) {
                assert_eq!(Err(e), case.result)
            }
        }
    }

    #[tokio::test]
    async fn test_next() {
        let calldata = hex::decode(CALLDATA_HEX).unwrap().into();
        let mut preimage_source = default_test_preimage_source();
        let altda_commitment = preimage_source.parse(&calldata).unwrap();
        let rbn = altda_commitment.get_rbn();
        let l1_inclusion_number = rbn + 100;
        let encoded_payload: Bytes = vec![
            0, 0, 0, 0, 0, 31, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1,
        ]
        .into();

        struct Case {
            recency: Result<u64, TestHokuleaProviderError>,
            validity: Result<bool, TestHokuleaProviderError>,
            encoded_payload: Result<EncodedPayload, TestHokuleaProviderError>,
            result: Result<EncodedPayload, HokuleaErrorKind>,
        }

        let cases = [
            // not recent enough
            Case {
                // l1_inclusion_number = rbn + 100 > rbn + 10
                recency: Ok(10),
                // below are ignored
                validity: Ok(false),
                encoded_payload: Ok(EncodedPayload::default()),
                result: Err(HokuleaPreimageError::NotRecentCert.into()),
            },
            // not valid
            Case {
                // l1_inclusion_number = rbn + 100 < rbn + 200
                recency: Ok(200),
                validity: Ok(false),
                // below are ignored
                encoded_payload: Ok(EncodedPayload::default()),
                result: Err(HokuleaPreimageError::InvalidCert.into()),
            },
            // working
            Case {
                recency: Ok(200),
                validity: Ok(true),
                encoded_payload: Ok(EncodedPayload {
                    encoded_payload: encoded_payload.clone(),
                }),
                result: Ok(EncodedPayload {
                    encoded_payload: encoded_payload.clone(),
                }),
            },
            // recency preimage has a critical problem
            Case {
                recency: Err(TestHokuleaProviderError::InvalidHokuleaPreimageQueryResponse),
                // below are ignored
                validity: Ok(false),
                encoded_payload: Ok(EncodedPayload {
                    encoded_payload: encoded_payload.clone(),
                }),
                result: Err(HokuleaErrorKind::Critical(
                    "Invalid hokulea preimage response".to_string(),
                )),
            },
            // recency preimage has a temporary problem
            Case {
                recency: Err(TestHokuleaProviderError::Preimage),
                // below are ignored
                validity: Ok(false),
                encoded_payload: Ok(EncodedPayload {
                    encoded_payload: encoded_payload.clone(),
                }),
                result: Err(HokuleaErrorKind::Temporary(
                    "Preimage temporary error".to_string(),
                )),
            },
            // validity preimage has a critical problem
            Case {
                recency: Ok(200),
                validity: Err(TestHokuleaProviderError::InvalidHokuleaPreimageQueryResponse),
                // below are ignored
                encoded_payload: Ok(EncodedPayload {
                    encoded_payload: encoded_payload.clone(),
                }),
                result: Err(HokuleaErrorKind::Critical(
                    "Invalid hokulea preimage response".to_string(),
                )),
            },
            // recency preimage has a temporary problem
            Case {
                recency: Ok(200),
                validity: Err(TestHokuleaProviderError::Preimage),
                // below are ignored
                encoded_payload: Ok(EncodedPayload {
                    encoded_payload: encoded_payload.clone(),
                }),
                result: Err(HokuleaErrorKind::Temporary(
                    "Preimage temporary error".to_string(),
                )),
            },
            // encoded payload preimage has a critical problem
            Case {
                recency: Ok(200),
                validity: Ok(true),
                encoded_payload: Err(TestHokuleaProviderError::InvalidHokuleaPreimageQueryResponse),
                result: Err(HokuleaErrorKind::Critical(
                    "Invalid hokulea preimage response".to_string(),
                )),
            },
            // encoded payload preimage has a temporary problem
            Case {
                recency: Ok(200),
                validity: Ok(true),
                encoded_payload: Err(TestHokuleaProviderError::Preimage),
                result: Err(HokuleaErrorKind::Temporary(
                    "Preimage temporary error".to_string(),
                )),
            },
        ];

        for case in cases {
            // set up preimage
            preimage_source
                .eigenda_fetcher
                .insert_recency(&altda_commitment, case.recency);
            preimage_source
                .eigenda_fetcher
                .insert_validity(&altda_commitment, case.validity);
            preimage_source
                .eigenda_fetcher
                .insert_encoded_payload(&altda_commitment, case.encoded_payload);

            match preimage_source.next(&calldata, l1_inclusion_number).await {
                Ok(encoded_payload) => assert_eq!(encoded_payload, case.result.unwrap()),
                Err(e) => assert_eq!(Err(e), case.result),
            }
        }
    }
}
