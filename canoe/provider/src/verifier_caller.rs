use alloy_sol_types::SolValue;
use canoe_bindings::IEigenDACertVerifierBase;
use eigenda_cert::{AltDACommitment, EigenDACertV3, EigenDAVersionedCert};

/// Call respecting solidity interface
#[allow(clippy::large_enum_variant)]
pub enum CertVerifierCall {
    /// Base is compatible with Router and calling V3 directly
    /// <https://github.com/Layr-Labs/eigenda/blob/f5032bb8683baa2a9eff58443c013f39005d7680/contracts/src/integrations/cert/interfaces/IEigenDACertVerifierBase.sol#L11>
    ABIEncodeInterface(IEigenDACertVerifierBase::checkDACertCall),
}

impl CertVerifierCall {
    /// convert eigenda cert type into its solidity type that works with solidity cert verifier interface
    pub fn build(altda_commitment: &AltDACommitment) -> Self {
        match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V2(v2_cert) => {
                // convert v2 cert to v3 cert, and use the VerifierBase interface to make the call
                let v3_cert = EigenDACertV3 {
                    batch_header_v2: v2_cert.batch_header_v2.clone(),
                    blob_inclusion_info: v2_cert.blob_inclusion_info.clone(),
                    nonsigner_stake_and_signature: v2_cert.nonsigner_stake_and_signature.clone(),
                    signed_quorum_numbers: v2_cert.signed_quorum_numbers.clone(),
                };
                let v3_soltype_cert = v3_cert.to_sol();
                CertVerifierCall::ABIEncodeInterface(IEigenDACertVerifierBase::checkDACertCall {
                    abiEncodedCert: v3_soltype_cert.abi_encode().into(),
                })
            }
            EigenDAVersionedCert::V3(cert) => {
                let v3_soltype_cert = cert.to_sol();
                CertVerifierCall::ABIEncodeInterface(IEigenDACertVerifierBase::checkDACertCall {
                    abiEncodedCert: v3_soltype_cert.abi_encode().into(),
                })
            }
        }
    }
}
