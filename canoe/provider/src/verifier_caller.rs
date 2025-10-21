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
            // convert v2 cert into v3 cert in order to call Router/CertVerifier which only supports version >= 3
            EigenDAVersionedCert::V2(v2_cert) => {
                let v3_cert: EigenDACertV3 = v2_cert.into();
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
