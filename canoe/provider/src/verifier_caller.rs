use alloy_sol_types::SolValue;
use canoe_bindings::{IEigenDACertVerifier, IEigenDACertVerifierBase};
use eigenda_cert::{AltDACommitment, EigenDAVersionedCert};

/// Call respecting solidity interface
#[allow(clippy::large_enum_variant)]
pub enum CertVerifierCall {
    /// contract interface for v2 cert
    /// <https://github.com/Layr-Labs/eigenda/blob/f5032bb8683baa2a9eff58443c013f39005d7680/contracts/src/integrations/cert/legacy/IEigenDACertVerifierLegacy.sol#L62>
    LegacyV2Interface(IEigenDACertVerifier::verifyDACertV2ForZKProofCall),
    /// Base is compatible with Router and calling V3 directly
    /// <https://github.com/Layr-Labs/eigenda/blob/f5032bb8683baa2a9eff58443c013f39005d7680/contracts/src/integrations/cert/interfaces/IEigenDACertVerifierBase.sol#L11>
    ABIEncodeInterface(IEigenDACertVerifierBase::checkDACertCall),
}

impl CertVerifierCall {
    /// convert eigenda cert type into its solidity type that works with solidity cert verifier interface
    pub fn build(altda_commitment: &AltDACommitment) -> Self {
        match &altda_commitment.versioned_cert {
            EigenDAVersionedCert::V2(cert) => CertVerifierCall::LegacyV2Interface(
                IEigenDACertVerifier::verifyDACertV2ForZKProofCall {
                    batchHeader: cert.batch_header_v2.to_sol(),
                    blobInclusionInfo: cert.blob_inclusion_info.clone().to_sol(),
                    nonSignerStakesAndSignature: cert.nonsigner_stake_and_signature.to_sol(),
                    signedQuorumNumbers: cert.signed_quorum_numbers.clone(),
                },
            ),
            EigenDAVersionedCert::V3(cert) => {
                let v3_soltype_cert = cert.to_sol();
                CertVerifierCall::ABIEncodeInterface(IEigenDACertVerifierBase::checkDACertCall {
                    abiEncodedCert: v3_soltype_cert.abi_encode().into(),
                })
            }
        }
    }
}
