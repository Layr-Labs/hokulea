# Hokulea Registry

Registry of custom CertVerifier router addresses for rollups deploying their own routers.

## When to Use

- ✅ **Use this registry** if you deploy your own CertVerifier/router contracts
- ❌ **Use `CanoeVerifierAddressFetcherDeployedByEigenLabs`** if you use EigenLabs-deployed routers

Supported L1 chains: Mainnet (1), Sepolia (11155111)

## Contributing Your Router Address

### Requirements

- Stable, production-ready router deployment
- Contract verified on block explorer
- Deployed on Mainnet or Sepolia

### How to Submit

1. Add your address to `src/lib.rs`:
   ```rust
   // For Mainnet
   10 => Ok(address!("0x...")),  // OP Mainnet

   // For Sepolia
   11155420 => Ok(address!("0x...")),  // OP Sepolia
   ```

2. Submit PR with:
   - Rollup name and L2 chain ID
   - Router address and block explorer link
   - Confirmation of stable deployment

## Usage

```rust
use hokulea_registry::HokuleaRegistry;
use canoe_verifier_address_fetcher::L2SpecificCanoeVerifierAddressFetcher;

let registry = HokuleaRegistry {};
let address = registry.fetch_address_for_l2(
    1,                // L1 chain ID
    &versioned_cert,
    12345,            // L2 chain ID (compile-time required)
)?;
```
