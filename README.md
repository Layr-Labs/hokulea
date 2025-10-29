# Hokulea

> Hokulea is a Polynesian double-hulled voyaging canoe. Hōkūle‘a (“Star of Gladness”), a zenith star of Hawai‘i, which appeared to him growing ever brighter in a dream. [Source](https://worldwidevoyage.hokulea.com/vessels/hokulea/)

Hokulea is a library to provide the altda providers for a derivation pipeline built with [kona](https://github.com/anton-rs/kona) to understand eigenDA blobs, following the [kona book](https://op-rs.github.io/kona/protocol/derive/providers.html#implementing-a-custom-data-availability-provider) recommendation (also see this [comment](https://github.com/anton-rs/kona/pull/862#issuecomment-2515038089)).

## Dependencies

We use mise to track and manage dependencies. Please first [install mise](https://mise.jdx.dev/getting-started.html), and then run `mise install` to install the dependencies.

## SRS points
Hokulea's proving client currently computes a challenge proof that validates the correctness of the eigenda blob against the provided kzg commitment. Such computation requires the proving client to have access to sufficient KZG G1 SRS points. Currently the SRS points are (hardcoded) assumed to be located at `resources/g1.point`. You can download the SRS points to that location by running `just download-srs`, which downloads the `g1.point` file from the [eigenda repo](https://github.com/Layr-Labs/eigenda-proxy/tree/main/resources).

## Integrating with Hokulea

A complete overview of the integration pipeline can be found in the [documentation](./docs/README.md). For zkVM integration details, refer to the following sections:
- [Overview on data transformation for secure integration with zkVM](./docs/README.md#overview-on-data-transformation-for-secure-integration-with-zkvm)
- [Three implementation of EigenDAPreimageProvider trait and their differences](./docs/README.md#three-implementation-of-eigendapreimageprovider-trait-and-their-differences)

For a practical example of how the library can be integrated with a zkVM, see `example/preloader/main.rs`. (Note: this example includes mock elements for demonstration purposes.)
For real-world implementations, both Op-succinct and Kailua integrate Hokulea in their zkVM workflows:

- [Op-succinct client](https://github.com/succinctlabs/op-succinct/tree/main/programs/range/eigenda)
- [Op-succinct host](https://github.com/succinctlabs/op-succinct/tree/main/utils/eigenda/host)
- [Kailua client](https://github.com/boundless-xyz/kailua/tree/main/crates/hokulea/src)
- [Kailua host](https://github.com/boundless-xyz/kailua/tree/main/crates/prover/src/hokulea)

[documentation](./docs/README.md) is also applicable for other integrations, and pay special attention on the trust assumption on certain data structure.

## EigenDA proxy configuration
Hokulea relies on eigenda proxy for fetching preimage values, including `recency_window`, `cert_validity` and `encoded_payload`. For cert validity and encode payload, the preimage comes from proxy and is verified later, whereas the recency window value is set in hokulea directly. However, the proxy maintains its own recency_window to process the eigenda blob derivation. For all trustless integrations, this number must be kept consistent on every proxy run by `op-node`s.

Currently, each rollup is free to choose the `recency_window` value, and it determines the staleness of AltDA commitments (DA certificates). If a DA Certificate is stale based on the recency value, it is dropped from the derivation pipeline. For more info see our [spec](https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#1-rbn-recency-validation). We recommend it be set to the `seq_window_size` from the rollup config.

Currently on proxy, the recency window is set to 0 by default, which ignores any recency check entirely. If recency is configured to some other value (like `seq_window_size`), the following components need to share the same value or history of values
- when starting the hokulea host, by setting `recency_window`
- and implementing `RecencyWindowProvider` trait
- ensure all proxy are using the same recency config

To prevent misconfiguration, hokulea has required user to enter the `recency_window` which would be checked against the implementation of `RecencyWindowProvider` trait when creating the hokulea ELF file. If the provided host argument is different from the `RecencyWindowProvider` implementation, the proving system would abort. There is planned work on proxy to expose its public config, such that all proxy users (like hokulea host) can retrieve the `recency window` from the proxy.

## Local Manual Testing

We use kurtosis to start an [optimism-package](https://github.com/ethpandaops/optimism-package/tree/main) devnet, and run the hokulea host and client against it.

```bash
just run-kurtosis-devnet-with-eigenlabs-package
```

## Supported L1 Chain
Hokulea now supports Mainnet, Sepolia and Holesky. More in the future. However, chain id `3151908` is explicitly not supported for trustless secure integration. Hokulea uses kurtosis devnet with chain id `3151908` for testing. Proving against `3151908` will generate a ZK proof that cannot be verified by the `CanoeVerifier` implementation in this repo.

### Running the native client

```bash
# Before running the client, it will download the needed g1.point SRS file
# and the rollup.json config file. Temporary env variables are stored at
# .devnet.env and .run.devnet.env
just run-client-against-devnet 'native'
```

### Running on Asterisc

> :Warning: Building the client to run on asterisc currently doesn't work. We are spending most of our current effort on zk approaches instead, but we will eventually fix this.

You will first need to build the client against the correct arch. Run
```bash
just build-client-for-asterisc
```
Then you can run
```bash
just run-client-against-devnet 'asterisc'
```

### Risc0 and Sp1 toolchain installation

[Canoe](./canoe/) takes advantage of zkvm to create a validity proof that attestes the validity of DA certificates. The proof generation requires 
compiling rust code into a ELF file runnable within zkVM. The canoe crate in Hokulea is dedicated for such purpose.
Canoe currently supports two backends:
1. Steel(Risc0)
   - under [canoe/steel](https://github.com/Layr-Labs/hokulea/blob/3599bbeb855156164643a2a56c4f92de0cf7b7cf/crates/proof/Cargo.toml#L44) feature.
   - Requires installing the Risc0 toolchain, see [rzup](https://dev.risczero.com/api/zkvm/install).
2. Sp1-contract-call(Succinct)
   - under [canoe/sp1-cc](https://github.com/Layr-Labs/hokulea/blob/3599bbeb855156164643a2a56c4f92de0cf7b7cf/crates/proof/Cargo.toml#L45) feature.
   - Requires installing Sp1 toolchain, see [sp1up](https://docs.succinct.xyz/docs/sp1/getting-started/install).

Trying to build the hokulea client binary with either zkvm backend feature will fail if the respective toolchain is not installed.

### Running the example preloaded client with Steel or Sp1-contract-call
```bash
cd example/preloader
just run-preloader .devnet.env
```

More information at [./example/preloader/README.md](./example/preloader/README.md)

### If you are interested in looking at the dependancy graph of crates
```bash
just generate-deps-graphviz
```

## Run Against Sepolia

You will need to run an instance of [eigenda-proxy](https://github.com/Layr-Labs/eigenda-proxy) with V2 support. Then populate the `.sepolia.env` file, see a template at `.example.env`.

```bash
# To download a `sepolia.rollup.json` from a rollup consensus node, you can use the command
cast rpc "optimism_rollupConfig" --rpc-url $ROLLUP_NODE_RPC | jq > sepolia.rollup.json
# Before running the client, it will download the needed g1.point SRS file
# and the rollup.json config file. Temporary env variables are stored at
# .sepolia.env and .run.sepolia.env
# No need to fill L1_CONFIG_PATH as sepolia can be inferred from l2 rollup config
just run-client-against-sepolia 'native'
```

![](./assets/hokulea.jpeg)
