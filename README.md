# Hokulea

> Hokulea is a Polynesian double-hulled voyaging canoe. Hōkūle‘a (“Star of Gladness”), a zenith star of Hawai‘i, which appeared to him growing ever brighter in a dream. [Source](https://worldwidevoyage.hokulea.com/vessels/hokulea/)

Hokulea is a library to provide the altda providers for a derivation pipeline built with [kona](https://github.com/anton-rs/kona) to understand eigenDA blobs, following the [kona book](https://op-rs.github.io/kona/protocol/derive/providers.html#implementing-a-custom-data-availability-provider) recommendation (also see this [comment](https://github.com/anton-rs/kona/pull/862#issuecomment-2515038089)).

## Dependencies

We use mise to track and manage dependencies. Please first [install mise](https://mise.jdx.dev/getting-started.html), and then run `mise install` to install the dependencies.

## SRS points
Hokulea's proving client currently computes a challenge proof that validates the correctness of the eigenda blob against the provided kzg commitment. Such computation requires the proving client to have access to sufficient KZG G1 SRS points. Currently the SRS points are (hardcoded) assumed to be located at `resources/g1.point`. You can download the SRS points to that location by running `just download-srs`, which downloads the `g1.point` file from the [eigenda repo](https://github.com/Layr-Labs/eigenda-proxy/tree/main/resources).

## Local Manual Testing

We use kurtosis to start an [optimism-package](https://github.com/ethpandaops/optimism-package/tree/main) devnet, and run the hokulea host and client against it.

```bash
just run-kurtosis-devnet
```

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
just run-client-against-sepolia 'native'
```

![](./assets/hokulea.jpeg)
