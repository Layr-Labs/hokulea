# Hokulea

Hokulea is a library to provide the altda providers for a derivation pipeline built with [kona](https://github.com/anton-rs/kona) to understand eigenDA blobs, following the [kona book](https://op-rs.github.io/kona/protocol/derive/providers.html#implementing-a-custom-data-availability-provider) recommendation (also see this [comment](https://github.com/anton-rs/kona/pull/862#issuecomment-2515038089)).

Below is the dependency graph between hokulea and kona crates:
<!-- Run `just generate-deps-graphviz` to regenerate/update this diagram -->
![](./generated/dependencies_graph.png)

### Dependencies

We use mise to track and manage dependencies. Please first [install mise](https://mise.jdx.dev/getting-started.html), and then run `mise install` to install the dependencies.

### SRS points
Hokulea's proving client currently computes a challenge proof that validates the correctness of the eigenda blob against the provided kzg commitment. Such computation requires the proving client to have access to sufficient KZG G1 SRS points. Currently the SRS points are (hardcoded) assumed to be located at `resources/g1.point`. You can download the SRS points to that location by running `just download-srs`, which downloads the `g1.point` file from the [eigenda repo](https://github.com/Layr-Labs/eigenda-proxy/tree/main/resources).

### Local Manual Testing

We use kurtosis to start an [optimism-package](https://github.com/ethpandaops/optimism-package/tree/main) devnet, and run the hokulea host and client against it.

```bash
just run-kurtosis-devnet
# Before running the client, it will download the needed g1.point SRS file
# and the rollup.json config file.
just run-client-native-against-devnet
```

![](./hokulea.jpeg)
