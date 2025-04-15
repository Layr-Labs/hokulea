# Hokulea

Hokulea is a library to provide the altda providers for a derivation pipeline built with [kona](https://github.com/anton-rs/kona) to understand eigenDA blobs, following the [kona book](https://op-rs.github.io/kona/protocol/derive/providers.html#implementing-a-custom-data-availability-provider) recommendation (also see this [comment](https://github.com/anton-rs/kona/pull/862#issuecomment-2515038089)).

Below is the dependency graph between hokulea and kona crates:
<!-- Run `just generate-deps-graphviz` to regenerate/update this diagram -->
![](./generated/dependencies_graph.png)

### Download SRS points
Hokulea host currently computes a challenge proof that validates the correctness of the eigenda blob against the provided kzg commitment. Such computation requires the host to have access to sufficient KZG SRS points. Follow the [link](https://github.com/Layr-Labs/eigenda-proxy/tree/main/resources) to download the points and save it to ./resources/g1.point

### Running against devnet

First start the devnet on a local L1 that uses eigenda v1:
```bash
git clone https://github.com/Layr-Labs/optimism.git
cd optimism/kurtosis-devnet && just eigenda-devnet-start
```
Then request rollup config and save it:
```bash
kurtosis files inspect eigenda-devnet op-deployer-configs ./rollup-2151908.json 1> rollup.json
```
Then run hokulea against v1:
```bash
cd bin/client
just run-client-native-against-devnet
```

![](./hokulea.jpeg)
