# Hokulea

Hokulea is a library to provide the altda providers for a derivation pipeline built with [kona](https://github.com/anton-rs/kona) to understand eigenDA blobs, following the [kona book](https://anton-rs.github.io/kona/sdk/pipeline/providers.html#implementing-a-custom-data-availability-provider) recommendation (also see this [comment](https://github.com/anton-rs/kona/pull/862#issuecomment-2515038089)).

### Download SRS points
Hokulea host currently computes a challenge proof that validates the correctness of the eigenda blob against the provided kzg commitment. Such computation requires the host to have access to sufficient KZG SRS points. Follow the [link](https://github.com/Layr-Labs/eigenda-proxy/tree/main/resources) to download the points and save it to ./resources/g1.point

### Running against devnet

First start the devnet on a local L1 that uses eigenda v1:
```bash
git clone https://github.com/Layr-Labs/optimism.git
cd optimism/kurtosis-devnet && just eigenda-memstore-devnet
```
Then request rollup config and save it:
```bash
ROLLUP_NODE_RPC=$(kurtosis port print eigenda-memstore-devnet op-cl-1-op-node-op-geth-op-kurtosis http) && curl -X POST -H "Content-Type: application/json" --data     '{"jsonrpc":"2.0","method":"optimism_rollupConfig","params":[],"id":1}' $ROLLUP_NODE_RPC | jq .result > rollup.json
```
Then run hokulea against v1:
```bash
cd bin/client
just run-client-native-against-devnet
```

![](./hokulea.jpeg)