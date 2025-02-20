# Hokulea

Hokulea is a library to provide the altda providers for a derivation pipeline built with [kona](https://github.com/anton-rs/kona) to understand eigenDA blobs, following the [kona book](https://anton-rs.github.io/kona/sdk/pipeline/providers.html#implementing-a-custom-data-availability-provider) recommendation (also see this [comment](https://github.com/anton-rs/kona/pull/862#issuecomment-2515038089)).

### Download SRS points
Hokulea host currently computes a challenge proof that validates the correctness of the eigenda blob against the provided kzg commitment. Such computation requires the host to have access to sufficient KZG SRS points. Follow the [link](https://github.com/Layr-Labs/eigenda-proxy/tree/main/resources) to download the points

### Running against devnet

First start the devnet:
```bash
git clone -b v1.10.0 https://github.com/ethereum-optimism/optimism.git
# this patches the optimism devnet to use the eigenda-proxy instead of their da-server
git patch optimism/ops-bedrock/docker-compose.yml < op-devnet.docker-compose.yml.patch
DEVNET_ALTDA=true GENERIC_ALTDA=true make -C ./optimism devnet-up
```
Then run hokulea:
```bash
cd bin/client
just run-client-native-against-devnet
```

![](./hokulea.jpeg)
