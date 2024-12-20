# Hokulea

Hokulea is a library to provide the altda providers for a derivation pipeline built with [kona](https://github.com/anton-rs/kona) to understand eigenDA blobs, following the [kona book](https://anton-rs.github.io/kona/sdk/pipeline/providers.html#implementing-a-custom-data-availability-provider) recommendation (also see this [comment](https://github.com/anton-rs/kona/pull/862#issuecomment-2515038089)).

### Running against devnet

First start the devnet:
```bash
git clone https://github.com/ethereum-optimism/optimism.git
cd optimism
DEVNET_ALTDA=true GENERIC_ALTDA=true make devnet-up
```
Then run hokulea:
```bash
cd bin/client
just run-client-native-against-devnet
```

To use eigenda proxy within optimism devnet, modify ops-bedrock/docker-compose.yaml:
```
da-server:
  image: ghcr.io/layr-labs/eigenda-proxy:v1.6.1
  environment:
    EIGENDA_PROXY_ADDR: 0.0.0.0
    EIGENDA_PROXY_PORT: 3100
    EIGENDA_PROXY_METRICS_ENABLED: true
    EIGENDA_PROXY_METRICS_PORT: 7300
    EIGENDA_PROXY_MEMSTORE_ENABLED: true
    EIGENDA_PROXY_MEMSTORE_EXPIRATION: 45m
    EIGENDA_PROXY_MEMSTORE_PUT_LATENCY: 0s
    EIGENDA_PROXY_MEMSTORE_GET_LATENCY: 0s
    EIGENDA_PROXY_EIGENDA_CERT_VERIFICATION_DISABLED: true
```

![](./hokulea.jpeg)