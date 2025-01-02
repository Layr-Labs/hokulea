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

![](./hokulea.jpeg)
