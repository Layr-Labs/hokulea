# Hokulea

![](./hokulea.jpeg)

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