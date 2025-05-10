## Run preloader

User must specify the name where to store the temporary .env file, which is always stored at the directory root
```bash
cd example/preloader
```

NoOp Preloader, that does not generate zk proof for eigenda certificate, used for testing. 
```bash
just run-preloader .devnet.env
```

Steel Preloader, generate zk proof with steel backend. By default, a mock steel proof (which is cheap to generate) is created and verified by the guest.
```bash
just run-preloader .devnet.env steel
```

Sp1 contract call Preloader, generate zk proof with sp1-cc backend, but in mock mode, no actual proof generated
```bash
just run-preloader .devnet.env sp1-cc
```



To turn off the mock mode for creating a Steel proof. Currently local proof generation requries a machine with x86 architecture, see [here](https://dev.risczero.com/api/generating-proofs/local-proving#proving-hardware). 

```bash
# Before running the client, it will download the needed g1.point SRS file
# and the rollup.json config file.
just run-preloader .devnet.env steel false
```