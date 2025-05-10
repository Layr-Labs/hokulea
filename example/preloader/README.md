## Run preloader

NoOp Preloader, that does not generate zk proof for eigenda certificate, used for testing. User must specify the name where to store the temporary env file, which is always stored at the directory root
```
just run-preloader .devnet.env
```

Steel Preloader, generate zk proof with steel backend, but in dev mode, no actual proof generated
```
just run-preloader .devnet.env --features steel
```

Sp1 contract call Preloader, generate zk proof with sp1-cc backend, but in mock mode, no actual proof generated
```
just run-preloader .devnet.env --features sp1-cc
```