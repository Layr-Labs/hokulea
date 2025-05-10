## Build preloader

NoOp Preloader, that does not generate zk proof for eigenda certificate, used for testing
```
cargo build
```

Steel Preloader, generate zk proof with steel backend, but in dev mode, no actual proof generated
```
cargo build --features steel
```

Sp1 contract call Preloader, generate zk proof with sp1-cc backend, but in mock mode, no actual proof generated
```
cargo build --features sp1-cc
```