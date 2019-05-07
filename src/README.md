# Schnorrkel-c

Provide a C wrapper for native app calling based on RUST implementation.

## How to use

gcc compile command

```
gcc -g -o test ./src/lib.c ./src/test.c ./target/debug/libschnorrkel_c.so -L. -Wl,-rpath=.^C
```

RUST 

```
cargo build
```