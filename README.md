# Schnorrkel-c

Provide a C wrapper for native app calling based on RUST implementation.

## 1.Directory struct
```
.
|--src
    |--def.h    //extern raw rust function to C.
    |--lib.h    //C API define
    |--lib.c    //impl of C API
    |--lib.rs   //wrapper of RUST, make it easy to call from C
    |--test.c   //test code
|--readme.md
|--Cargo.toml
|--test //execute binary

```

## How to use

### compile rust

in project root dir:
```
cargo build
```
### compile C
in project root dir, use gcc:

```
gcc -g -o test ./src/lib.c ./src/test.c ./target/debug/libschnorrkel_c.so -L. -Wl,-rpath=.^C
```
### Run test
```
./test
```
