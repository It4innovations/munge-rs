# Munge RS
Rust FFI binding for [MUNGE Uid 'N' Gid Emporium](https://github.com/dun/munge).

## Building
```sh
git clone --depth 1 https://github.com/It4innovations/munge-rs
cd munge-rs
cargo build --release
```  

## Running tests
To run the tests and see more output use

```sh
cargo test -q -- --nocapture
```
Otherwise use

```sh
cargo test
```
