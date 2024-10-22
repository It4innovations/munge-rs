# Munge RS
Rust FFI binding for [MUNGE Uid 'N' Gid Emporium](https://github.com/dun/munge).

## Installation
- Clone this repo
- Add the following to your `Cargo.toml`:

```toml
[dependencies.munge-rs]
path = "/path/to/munge-rs"
```
or inline
```toml
[dependencies]
munge-rs = { path = "/path/to/munge-rs" }
```

I will try to add the library into crates.io as well

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
