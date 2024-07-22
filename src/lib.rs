//! Rust FFI binding for MUNGE Uid 'N' Gid Emporium
//!
//!```sh
//! cargo test -q -- --nocapture
//!```
//! This will run the tests without capturing the output so that you can see the test outputs.

#[allow(
    dead_code,
    unused_imports,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
mod ffi;

mod credential;
mod ctx;
mod enums;
mod munge;

pub use credential::Credential;
pub use ctx::Context;
pub use enums::{Error, MungeCipher, MungeError, MungeMac, MungeOption, MungeZip};
pub use munge::{decode, encode};
