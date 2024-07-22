#![warn(missing_docs)]

//! Rust FFI binding for MUNGE Uid 'N' Gid Emporium
//!
//!

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
