//! Rust FFI binding for MUNGE Uid 'N' Gid Emporium
//!
//!

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod ffi;

pub mod credential;
pub mod ctx;
pub mod enums;
pub mod munge;
