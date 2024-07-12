#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use libc::c_char;

    use super::*;
    use std::{mem, ptr};

    #[test]
    fn roundtrip_encode_decode() {
        let mut cred: *mut *mut c_char = ptr::null_mut();
        let result = unsafe { munge_encode(cred, std::ptr::null_mut(), ptr::null(), 0) };
    }
}
