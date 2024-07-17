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

#[cfg(test)]
mod libTests {

    use libc::c_char;

    use super::*;
    use std::ptr;

    #[test]
    fn roundtrip_encode_decode() {
        // Box is used to allocate memory to `cred`
        #[allow(unused_mut)]
        let mut cred: *mut *mut c_char = Box::into_raw(Box::new(ptr::null_mut()));
        let ctx = unsafe { ffi::munge_ctx_create() };
        if ctx.is_null() {
            panic!("Failed to create munge context!");
        }
        let mut _err: u32 = 42;
        unsafe {
            ffi::munge_ctx_set(
                ctx,
                ffi::munge_opt_MUNGE_OPT_SOCKET as i32,
                "/usr/local/var/run/munge/munge.socket.2",
            );
            _err = ffi::munge_encode(cred, ctx, ptr::null(), 0);
        }
        assert_eq!(
            _err,
            ffi::munge_err_EMUNGE_SUCCESS,
            "{:?}",
            enums::MungeError::from_u32(_err)
        );
        println!("Roundtrip Credential {:?}", &cred);

        let cred_value: *const c_char = unsafe { *cred };

        let mut uid: u32 = 42;
        let mut gid: u32 = 69;
        let mut _decode_err: u32 = 42;
        unsafe {
            _decode_err = ffi::munge_decode(
                cred_value,
                ctx,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut uid,
                &mut gid,
            );
        }
        println!("UID: {}, \tGID: {}", uid, gid);
        assert_eq!(
            _decode_err,
            ffi::munge_err_EMUNGE_SUCCESS,
            "{:?}",
            enums::MungeError::from_u32(_decode_err)
        );
    }

    #[test]
    fn encode() {
        #[allow(unused_mut)]
        let mut cred: *mut *mut c_char = Box::into_raw(Box::new(ptr::null_mut()));
        let ctx = unsafe { ffi::munge_ctx_create() };
        // if safe_ctx {
        //     panic!("Failed to create munge context!");
        // }
        let mut _err: u32 = 42;
        let mut _set_err: u32 = 69;
        let mut _err_desc: &str = "";
        unsafe {
            _set_err = ffi::munge_ctx_set(
                ctx,
                ffi::munge_opt_MUNGE_OPT_SOCKET as i32,
                "/usr/local/var/run/munge/munge.socket.2",
            );
            _err = ffi::munge_encode(cred, ctx, ptr::null(), 0);
        }
        assert_eq!(
            _err,
            ffi::munge_err_EMUNGE_SUCCESS,
            "{:?}",
            enums::MungeError::from_u32(_err)
        );
        println!("Encode credential: {:?}", cred);
    }
}
