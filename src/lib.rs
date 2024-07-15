#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod credential;
pub mod ctx;
pub mod enums;

// C prototype: `munge_err_t munge_encode(char **cred, munge_ctx_t ctx, const void *buf, int len);`
// pub fn encode(payload: Option<&'_ [u8]>) -> Result<String, error::MungeError> {
//     todo!()
// }

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
        let ctx = unsafe { munge_ctx_create() };
        if ctx.is_null() {
            panic!("Failed to create munge context!");
        }
        let mut _err: u32 = 42;
        unsafe {
            munge_ctx_set(
                ctx,
                munge_opt_MUNGE_OPT_SOCKET as i32,
                "/usr/local/var/run/munge/munge.socket.2",
            );
            _err = munge_encode(cred, ctx, ptr::null(), 0);
        }
        assert_eq!(
            _err,
            munge_err_EMUNGE_SUCCESS,
            "{:?}",
            enums::MungeError::from_u32(_err)
        );

        let cred_value: *const c_char = unsafe { *cred };

        let mut uid: u32 = 42;
        let mut gid: u32 = 69;
        let mut _decode_err: u32 = 42;
        unsafe {
            _decode_err = munge_decode(
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
            munge_err_EMUNGE_SUCCESS,
            "{:?}",
            enums::MungeError::from_u32(_decode_err)
        );
    }

    #[test]
    fn encode() {
        #[allow(unused_mut)]
        let mut cred: *mut *mut c_char = Box::into_raw(Box::new(ptr::null_mut()));
        let ctx = unsafe { munge_ctx_create() };
        // if safe_ctx {
        //     panic!("Failed to create munge context!");
        // }
        let mut _err: u32 = 42;
        unsafe {
            munge_ctx_set(
                ctx,
                munge_opt_MUNGE_OPT_SOCKET as i32,
                "/usr/local/var/run/munge/munge.socket.2",
            );
            _err = munge_encode(cred, ctx, ptr::null(), 0);
        }
        assert_eq!(
            _err,
            munge_err_EMUNGE_SUCCESS,
            "{:?}",
            enums::MungeError::from_u32(_err)
        );
    }
}
