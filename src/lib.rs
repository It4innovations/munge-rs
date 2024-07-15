#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod credential;
pub mod ctx;
pub mod error;
pub mod mungeOption;

/// returns: munge_err_t
/// params:
///     credential
///     munge_ctx_t
///     buffer, length <- payload
///
/// C prototype: `munge_err_t munge_encode(char **cred, munge_ctx_t ctx, const void *buf, int len);`
pub fn encode(payload: Option<&'_ [u8]>) -> Result<String, error::MungeError> {
    todo!()
}

// TODO: Implement encode decode test
#[cfg(test)]
mod tests {

    use super::*;
    use std::ptr;

    #[test]
    fn roundtrip_encode_decode() {
        let mut cred: *mut *mut ::std::os::raw::c_char = Box::into_raw(Box::new(ptr::null_mut()));
        let ctx = unsafe { munge_ctx_create() };
        if ctx.is_null() {
            panic!("Failed to create munge context!");
        }
        let mut err: u32 = 42;
        unsafe {
            munge_ctx_set(
                ctx,
                munge_opt_MUNGE_OPT_SOCKET as i32,
                "/usr/local/var/run/munge/munge.socket.2",
            );
            err = munge_encode(cred, ptr::null_mut(), ptr::null(), 0);
        }
        assert_eq!(err, munge_err_EMUNGE_SUCCESS);

        let cred_value: *const ::std::os::raw::c_char = unsafe { *cred };

        let mut uid: u32 = 42;
        let mut gid: u32 = 69;
        let mut decode_err: u32 = 42;
        unsafe {
            decode_err = munge_decode(
                cred_value,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut uid,
                &mut gid,
            );
        }
        println!("UID: {}, \tGID: {}", uid, gid);
        assert_eq!(decode_err, munge_err_EMUNGE_SUCCESS);
    }

    #[test]
    fn encode() {
        let mut cred: *mut *mut ::std::os::raw::c_char = Box::into_raw(Box::new(ptr::null_mut()));
        let ctx = unsafe { munge_ctx_create() };
        if ctx.is_null() {
            panic!("Failed to create munge context!");
        }
        let mut err: u32 = 42;
        unsafe {
            munge_ctx_set(
                ctx,
                munge_opt_MUNGE_OPT_SOCKET as i32,
                "/usr/local/var/run/munge/munge.socket.2",
            );
            err = munge_encode(cred, ptr::null_mut(), ptr::null(), 0);
        }
        assert_eq!(err, munge_err_EMUNGE_SUCCESS);
    }
}
