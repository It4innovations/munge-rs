use std::{
    ffi::{self, CStr, CString},
    ptr,
};

use crate::{
    credential::Credential,
    ctx,
    enums::{self, MungeError},
    ffi as c,
};

// for the doc string
#[allow(unused_imports)]
use ctx::Context;

/// Takes a string to be included with encoded credential and an optional [`Context`]
///
/// INTERNALLY:  
/// Creates a credential contained in a NUL-terminated base64 string.
///   A payload specified by a buffer [buf] of length [len] can be
///   encapsulated in as well.
/// If the munge context [ctx] is NULL, the default context will be used.
/// A pointer to the resulting credential is returned via [cred]; the caller
///   is responsible for freeing this memory.
/// Returns EMUNGE_SUCCESS if the credential is successfully created;
///   o/w, sets [cred] to NULL and returns the munge error number.
///   If a [ctx] was specified, it may contain a more detailed error
///   message accessible via munge_ctx_strerror().
///
/// `munge_err_t munge_encode (char **cred, munge_ctx_t ctx, const void *buf, int len);`
///
/// # Errors
///
/// TODO:
pub fn encode(msg: &str, ctx: Option<ctx::Context>) -> Result<String, enums::Error> {
    let mut cred: *mut ffi::c_char = ptr::null_mut();
    let len: ffi::c_int = msg.len() as i32;
    let buf: *const ffi::c_void = CString::new(msg)?.into_raw() as *const ffi::c_void;

    let err: u32;

    if let Some(ctx) = ctx {
        err = unsafe { c::munge_encode(&mut cred, ctx.context(), buf, len) };
    } else {
        err = unsafe { c::munge_encode(&mut cred, ptr::null_mut(), buf, len) };
    }
    if err != 0 {
        Err(MungeError::from_u32(err).into())
    } else {
        let resp = Ok(unsafe { CStr::from_ptr(cred as *const i8) }
            .to_str()?
            .to_string());
        unsafe { libc::free(cred as *mut ffi::c_void) };
        resp
    }
}

/// Decodes the provided base64 encoded string.  
/// Returns a [`Credential`]
///
/// # Errors
///
/// TODO:
pub fn decode(encoded_msg: String) -> Result<Credential, enums::Error> {
    let cred: *mut ffi::c_char = CString::new(encoded_msg)?.into_raw();
    let mut dmsg: *mut ffi::c_void = ptr::null_mut();
    let mut len: ffi::c_int = 0;
    let mut uid: c::uid_t = 0;
    let mut gid: c::gid_t = 0;

    let err = unsafe {
        c::munge_decode(
            cred,
            ptr::null_mut(),
            &mut dmsg,
            &mut len,
            &mut uid,
            &mut gid,
        )
    };
    if err != 0 {
        Err(MungeError::from_u32(err).into())
    } else {
        let resp: String = if !dmsg.is_null() {
            unsafe { CStr::from_ptr(dmsg as *const i8) }
                .to_str()?
                .to_string()
        } else {
            "".to_string()
        };
        unsafe { libc::free(dmsg) };
        Ok(Credential {
            message: resp,
            uid,
            gid,
        })
    }
}

#[cfg(test)]
mod munge_tests {
    use std::path::PathBuf;

    use crate::{
        ctx::Context,
        munge::{self},
    };

    #[test]
    fn encode_test() {
        let cred = munge::encode("Hello World! 'aaaa'", None).expect("Failed to encode");
        println!("{:?}", cred);
    }
    #[test]
    fn encode_test_w_ctx() {
        let mut ctx = Context::new();
        ctx.set_socket(PathBuf::from("/usr/local/var/run/munge/munge.socket.2"))
            .unwrap();
        let cred = munge::encode("Hello World!", Some(ctx)).expect("Failed to encode");
        println!("Cred with context: {:?}", cred);
    }

    #[test]
    fn encode_decode() {
        let cred = munge::encode("Goodbye cruel world...", None).expect("Failed to encode");

        let res = munge::decode(cred).expect("Failed to decode");
        println!("Result: {:?}", res);
    }
}
