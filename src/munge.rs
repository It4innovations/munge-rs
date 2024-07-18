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
/// # Errors
///
pub fn encode(msg: &str, ctx: Option<&ctx::Context>) -> Result<String, enums::Error> {
    let mut cred: *mut ffi::c_char = ptr::null_mut();
    let len: ffi::c_int = msg.len() as i32;
    let buf: *const ffi::c_void = CString::new(msg)?.into_raw() as *const ffi::c_void;

    let err: u32 = if let Some(ctx) = ctx {
        unsafe { c::munge_encode(&mut cred, ctx.ctx, buf, len) }
    } else {
        unsafe { c::munge_encode(&mut cred, ptr::null_mut(), buf, len) }
    };

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
/// If no context is provided the default values are used.  
///
/// Returns a [`Credential`]
///
/// # Errors
///
/// This will return an error thrown by munge or when the provided [`encoded_msg`] is invalid ie.
/// the bytes provided contain an internal 0 byte. [`std::ffi::NulError`]
pub fn decode(encoded_msg: String, ctx: Option<&Context>) -> Result<Credential, enums::Error> {
    let cred: *mut ffi::c_char = CString::new(encoded_msg)?.into_raw();
    let mut dmsg: *mut ffi::c_void = ptr::null_mut();
    let mut len: ffi::c_int = 0;
    let mut uid: c::uid_t = 0;
    let mut gid: c::gid_t = 0;

    let err: u32 = if let Some(ctx) = ctx {
        unsafe { c::munge_decode(cred, ctx.ctx, &mut dmsg, &mut len, &mut uid, &mut gid) }
    } else {
        unsafe {
            c::munge_decode(
                cred,
                ptr::null_mut(),
                &mut dmsg,
                &mut len,
                &mut uid,
                &mut gid,
            )
        }
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
        let socket = ctx.get_socket().expect("Failed to get socket.");
        ctx.set_socket(socket).expect("Failed to set socket.");
        let cred = munge::encode("Hello World!", Some(&ctx)).expect("Failed to encode");
        println!("Cred with context: {:?}", cred);
    }

    #[test]
    fn encode_decode() {
        let cred = munge::encode("Goodbye cruel world...", None).expect("Failed to encode");

        let res = munge::decode(cred, None).expect("Failed to decode");
        println!("Result: {:?}", res);
    }
}
