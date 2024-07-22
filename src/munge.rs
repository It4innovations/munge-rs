use std::{
    ffi::{self, CStr, CString},
    ptr,
    str::Utf8Error,
};

use crate::{
    credential::Credential,
    ctx::Context,
    enums::{self, MungeError},
    ffi as c,
};

/// Encodes the given message and returns a base64 encoded credential string.
///
/// # Arguments
///
/// * `msg` - The message to be included with the encoded credential.
/// * `ctx` - An optional reference to a `Context`. If no context is provided, defaults will be used.
///
/// # Errors
///
/// Returns an `enums::Error` if:
/// - The message cannot be converted to a C string (contains an internal null byte).
/// - The encoding process fails.
///
/// # Example
///
/// ```ignore
/// let msg = "Hello, MUNGE!";
/// let encoded = encode(msg, None);
/// match encoded {
///     Ok(cred) => println!("Encoded credential: {}", cred),
///     Err(e) => eprintln!("Failed to encode message: {:?}", e),
/// }
/// ```
pub fn encode(msg: &str, ctx: Option<&Context>) -> Result<String, enums::Error> {
    let mut cred: *mut ffi::c_char = ptr::null_mut();
    let len: ffi::c_int = msg.len() as i32;
    let buf: *const ffi::c_void = CString::new(msg)?.into_raw() as *const ffi::c_void;

    let err: u32 = if let Some(ctx) = ctx {
        unsafe { c::munge_encode(&mut cred, ctx.ctx, buf, len) }
    } else {
        unsafe { c::munge_encode(&mut cred, ptr::null_mut(), buf, len) }
    };

    if err != 0 {
        Err(enums::Error::MungeError(
            MungeError::from_u32(err),
            match str_error(err)? {
                Some(s) => s,
                None => "No error description available.".to_string(),
            },
        ))
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
/// * `encoded_msg` - The base64 encoded credential string to decode.
/// * `ctx` - An optional reference to a [`Context`]. If no context is provided, defaults will be used.
///
/// # Errors
///
/// This will return an error thrown by munge or when the provided `encoded_msg` is invalid ie.
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
        Err(enums::Error::MungeError(
            MungeError::from_u32(err),
            match str_error(err)? {
                Some(s) => s,
                None => "No error description available.".to_string(),
            },
        ))
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

pub fn str_error(e: u32) -> Result<Option<String>, Utf8Error> {
    let err: *const libc::c_char = unsafe { crate::ffi::munge_strerror(e) };

    if err.is_null() {
        return Ok(None); // No error condition
    }

    // The conversion from CStr to &str and from &str to String
    let out_err = Some(unsafe { CStr::from_ptr(err) }.to_str()?);

    // Return the error message if parsing was successful, otherwise None
    Ok(out_err.map(|s| s.to_string()))
}

#[cfg(test)]
mod munge_tests {
    use crate::{
        ctx::Context,
        enums::{MungeMac, MungeOption},
        munge::{self, str_error},
    };

    #[test]
    fn str_error_test() {
        let err = str_error(13).unwrap().unwrap();
        println!("Bad Realm Error: {err}");
    }

    #[test]
    fn encode_test() {
        let cred = munge::encode("Hello World! 'aaaa'", None).expect("Failed to encode");
        println!("{:?}", cred);
    }
    #[test]
    fn encode_test_w_ctx() {
        let mut ctx = Context::new();
        let socket = ctx.socket().expect("Failed to get socket.");
        ctx.set_socket(socket).expect("Failed to set socket.");
        ctx.set_ctx_opt(MungeOption::MacType, MungeMac::RIPEMD160 as u32)
            .expect("Failed to set MAC type");
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
