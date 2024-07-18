use std::{
    ffi::{self, CStr, CString},
    path::PathBuf,
    ptr,
};

use crate::enums::{self, MungeError, MungeOption};

pub struct Context {
    pub(crate) ctx: *mut crate::ffi::munge_ctx,
}

impl Context {
    pub fn new() -> Self {
        Context {
            ctx: unsafe { crate::ffi::munge_ctx_create() },
        }
    }

    /// Sets the path to the daemons socket of this [`Context`].
    pub fn set_socket(&mut self, path: PathBuf) -> Result<&mut Self, enums::Error> {
        let socket = path;

        let c_path = CString::new(socket.to_str().ok_or(enums::Error::InvalidUtf8)?)?;

        let _err = unsafe {
            crate::ffi::munge_ctx_set(self.ctx, MungeOption::SOCKET as i32, c_path.as_ptr())
        };
        if _err != 0 {
            Err(MungeError::from_u32(_err).into())
        } else {
            Ok(self)
        }
    }

    /// Sets an option that takes a number as a value in `munge_ctx`
    pub fn set_ctx_opt(
        &mut self,
        option: MungeOption,
        value: u32,
    ) -> Result<&mut Self, MungeError> {
        let _err = unsafe { crate::ffi::munge_ctx_set(self.ctx, option as i32, value) };
        if _err != 0 {
            Err(MungeError::from_u32(_err))
        } else {
            Ok(self)
        }
    }

    /// Returns the get socket of this [`Context`].
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    // TODO: Getters
    pub fn get_socket(&mut self) -> Result<PathBuf, enums::Error> {
        let mut c_path: *const ffi::c_char = ptr::null();

        let _err =
            unsafe { crate::ffi::munge_ctx_get(self.ctx, MungeOption::SOCKET as i32, &mut c_path) };
        let socket = unsafe { CStr::from_ptr(c_path) }.to_str()?.to_owned();

        if _err != 0 {
            Err(MungeError::from_u32(_err).into())
        } else {
            Ok(PathBuf::from(socket))
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn get_ctx_opt(&self, option: MungeOption) -> Result<i32, enums::Error> {
        let mut value: i32 = 42;

        let _err = unsafe { crate::ffi::munge_ctx_get(self.ctx, option as i32, &mut value) };

        if _err != 0 {
            Err(MungeError::from_u32(_err).into())
        } else {
            Ok(value)
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { crate::ffi::munge_ctx_destroy(self.ctx) };
    }
}

#[cfg(test)]
mod contextTests {
    use crate::{
        ctx::Context,
        enums::{MungeCipher, MungeMac, MungeOption, MungeZip},
    };

    #[test]
    fn getter_test() {
        let mut ctx = Context::new();
        let res = ctx.get_socket().unwrap();
        let i = ctx.get_ctx_opt(MungeOption::TTL).unwrap();
        println!("Result: {:?}", res);
        println!("TTL: {}", i);
        println!();
    }

    #[test]
    fn set_ctx_opt() {
        let mut ctx = Context::new();
        assert!(ctx
            .set_ctx_opt(MungeOption::ZIP_TYPE, MungeZip::Bzlib as u32)
            .is_ok());
        assert!(ctx
            .set_ctx_opt(MungeOption::MAC_TYPE, MungeMac::SHA256 as u32)
            .is_ok());
        assert!(ctx
            .set_ctx_opt(MungeOption::CIPHER_TYPE, MungeCipher::Aes256 as u32)
            .is_ok());
        assert!(ctx.set_ctx_opt(MungeOption::TTL, 180).is_ok());
    }
}
