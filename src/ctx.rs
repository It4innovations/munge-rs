use std::{ffi::CString, path::PathBuf};

use crate::enums::{self, MungeError, MungeOption};

pub struct Context {
    pub(crate) ctx: *mut crate::ffi::munge_ctx,

    pub socket: PathBuf,
}

impl Context {
    pub fn new() -> Self {
        Context {
            ctx: unsafe { crate::ffi::munge_ctx_create() },
            socket: PathBuf::new(),
        }
    }

    /// Sets the path to the daemons socket of this [`Context`].
    /// TODO: Return Self or Error ie. builder pattern
    pub fn set_socket(&mut self, path: PathBuf) -> Result<(), enums::Error> {
        self.socket = path;
        let mut _err = 42;

        let c_path = CString::new(self.socket.to_str().ok_or(enums::Error::InvalidUtf8)?)?;

        _err = unsafe { crate::ffi::munge_ctx_set(self.ctx, MungeOption::SOCKET as i32, c_path) };
        if _err != 0 {
            Err(MungeError::from_u32(_err).into())
        } else {
            Ok(())
        }
    }

    /// Sets an option that takes a number as a value in `munge_ctx`
    pub fn set_ctx_opt(&self, option: MungeOption, value: u32) -> Result<(), MungeError> {
        let mut _err = 42;
        _err = unsafe { crate::ffi::munge_ctx_set(self.ctx, option as i32, value) };
        if _err != 0 {
            Err(MungeError::from_u32(_err))
        } else {
            Ok(())
        }
    }

    pub fn get_socket(&mut self) {
        todo!()
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
    use std::path::PathBuf;

    #[test]
    fn create_ctx_with_socket() {
        let mut ctx = Context::new();
        assert!(ctx
            .set_socket(PathBuf::from("/usr/local/var/run/munge/munge.socket.2"))
            .is_ok());
        assert!(!ctx.ctx.is_null())
    }

    #[test]
    fn set_ctx_opt() {
        let ctx = Context::new();
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

    // Do we need `munge_ctx_get()`?
    // #[test]
    // fn get_munge_ctx_opt() {
    //     let mut ctx = Context::new();
    //     let err = ctx.set_socket(PathBuf::from("/usr/local/var/run/munge/munge.socket.2"));
    //     assert_eq!(err, MungeError::Success);
    //
    //     let mut path: &str = "42";
    //
    //     let get_err: MungeError;
    //     unsafe {
    //         get_err = MungeError::from_u32(crate::ffi::munge_ctx_get(
    //             ctx.ctx,
    //             enums::MungeOption::SOCKET.to_u32() as i32,
    //             &mut path,
    //         ));
    //     }
    //
    //     assert_eq!(get_err, MungeError::Success);
    //     assert_eq!(path, "/usr/local/var/run/munge/munge.socket.2");
    // }
}
