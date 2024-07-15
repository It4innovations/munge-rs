use std::path::PathBuf;

use crate::enums::{self, MungeError, MungeMac, MungeOption, MungeZip};

pub struct Context {
    ctx: *mut crate::munge_ctx,

    pub socket: PathBuf,
}

impl Context {
    pub fn new() -> Self {
        Context {
            ctx: unsafe { crate::munge_ctx_create() },
            socket: PathBuf::new(),
        }
    }

    /// Sets the path to the daemons socket of this [`Context`].
    pub fn set_socket(&mut self, path: PathBuf) -> Result<(), MungeError> {
        self.socket = path;
        let mut _err = 42;
        _err = unsafe { crate::munge_ctx_set(self.ctx, MungeOption::SOCKET as i32, &self.socket) };
        if MungeError::from_u32(_err) != MungeError::Success {
            Err(MungeError::from_u32(_err))
        } else {
            Ok(())
        }
    }

    /// Sets the message auth code type of this [`Context`]
    pub fn set_mac_type(&self, macType: MungeMac) -> Result<(), MungeError> {
        let mut _err = 42;
        _err = unsafe { crate::munge_ctx_set(self.ctx, MungeOption::MAC_TYPE as i32, macType) };
        if MungeError::from_u32(_err) != MungeError::Success {
            Err(MungeError::from_u32(_err))
        } else {
            Ok(())
        }
    }

    /// Sets the compression type of this [`Context`]
    pub fn set_zip_type(&self, zipType: MungeZip) {
        todo!()
    }

    //TODO: Other setters
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { crate::munge_ctx_destroy(self.ctx) };
    }
}

#[cfg(test)]
mod contextTests {
    use crate::{ctx::Context, enums::MungeMac};
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
    fn set_mac_type() {
        let ctx = Context::new();
        assert!(ctx.set_mac_type(MungeMac::MD5).is_ok());
        assert!(ctx.set_mac_type(MungeMac::None).is_ok());
        assert!(ctx.set_mac_type(MungeMac::SHA1).is_ok());
        assert!(ctx.set_mac_type(MungeMac::SHA256).is_ok());
        assert!(ctx.set_mac_type(MungeMac::SHA512).is_ok());
        assert!(ctx.set_mac_type(MungeMac::RIPEMD160).is_ok());
        assert!(ctx.set_mac_type(MungeMac::Default).is_ok());
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
    //         get_err = MungeError::from_u32(crate::munge_ctx_get(
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
