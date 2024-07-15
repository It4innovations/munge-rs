use std::path::PathBuf;

use crate::enums::{self, MungeError};

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

    pub fn set_socket(&mut self, path: PathBuf) -> MungeError {
        self.socket = path;
        let mut err = 42;
        err = unsafe {
            crate::munge_ctx_set(self.ctx, enums::MungeOption::SOCKET as i32, &self.socket)
        };
        MungeError::from_u32(err)
    }

    // pub fn set_
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { crate::munge_ctx_destroy(self.ctx) };
    }
}

#[cfg(test)]
mod contextTests {
    use crate::{ctx::Context, enums::MungeError};
    use std::path::PathBuf;

    #[test]
    fn create_munge_context() {
        let mut ctx = Context::new();
        let err = ctx.set_socket(PathBuf::from("/usr/local/var/run/munge/munge.socket.2"));
        assert_eq!(err, MungeError::Success);
        assert!(!ctx.ctx.is_null())
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
