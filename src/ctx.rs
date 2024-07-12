use std::path::PathBuf;

use crate::mungeOption;

// TODO: Create functions to set context correctly
// ie. `MungeCtx.setSocket(path)`
pub struct MungeCtx {
    ctx: Box<crate::munge_ctx>,
    socket: PathBuf,
}

impl MungeCtx {
    pub fn new() -> Self {
        MungeCtx {
            ctx: unsafe { Box::from_raw(crate::munge_ctx_create()) },
            socket: PathBuf::new(),
        }
    }

    pub fn ctx(&self) -> &crate::munge_ctx {
        &self.ctx
    }

    pub fn socket(&self) -> &PathBuf {
        &self.socket
    }

    pub fn set_socket(&mut self, path: PathBuf) {
        self.socket = path;
        unsafe {
            crate::munge_ctx_set(
                self.ctx.as_mut() as *mut crate::munge_ctx,
                i32::try_from(mungeOption::MungeOption::SOCKET.to_u32()).unwrap(),
                self.socket.to_str().unwrap(),
            );
        }
    }
}

impl Default for MungeCtx {
    fn default() -> Self {
        Self::new()
    }
}
