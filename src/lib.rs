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
pub fn encode(payload: Option<&'_ [u8]>) -> Result<String, error::Error> {
    todo!()
}

// TODO: Implement encode decode test
#[cfg(test)]
mod tests {
    use libc::c_char;

    use super::*;
    use std::{env, ptr};

    #[test]
    fn roundtrip_encode_decode() {
        let cred: *mut *mut c_char = ptr::null_mut();
        let mut ctx = ctx::MungeCtx::default();
        ctx.set_socket("/usr/local/var/run/munge/munge.socket.2".into());

        let result = unsafe {
            munge_encode(
                cred,
                ctx.ctx() as *const _ as *mut crate::munge_ctx,
                ptr::null(),
                0,
            )
        };

        println!("Encode: {:?}, Return: {:?}", cred, result);
        println!("bindings.rs: {}", env!("OUT_DIR"));
    }
}
