use std::{
    ffi::{self, CStr, CString},
    path::PathBuf,
    ptr,
};

use crate::enums::{self, MungeError, MungeOption};

/// Represents a context used for managing options and settings.
///
/// This struct is used to configure and interact with various options.
///
/// # Examples
///
/// ```ignore
/// let mut ctx = Context::new(); // Hypothetical function to create a new context
/// // ...use ctx to set or get options
/// ```
pub struct Context {
    pub(crate) ctx: *mut crate::ffi::munge_ctx,
}

impl Context {
    pub fn new() -> Self {
        Context {
            ctx: unsafe { crate::ffi::munge_ctx_create() },
        }
    }

    /// Sets the socket path in the context to the given `PathBuf`.
    ///
    /// # Arguments
    ///
    /// * `path` - The `PathBuf` specifying the socket path to set.
    ///
    /// # Errors
    ///
    /// Returns an `enums::Error` if:
    /// - The path cannot be converted to a UTF-8 string.
    /// - The function call to `munge_ctx_set` fails.
    ///
    /// # Returns
    ///
    /// On success, returns a mutable reference to `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = /* initialize your context here */;
    /// match ctx.set_socket(PathBuf::from("/path/to/socket")) {
    ///     Ok(ctx) => println!("Socket path set successfully"),
    ///     Err(e) => eprintln!("Failed to set socket path: {:?}", e),
    /// }
    /// ```
    pub fn set_socket(&mut self, path: PathBuf) -> Result<&mut Self, enums::Error> {
        let socket = path;

        let c_path = CString::new(socket.to_str().ok_or(enums::Error::InvalidUtf8)?)?;

        let _err = unsafe {
            crate::ffi::munge_ctx_set(self.ctx, MungeOption::Socket as i32, c_path.as_ptr())
        };
        if _err != 0 {
            Err(MungeError::from_u32(_err).into())
        } else {
            Ok(self)
        }
    }

    /// Sets the specified context option to the given value.
    ///
    /// # Arguments
    ///
    /// * `option` - The `MungeOption` to set.
    /// * `value` - The value to set for the specified option.
    ///
    /// # Errors
    ///
    /// Returns a `MungeError` if the function call to `munge_ctx_set` fails.
    ///
    /// # Returns
    ///
    /// On success, returns a mutable reference to `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = /* initialize your context here */;
    /// match ctx.set_ctx_opt(MungeOption::SOME_OPTION, value) {
    ///     Ok(ctx) => println!("Option set successfully"),
    ///     Err(e) => eprintln!("Failed to set option value: {:?}", e),
    /// }
    /// ```
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

    /// Retrieves the socket path from the context and returns it as a `PathBuf`.
    ///
    /// # Errors
    ///
    /// Returns an `enums::Error` if the function call to `munge_ctx_get` fails or
    /// if the string conversion fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = /* initialize your context here */;
    /// match ctx.get_socket() {
    ///     Ok(path) => println!("Socket path: {:?}", path),
    ///     Err(e) => eprintln!("Failed to get socket path: {:?}", e),
    /// }
    /// ```
    pub fn get_socket(&mut self) -> Result<PathBuf, enums::Error> {
        let mut c_path: *const ffi::c_char = ptr::null();

        let _err =
            unsafe { crate::ffi::munge_ctx_get(self.ctx, MungeOption::Socket as i32, &mut c_path) };
        let socket = unsafe { CStr::from_ptr(c_path) }.to_str()?.to_owned();

        if _err != 0 {
            Err(MungeError::from_u32(_err).into())
        } else {
            Ok(PathBuf::from(socket))
        }
    }

    /// Retrieves the specified context option as an `i32`.
    ///
    /// # Arguments
    ///
    /// * `option` - The `MungeOption` to retrieve from the context.
    ///
    /// # Errors
    ///
    /// Returns an `enums::Error` if the function call to `munge_ctx_get` fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = /* initialize your context here */;
    /// match ctx.get_ctx_opt(MungeOption::SOME_OPTION) {
    ///     Ok(value) => println!("Option value: {}", value),
    ///     Err(e) => eprintln!("Failed to get option value: {:?}", e),
    /// }
    /// ```
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
mod context_tests {
    use crate::{
        ctx::Context,
        enums::{MungeCipher, MungeMac, MungeOption, MungeZip},
    };

    #[test]
    fn getter_test() {
        let mut ctx = Context::new();
        let res = ctx.get_socket().unwrap();
        let i = ctx.get_ctx_opt(MungeOption::Ttl).unwrap();
        println!("Result: {:?}", res);
        println!("TTL: {}", i);
        println!();
    }

    #[test]
    fn set_ctx_opt() {
        let mut ctx = Context::new();
        assert!(ctx
            .set_ctx_opt(MungeOption::ZipType, MungeZip::Bzlib as u32)
            .is_ok());
        assert!(ctx
            .set_ctx_opt(MungeOption::MacType, MungeMac::SHA256 as u32)
            .is_ok());
        assert!(ctx
            .set_ctx_opt(MungeOption::CipherType, MungeCipher::Aes256 as u32)
            .is_ok());
        assert!(ctx.set_ctx_opt(MungeOption::Ttl, 180).is_ok());
    }
}
