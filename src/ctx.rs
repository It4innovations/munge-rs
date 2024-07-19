use std::{
    ffi::{self, CStr, CString},
    path::PathBuf,
    ptr,
};

use crate::{
    enums::{Error, MungeError, MungeOption},
    MungeCipher, MungeMac, MungeZip,
};

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
    /// * `path` - The [`PathBuf`] specifying the socket path to set.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if:
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
    pub fn set_socket(&mut self, path: PathBuf) -> Result<&mut Self, Error> {
        let socket = path;

        let c_path = CString::new(socket.to_str().ok_or(Error::NonUtf8SocketPath)?)?;

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
    /// * `option` - The [`MungeOption`] to set.
    /// * `value` - The value to set for the specified option.
    ///
    /// # Errors
    ///
    /// Returns a [`MungeError`] if the function call to `munge_ctx_set` fails.
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
    pub(crate) fn set_ctx_opt(
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

    // TODO: Documentation
    // uid_restriction, gid_restriction

    /// Sets the time-to-live (TTL) for the context.
    ///
    /// # Arguments
    ///
    /// * `ttl` - The TTL value to set.
    ///
    /// # Errors
    ///
    /// Returns a [`MungeError`] if the function call to `munge_ctx_set` fails.
    ///
    /// # Returns
    ///
    /// On success, returns a mutable reference to `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.set_ttl(60) {
    ///     Ok(ctx) => println!("TTL set successfully"),
    ///     Err(e) => eprintln!("Failed to set TTL: {:?}", e),
    /// }
    /// ```
    pub fn set_ttl(&mut self, ttl: u32) -> Result<&mut Self, MungeError> {
        self.set_ctx_opt(MungeOption::Ttl, ttl)
    }

    /// Sets the message authentication code (MAC) type for the context.
    ///
    /// # Arguments
    ///
    /// * `mac` - The [`MungeMac`] type to set.
    ///
    /// # Errors
    ///
    /// Returns a [`MungeError`] if the function call to `munge_ctx_set` fails.
    ///
    /// # Returns
    ///
    /// On success, returns a mutable reference to `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.set_mac(MungeMac::SHA256) {
    ///     Ok(ctx) => println!("MAC type set successfully"),
    ///     Err(e) => eprintln!("Failed to set MAC type: {:?}", e),
    /// }
    /// ```
    pub fn set_mac(&mut self, mac: MungeMac) -> Result<&mut Self, MungeError> {
        self.set_ctx_opt(MungeOption::MacType, mac as u32)
    }

    /// Sets the compression type for the context.
    ///
    /// # Arguments
    ///
    /// * `zip_type` - The [`MungeZip`] type to set.
    ///
    /// # Errors
    ///
    /// Returns a [`MungeError`] if the function call to `munge_ctx_set` fails.
    ///
    /// # Returns
    ///
    /// On success, returns a mutable reference to `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.set_zip(MungeZip::Zlib) {
    ///     Ok(ctx) => println!("Compression type set successfully"),
    ///     Err(e) => eprintln!("Failed to set compression type: {:?}", e),
    /// }
    /// ```
    pub fn set_zip(&mut self, zip_type: MungeZip) -> Result<&mut Self, MungeError> {
        self.set_ctx_opt(MungeOption::ZipType, zip_type as u32)
    }

    /// Sets the cipher type for the context.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The [`MungeCipher`] type to set.
    ///
    /// # Errors
    ///
    /// Returns a [`MungeError`] if the function call to `munge_ctx_set` fails.
    ///
    /// # Returns
    ///
    /// On success, returns a mutable reference to `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.set_cipher(MungeCipher::Aes256) {
    ///     Ok(ctx) => println!("Cipher type set successfully"),
    ///     Err(e) => eprintln!("Failed to set cipher type: {:?}", e),
    /// }
    /// ```
    pub fn set_cipher(&mut self, cipher: MungeCipher) -> Result<&mut Self, MungeError> {
        self.set_ctx_opt(MungeOption::CipherType, cipher as u32)
    }

    // pub fn set_realm(&mut self, realm: String) -> Result<&mut Self, Error> {
    //     let _realm = realm;

    //     let c_str = CString::new(_realm.to_string())?;

    //     let _err = unsafe {
    //         crate::ffi::munge_ctx_set(self.ctx, MungeOption::Realm as i32, c_str.as_ptr())
    //     };
    //     if _err != 0 {
    //         Err(MungeError::from_u32(_err).into())
    //     } else {
    //         Ok(self)
    //     }
    // }

    /// Retrieves the socket path from the context and returns it as a [`PathBuf`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the function call to `munge_ctx_get` fails or
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
    pub fn socket(&mut self) -> Result<PathBuf, Error> {
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
    /// * `option` - The [`MungeOption`] to retrieve from the context.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the function call to `munge_ctx_get` fails.
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
    pub(crate) fn get_ctx_opt(&self, option: MungeOption) -> Result<i32, Error> {
        let mut value: i32 = 42;

        let _err = unsafe { crate::ffi::munge_ctx_get(self.ctx, option as i32, &mut value) };

        if _err != 0 {
            Err(MungeError::from_u32(_err).into())
        } else {
            Ok(value)
        }
    }

    // TODO: Rest of the getters
    // realm, addr4, encode_time, decode_time, uid_restriction,
    // gid_restriction

    /// Retrieves the time-to-live (TTL) value for the context.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the function call to `munge_ctx_get` fails.
    ///
    /// # Returns
    ///
    /// On success, returns the TTL value as an [`i32`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.ttl() {
    ///     Ok(ttl) => println!("TTL: {}", ttl),
    ///     Err(e) => eprintln!("Failed to get TTL: {:?}", e),
    /// }
    /// ```
    pub fn ttl(&self) -> Result<i32, Error> {
        self.get_ctx_opt(MungeOption::Ttl)
    }

    /// Retrieves the message authentication code (MAC) type for the context.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the function call to `munge_ctx_get` fails or the MAC type is invalid.
    ///
    /// # Returns
    ///
    /// On success, returns the MAC type as a [`MungeMac`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.mac() {
    ///     Ok(mac) => println!("MAC type: {:?}", mac),
    ///     Err(e) => eprintln!("Failed to get MAC type: {:?}", e),
    /// }
    /// ```
    pub fn mac(&self) -> Result<MungeMac, Error> {
        match self.get_ctx_opt(MungeOption::MacType) {
            Ok(mac) => Ok(MungeMac::try_from(mac as u32)?),
            Err(e) => Err(e),
        }
    }

    /// Retrieves the compression type for the context.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the function call to `munge_ctx_get` fails or the compression type is invalid.
    ///
    /// # Returns
    ///
    /// On success, returns the compression type as a [`MungeZip`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.zip() {
    ///     Ok(zip) => println!("Compression type: {:?}", zip),
    ///     Err(e) => eprintln!("Failed to get compression type: {:?}", e),
    /// }
    /// ```
    pub fn zip(&self) -> Result<MungeZip, Error> {
        match self.get_ctx_opt(MungeOption::ZipType) {
            Ok(zip) => Ok(MungeZip::try_from(zip as u32)?),
            Err(e) => Err(e),
        }
    }

    /// Retrieves the cipher type for the context.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the function call to `munge_ctx_get` fails or the cipher type is invalid.
    ///
    /// # Returns
    ///
    /// On success, returns the cipher type as a [`MungeCipher`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.cipher() {
    ///     Ok(cipher) => println!("Cipher type: {:?}", cipher),
    ///     Err(e) => eprintln!("Failed to get cipher type: {:?}", e),
    /// }
    /// ```
    pub fn cipher(&self) -> Result<MungeCipher, Error> {
        match self.get_ctx_opt(MungeOption::ZipType) {
            Ok(cipher) => Ok(MungeCipher::try_from(cipher as u32)?),
            Err(e) => Err(e),
        }
    }

    // pub fn realm(&self) -> Result<String, Error> {
    //     let mut c_str: *const ffi::c_char = ptr::null();
    //
    //     let _err =
    //         unsafe { crate::ffi::munge_ctx_get(self.ctx, MungeOption::Realm as i32, &mut c_str) };
    //     if c_str.is_null() {
    //         return Err(Error::NonUtf8SocketPath);
    //     }
    //     let realm = unsafe { CStr::from_ptr(c_str) }.to_str()?.to_owned();
    //
    //     if _err != 0 {
    //         Err(MungeError::from_u32(_err).into())
    //     } else {
    //         Ok(realm)
    //     }
    // }
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
        let res = ctx.socket().unwrap();
        let i = ctx.get_ctx_opt(MungeOption::Ttl).unwrap();
        println!("Result: {:?}", res);
        println!("TTL: {}", i);
        println!();
    }

    // #[test]
    // fn relm_getter_test() {
    //     let mut ctx = Context::new();
    //     let realm = ctx.realm().expect("Failed to get realm");
    //     println!("\nRealm: \t{}\n", realm);
    // }

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
