#![allow(clippy::new_without_default)]

use std::{
    ffi::{self, CStr, CString},
    net::Ipv4Addr,
    path::PathBuf,
    ptr,
    str::Utf8Error,
};

use chrono::{DateTime, Utc};

use crate::{
    enums::{Error, MungeError, MungeOption},
    MungeCipher, MungeMac, MungeZip,
};

/// Context used for managing options and settings.
pub struct Context {
    pub(crate) ctx: *mut crate::ffi::munge_ctx,
}

impl Context {
    /// Create a new [`Context`]
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
            Err(Error::MungeError(
                MungeError::from_u32(_err),
                match self.str_error()? {
                    Some(s) => s,
                    None => "No error description available.".to_string(),
                },
            ))
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

    /// Sets the user ID (UID) restriction for the current context.
    ///
    /// This function updates the context to restrict operations based on the specified
    /// user ID, allowing for security measures related to user permissions.
    ///
    /// # Arguments
    ///
    /// * `uid` - The [`libc::uid_t`] value representing the user ID restriction to set.
    ///
    /// # Returns
    ///
    /// Returns a `Result<&mut Self, MungeError>`, where:
    /// - `Ok(&mut Self)` allows for method chaining on success.
    /// - `Err(MungeError)` if the function call to the MUNGE library fails.
    ///
    /// # Errors
    ///
    /// Returns a [`MungeError`] if:
    /// - The function call to `munge_ctx_set` fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.set_uid_restriction(1001) {
    ///     Ok(ctx) => println!("UID restriction set successfully"),
    ///     Err(e) => eprintln!("Failed to set UID restriction: {:?}", e),
    /// }
    /// ```
    pub fn set_uid_restriction(&mut self, uid: libc::uid_t) -> Result<&mut Self, MungeError> {
        self.set_ctx_opt(MungeOption::UidRestriction, uid)
    }

    /// Sets the group ID (GID) restriction for the current context.
    ///
    /// This function updates the context to restrict operations based on the specified
    /// group ID, enabling security measures related to group permissions.
    ///
    /// # Arguments
    ///
    /// * `gid` - The [`libc::gid_t`] value representing the group ID restriction to set.
    ///
    /// # Returns
    ///
    /// Returns a `Result<&mut Self, MungeError>`, where:
    /// - `Ok(&mut Self)` allows for method chaining on success.
    /// - `Err(MungeError)` if the function call to the MUNGE library fails.
    ///
    /// # Errors
    ///
    /// Returns a [`MungeError`] if:
    /// - The function call to `munge_ctx_set` fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.set_gid_restriction(1001) {
    ///     Ok(ctx) => println!("GID restriction set successfully"),
    ///     Err(e) => eprintln!("Failed to set GID restriction: {:?}", e),
    /// }
    /// ```
    pub fn set_gid_restriction(&mut self, gid: libc::gid_t) -> Result<&mut Self, MungeError> {
        self.set_ctx_opt(MungeOption::GidRestriction, gid)
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

        self.error_check_i32(_err, value)
    }

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

    /// Retrieves the IPv4 address ([`Ipv4Addr`]) associated with the current context.
    ///
    /// This function calls the MUNGE library to obtain the IPv4 address
    ///
    /// # Returns
    ///
    /// Returns a [`Result<Ipv4Addr, Error>`], where:
    /// - `Ok(Ipv4Addr)` contains the IPv4 address on success.
    /// - `Err(Error)` if the function call to the MUNGE library fails.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if:
    /// - The function call to `munge_ctx_get` fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let decoded = munge::decode(encoded, Some(&ctx)).unwrap();
    /// let addr4 = ctx.addr4().unwrap();
    /// ```
    pub fn addr4(&self) -> Result<Ipv4Addr, Error> {
        let mut value: u32 = 42;

        let _err =
            unsafe { crate::ffi::munge_ctx_get(self.ctx, MungeOption::Addr4 as i32, &mut value) };

        if _err != 0 {
            Err(Error::MungeError(
                MungeError::from_u32(_err),
                match self.str_error()? {
                    Some(s) => s,
                    None => "No error description available.".to_string(),
                },
            ))
        } else {
            Ok(Ipv4Addr::from(value.to_be()))
        }
    }

    /// Retrieves the encode time for the current context and converts it to a `DateTime<Utc>`.
    ///
    /// # Returns
    ///
    /// Returns a `Result<DateTime<Utc>, Error>`, where:
    /// - `Ok(DateTime<Utc>)` contains the encode time on success.
    /// - `Err(Error)` if the function call to the MUNGE library fails or if the conversion
    ///   to a `DateTime<Utc>` is invalid.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if:
    /// - The function call to `munge_ctx_get` fails, defined by the MUNGE library.
    /// - The conversion from `time_t` to `DateTime<Utc>` fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.encode_time() {
    ///     Ok(date_time) => println!("Encode time: {:?}", date_time),
    ///     Err(e) => eprintln!("Failed to retrieve encode time: {:?}", e),
    /// }
    /// ```
    pub fn encode_time(&self) -> Result<DateTime<Utc>, Error> {
        let mut c_time: libc::time_t = 0i64;

        let _err = unsafe {
            crate::ffi::munge_ctx_get(self.ctx, MungeOption::EncodeTime as i32, &mut c_time)
        };

        let date_time: DateTime<Utc> =
            DateTime::from_timestamp(c_time, 0).ok_or(Error::InvalidTime)?;

        self.error_check_time(_err, date_time)
    }

    /// Retrieves the decode time for the current context and converts it to a `DateTime<Utc>`.
    ///
    /// # Returns
    ///
    /// Returns a `Result<DateTime<Utc>, Error>`, where:
    /// - `Ok(DateTime<Utc>)` contains the decode time on success.
    /// - `Err(Error)` if the function call to the MUNGE library fails or if the conversion
    ///   to a `DateTime<Utc>` is invalid.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if:
    /// - The function call to `munge_ctx_get` fails, as defined by the MUNGE library.
    /// - The conversion from `time_t` to `DateTime<Utc>` fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.decode_time() {
    ///     Ok(date_time) => println!("Decode time: {:?}", date_time),
    ///     Err(e) => eprintln!("Failed to retrieve decode time: {:?}", e),
    /// }
    /// ```
    pub fn decode_time(&self) -> Result<DateTime<Utc>, Error> {
        let mut c_time: libc::time_t = 0i64;

        let _err = unsafe {
            crate::ffi::munge_ctx_get(self.ctx, MungeOption::DecodeTime as i32, &mut c_time)
        };

        let date_time: DateTime<Utc> =
            DateTime::from_timestamp(c_time, 0).ok_or(Error::InvalidTime)?;

        self.error_check_time(_err, date_time)
    }

    /// Retrieves the user ID (UID) restriction for the current context.
    ///
    /// # Returns
    ///
    /// Returns a `Result<libc::uid_t, Error>`, where:
    /// - `Ok(uid_t)` contains the user ID restriction on success.
    /// - `Err(Error)` if the function call to the MUNGE library fails.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if:
    /// - The function call to `munge_ctx_get` fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.uid_restriction() {
    ///     Ok(uid) => println!("UID restriction: {}", uid),
    ///     Err(e) => eprintln!("Failed to retrieve UID restriction: {:?}", e),
    /// }
    /// ```
    pub fn uid_restriction(&self) -> Result<libc::uid_t, Error> {
        let mut c_uid: libc::uid_t = 0;

        let _err = unsafe {
            crate::ffi::munge_ctx_get(self.ctx, MungeOption::UidRestriction as i32, &mut c_uid)
        };

        self.error_check_u32(_err, c_uid)
    }

    /// Retrieves the group ID (GID) restriction for the current context.
    ///
    /// # Returns
    ///
    /// Returns a `Result<libc::gid_t, Error>`, where:
    /// - `Ok(gid_t)` contains the group ID restriction on success.
    /// - `Err(Error)` if the function call to the MUNGE library fails.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if:
    /// - The function call to `munge_ctx_get` fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Context::new(); // Hypothetical function to create a new context
    /// match ctx.gid_restriction() {
    ///     Ok(gid) => println!("GID restriction: {}", gid),
    ///     Err(e) => eprintln!("Failed to retrieve GID restriction: {:?}", e),
    /// }
    /// ```
    pub fn gid_restriction(&self) -> Result<libc::gid_t, Error> {
        let mut c_gid: libc::gid_t = 0;

        let _err = unsafe {
            crate::ffi::munge_ctx_get(self.ctx, MungeOption::GidRestriction as i32, &mut c_gid)
        };

        self.error_check_u32(_err, c_gid)
    }

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
    pub fn socket(&self) -> Result<PathBuf, Error> {
        let mut c_path: *const ffi::c_char = ptr::null();

        let _err =
            unsafe { crate::ffi::munge_ctx_get(self.ctx, MungeOption::Socket as i32, &mut c_path) };
        let socket = unsafe { CStr::from_ptr(c_path) }.to_str()?.to_owned();

        if _err != 0 {
            // Err(MungeError::from_u32(_err).into())
            Err(Error::MungeError(
                MungeError::from_u32(_err),
                "ctx_str_error()".to_string(),
            ))
        } else {
            Ok(PathBuf::from(socket))
        }
    }

    /// Retrieves a human-readable error message associated with the current context.
    ///
    /// This function calls the MUNGE library's `munge_ctx_strerror` function to obtain an
    /// error message for the current context. If there is no error present, it returns `None`.
    ///
    /// # Returns
    ///
    /// Returns a `Result<Option<String>, Utf8Error>`, where:
    /// - `Ok(Some(String))` contains the error message if it exists.
    /// - `Ok(None)` if there is no error message associated with the context.
    /// - `Err(Utf8Error)` if the conversion of the error message to a valid UTF-8 string fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// match ctx.str_error() {
    ///     Ok(Some(message)) => println!("Error message: {}", message),
    ///     Ok(None) => println!("No error message available."),
    ///     Err(e) => eprintln!("Failed to retrieve error message: {:?}", e),
    /// }
    /// ```
    fn str_error(&self) -> Result<Option<String>, Utf8Error> {
        let err: *const libc::c_char = unsafe { crate::ffi::munge_ctx_strerror(self.ctx) };

        if err.is_null() {
            return Ok(None); // No error condition
        }

        // The conversion from CStr to &str and from &str to String
        let out_err = Some(unsafe { CStr::from_ptr(err) }.to_str()?);

        // Return the error message if parsing was successful, otherwise None
        Ok(out_err.map(|s| s.to_string()))
    }

    /// Checks the result of a MUNGE operation that returns a `u32`.
    ///
    /// This function examines the provided error code from a MUNGE operation. If the error code
    /// is non-zero, it constructs an `Error` containing a detailed error message. If the operation
    /// was successful, it returns the specified return value.
    ///
    /// # Arguments
    ///
    /// * `_err` - The error code returned by the MUNGE operation.
    /// * `ret_val` - The return value to return on success.
    ///
    /// # Returns
    ///
    /// Returns a `Result<u32, Error>`, where:
    /// - `Ok(u32)` contains the return value if the operation was successful.
    /// - `Err(Error)` if the operation failed, including a descriptive error message.
    fn error_check_u32(&self, _err: u32, ret_val: u32) -> Result<u32, Error> {
        if _err != 0 {
            Err(Error::MungeError(
                MungeError::from_u32(_err),
                match self.str_error()? {
                    Some(s) => s,
                    None => "No error description available.".to_string(),
                },
            ))
        } else {
            Ok(ret_val)
        }
    }

    /// Checks the result of a MUNGE operation that returns an `i32`.
    ///
    /// This function examines the provided error code from a MUNGE operation. If the error code
    /// is non-zero, it constructs an `Error` containing a detailed error message. If the operation
    /// was successful, it returns the specified return value.
    ///
    /// # Arguments
    ///
    /// * `_err` - The error code returned by the MUNGE operation.
    /// * `ret_val` - The return value to return on success.
    ///
    /// # Returns
    ///
    /// Returns a `Result<i32, Error>`, where:
    /// - `Ok(i32)` contains the return value if the operation was successful.
    /// - `Err(Error)` if the operation failed, including a descriptive error message.
    fn error_check_i32(&self, _err: u32, ret_val: i32) -> Result<i32, Error> {
        if _err != 0 {
            Err(Error::MungeError(
                MungeError::from_u32(_err),
                match self.str_error()? {
                    Some(s) => s,
                    None => "No error description available.".to_string(),
                },
            ))
        } else {
            Ok(ret_val)
        }
    }

    /// Checks the result of a MUNGE operation that returns a `DateTime<Utc>`.
    ///
    /// This function examines the provided error code from a MUNGE operation. If the error code
    /// is non-zero, it constructs an `Error` containing a detailed error message. If the operation
    /// was successful, it returns the specified `DateTime<Utc>`.
    ///
    /// # Arguments
    ///
    /// * `_err` - The error code returned by the MUNGE operation.
    /// * `rust_time` - The `DateTime<Utc>` value to return on success.
    ///
    /// # Returns
    ///
    /// Returns a `Result<DateTime<Utc>, Error>`, where:
    /// - `Ok(DateTime<Utc>)` contains the return value if the operation was successful.
    /// - `Err(Error)` if the operation failed, including a descriptive error message.
    fn error_check_time(
        &self,
        _err: u32,
        rust_time: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, Error> {
        if _err != 0 {
            Err(Error::MungeError(
                MungeError::from_u32(_err),
                match self.str_error()? {
                    Some(s) => s,
                    None => "No error description available.".to_string(),
                },
            ))
        } else {
            Ok(rust_time)
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
    fn str_err_test() {
        let ctx = Context::new();
        let error = ctx.str_error().unwrap();
        if let Some(str) = error {
            println!("Error: {str}");
        } else {
            println!("No Error.");
        }
    }

    #[test]
    fn getter_test() {
        let ctx = Context::new();
        let res = ctx.socket().unwrap();
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
