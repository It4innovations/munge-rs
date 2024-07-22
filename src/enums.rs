use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use std::{ffi::NulError, str::Utf8Error, string::FromUtf8Error};
use thiserror::Error;

use crate::ffi as c;

/// Context options.
///
/// This enum wraps various context options that can be used with MUNGE encoding and decoding operations.
///
/// Each variant represents a different option and maps to a corresponding constant in the MUNGE C library.
///
/// # Examples
///
/// ```ignore
/// let option = MungeOption::CIPHER_TYPE;
/// println!("Option: {:?}", option);
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeOption {
    CipherType = c::munge_opt_MUNGE_OPT_CIPHER_TYPE,
    MacType = c::munge_opt_MUNGE_OPT_MAC_TYPE,
    ZipType = c::munge_opt_MUNGE_OPT_ZIP_TYPE,
    Realm = c::munge_opt_MUNGE_OPT_REALM,
    Ttl = c::munge_opt_MUNGE_OPT_TTL,
    Addr4 = c::munge_opt_MUNGE_OPT_ADDR4,
    EncodeTime = c::munge_opt_MUNGE_OPT_ENCODE_TIME,
    DecodeTime = c::munge_opt_MUNGE_OPT_DECODE_TIME,
    Socket = c::munge_opt_MUNGE_OPT_SOCKET,
    UidRestriction = c::munge_opt_MUNGE_OPT_UID_RESTRICTION,
    GidRestriction = c::munge_opt_MUNGE_OPT_GID_RESTRICTION,
}

/// Possible error codes returned by the MUNGE library.
///
/// These error codes are mapped to their corresponding constants in the MUNGE C library.
#[repr(u32)]
#[derive(Debug, Error)]
pub enum MungeError {
    #[error("Snafu error")]
    Snafu = c::munge_err_EMUNGE_SNAFU,

    #[error("Bad argument")]
    BadArg = c::munge_err_EMUNGE_BAD_ARG,

    #[error("Bad length")]
    BadLength = c::munge_err_EMUNGE_BAD_LENGTH,

    #[error("Overflow error")]
    Overflow = c::munge_err_EMUNGE_OVERFLOW,

    #[error("No memory available")]
    NoMemory = c::munge_err_EMUNGE_NO_MEMORY,

    #[error("Socket error")]
    Socket = c::munge_err_EMUNGE_SOCKET,

    #[error("Operation timed out")]
    Timeout = c::munge_err_EMUNGE_TIMEOUT,

    #[error("Bad credential")]
    BadCred = c::munge_err_EMUNGE_BAD_CRED,

    #[error("Bad version")]
    BadVersion = c::munge_err_EMUNGE_BAD_VERSION,

    #[error("Bad cipher")]
    BadCipher = c::munge_err_EMUNGE_BAD_CIPHER,

    #[error("Bad MAC")]
    BadMac = c::munge_err_EMUNGE_BAD_MAC,

    #[error("Bad ZIP")]
    BadZip = c::munge_err_EMUNGE_BAD_ZIP,

    #[error("Bad realm")]
    BadRealm = c::munge_err_EMUNGE_BAD_REALM,

    #[error("Credential invalid")]
    CredInvalid = c::munge_err_EMUNGE_CRED_INVALID,

    #[error("Credential expired")]
    CredExpired = c::munge_err_EMUNGE_CRED_EXPIRED,

    #[error("Credential rewound")]
    CredRewound = c::munge_err_EMUNGE_CRED_REWOUND,

    #[error("Credential replayed")]
    CredReplayed = c::munge_err_EMUNGE_CRED_REPLAYED,

    #[error("Credential unauthorized")]
    CredUnauthorized = c::munge_err_EMUNGE_CRED_UNAUTHORIZED,
}

impl MungeError {
    /// Converts a raw error code (`u32`) from the MUNGE library into a `MungeError`.
    ///
    /// # Arguments
    ///
    /// * `err` - The raw error code to convert.
    ///
    /// # Returns
    ///
    /// A `MungeError` corresponding to the provided error code.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let error = MungeError::from_u32(1);
    /// println!("Error: {:?}", error);
    /// ```
    pub fn from_u32(err: u32) -> MungeError {
        match err {
            c::munge_err_EMUNGE_SNAFU => MungeError::Snafu,
            c::munge_err_EMUNGE_BAD_ARG => MungeError::BadArg,
            c::munge_err_EMUNGE_BAD_LENGTH => MungeError::BadLength,
            c::munge_err_EMUNGE_OVERFLOW => MungeError::Overflow,
            c::munge_err_EMUNGE_NO_MEMORY => MungeError::NoMemory,
            c::munge_err_EMUNGE_SOCKET => MungeError::Socket,
            c::munge_err_EMUNGE_TIMEOUT => MungeError::Timeout,
            c::munge_err_EMUNGE_BAD_CRED => MungeError::BadCred,
            c::munge_err_EMUNGE_BAD_VERSION => MungeError::BadVersion,
            c::munge_err_EMUNGE_BAD_CIPHER => MungeError::BadCipher,
            c::munge_err_EMUNGE_BAD_MAC => MungeError::BadMac,
            c::munge_err_EMUNGE_BAD_ZIP => MungeError::BadZip,
            c::munge_err_EMUNGE_BAD_REALM => MungeError::BadRealm,
            c::munge_err_EMUNGE_CRED_INVALID => MungeError::CredInvalid,
            c::munge_err_EMUNGE_CRED_EXPIRED => MungeError::CredExpired,
            c::munge_err_EMUNGE_CRED_REWOUND => MungeError::CredRewound,
            c::munge_err_EMUNGE_CRED_REPLAYED => MungeError::CredReplayed,
            c::munge_err_EMUNGE_CRED_UNAUTHORIZED => MungeError::CredUnauthorized,
            _ => MungeError::BadArg,
        }
    }
}

/// Types of errors that can occur in the library.
#[derive(Debug, Error)]
pub enum Error {
    #[error("munge errored: {0}")]
    MungeError(#[from] MungeError),

    #[error("C string to Rust string lift failed: got non-UTF8 output: {0}")]
    InvalidUtf8(#[from] Utf8Error),

    #[error("Rust string to UTF-8 conversion failed: got invalid UTF-8 output")]
    InvalidFromUtf8(FromUtf8Error),

    #[error("Rust string to C string lift failed: input had inner null: {0}")]
    InnerNull(#[from] NulError),

    #[error("Unable to use a non UTF8 socket path")]
    NonUtf8SocketPath,

    #[error("Failed to convert from primitive to MungeCipher: {0}")]
    TryFromPrimitiveCipher(#[from] TryFromPrimitiveError<MungeCipher>),
    #[error("Failed to convert from primitive to MungeMac: {0}")]
    TryFromPrimitiveMac(#[from] TryFromPrimitiveError<MungeMac>),
    #[error("Failed to convert from primitive to MungeZip: {0}")]
    TryFromPrimitiveZip(#[from] TryFromPrimitiveError<MungeZip>),
}

impl From<FromUtf8Error> for Error {
    fn from(value: FromUtf8Error) -> Self {
        Error::InvalidFromUtf8(value)
    }
}

/// Symmetric cipher types.
///
/// Each variant maps to a corresponding constant in the MUNGE C library.
///
/// # Examples
///
/// ```ignore
/// let cipher = MungeCipher::AES128;
/// println!("Cipher: {:?}", cipher);
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
pub enum MungeCipher {
    None = c::munge_cipher_MUNGE_CIPHER_NONE,
    Default = c::munge_cipher_MUNGE_CIPHER_DEFAULT,
    Blowfish = c::munge_cipher_MUNGE_CIPHER_BLOWFISH,
    Cast5 = c::munge_cipher_MUNGE_CIPHER_CAST5,
    Aes128 = c::munge_cipher_MUNGE_CIPHER_AES128,
    Aes256 = c::munge_cipher_MUNGE_CIPHER_AES256,
}

/// Represents MUNGE message authentication code (MAC) types.
///
/// Each variant maps to a corresponding constant in the MUNGE C library.
///
/// # Examples
///
/// ```ignore
/// let mac = MungeMac::SHA256;
/// println!("MAC: {:?}", mac);
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
pub enum MungeMac {
    None = c::munge_mac_MUNGE_MAC_NONE,
    Default = c::munge_mac_MUNGE_MAC_DEFAULT,
    MD5 = c::munge_mac_MUNGE_MAC_MD5,
    SHA1 = c::munge_mac_MUNGE_MAC_SHA1,
    RIPEMD160 = c::munge_mac_MUNGE_MAC_RIPEMD160,
    SHA256 = c::munge_mac_MUNGE_MAC_SHA256,
    SHA512 = c::munge_mac_MUNGE_MAC_SHA512,
}

/// Represents MUNGE compression types.
///
/// Each variant maps to a corresponding constant in the MUNGE C library.
///
/// # Examples
///
/// ```ignore
/// let zip = MungeZip::BZLIB;
/// println!("ZIP: {:?}", zip);
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
pub enum MungeZip {
    None = c::munge_zip_MUNGE_ZIP_NONE,
    Default = c::munge_zip_MUNGE_ZIP_DEFAULT,
    Bzlib = c::munge_zip_MUNGE_ZIP_BZLIB,
    Zlib = c::munge_zip_MUNGE_ZIP_ZLIB,
}
