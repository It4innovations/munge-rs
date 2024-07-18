use std::{ffi::NulError, str::Utf8Error, string::FromUtf8Error};
use thiserror::Error;

use crate::ffi as c;

/// Represents MUNGE context options.
///
/// This enum wraps various context options that can be used with MUNGE encoding and decoding operations.
///
/// Each variant represents a different option and maps to a corresponding constant in the MUNGE C library.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeOption {
    CIPHER_TYPE = c::munge_opt_MUNGE_OPT_CIPHER_TYPE,
    MAC_TYPE = c::munge_opt_MUNGE_OPT_MAC_TYPE,
    ZIP_TYPE = c::munge_opt_MUNGE_OPT_ZIP_TYPE,
    REALM = c::munge_opt_MUNGE_OPT_REALM,
    TTL = c::munge_opt_MUNGE_OPT_TTL,
    ADDR4 = c::munge_opt_MUNGE_OPT_ADDR4,
    ENCODE_TIME = c::munge_opt_MUNGE_OPT_ENCODE_TIME,
    DECODE_TIME = c::munge_opt_MUNGE_OPT_DECODE_TIME,
    SOCKET = c::munge_opt_MUNGE_OPT_SOCKET,
    UID_RESTRICTION = c::munge_opt_MUNGE_OPT_UID_RESTRICTION,
    GID_RESTRICTION = c::munge_opt_MUNGE_OPT_GID_RESTRICTION,
}

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

#[derive(Debug, Error)]
pub enum Error {
    #[error("munge errored: {0}")]
    MungeError(#[from] MungeError),

    #[error("C string to Rust string lift failed: got non-UTF8 output")]
    InvalidUtf8,

    #[error("Rust string to C string lift failed: input had inner null")]
    InnerNull,
}

impl From<Utf8Error> for Error {
    fn from(_value: Utf8Error) -> Self {
        Error::InvalidUtf8
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_value: FromUtf8Error) -> Self {
        Error::InvalidUtf8
    }
}

impl From<NulError> for Error {
    fn from(_value: NulError) -> Self {
        Error::InnerNull
    }
}

/// MUNGE symmetric cipher types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeCipher {
    None = c::munge_cipher_MUNGE_CIPHER_NONE,
    Default = c::munge_cipher_MUNGE_CIPHER_DEFAULT,
    Blowfish = c::munge_cipher_MUNGE_CIPHER_BLOWFISH,
    Cast5 = c::munge_cipher_MUNGE_CIPHER_CAST5,
    Aes128 = c::munge_cipher_MUNGE_CIPHER_AES128,
    Aes256 = c::munge_cipher_MUNGE_CIPHER_AES256,
}

/// MUNGE message authentication code types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeMac {
    None = c::munge_mac_MUNGE_MAC_NONE,
    Default = c::munge_mac_MUNGE_MAC_DEFAULT,
    MD5 = c::munge_mac_MUNGE_MAC_MD5,
    SHA1 = c::munge_mac_MUNGE_MAC_SHA1,
    RIPEMD160 = c::munge_mac_MUNGE_MAC_RIPEMD160,
    SHA256 = c::munge_mac_MUNGE_MAC_SHA256,
    SHA512 = c::munge_mac_MUNGE_MAC_SHA512,
}

/// MUNGE compression types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeZip {
    None = c::munge_zip_MUNGE_ZIP_NONE,
    Default = c::munge_zip_MUNGE_ZIP_DEFAULT,
    Bzlib = c::munge_zip_MUNGE_ZIP_BZLIB,
    Zlib = c::munge_zip_MUNGE_ZIP_ZLIB,
}
