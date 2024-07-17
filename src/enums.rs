use std::{
    error::{self},
    ffi::NulError,
    fmt,
    str::Utf8Error,
};

use crate::ffi as c;

/// Represents MUNGE context options
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeError {
    Snafu = c::munge_err_EMUNGE_SNAFU,
    BadArg = c::munge_err_EMUNGE_BAD_ARG,
    BadLength = c::munge_err_EMUNGE_BAD_LENGTH,
    Overflow = c::munge_err_EMUNGE_OVERFLOW,
    NoMemory = c::munge_err_EMUNGE_NO_MEMORY,
    Socket = c::munge_err_EMUNGE_SOCKET,
    Timeout = c::munge_err_EMUNGE_TIMEOUT,
    BadCred = c::munge_err_EMUNGE_BAD_CRED,
    BadVersion = c::munge_err_EMUNGE_BAD_VERSION,
    BadCipher = c::munge_err_EMUNGE_BAD_CIPHER,
    BadMac = c::munge_err_EMUNGE_BAD_MAC,
    BadZip = c::munge_err_EMUNGE_BAD_ZIP,
    BadRealm = c::munge_err_EMUNGE_BAD_REALM,
    CredInvalid = c::munge_err_EMUNGE_CRED_INVALID,
    CredExpired = c::munge_err_EMUNGE_CRED_EXPIRED,
    CredRewound = c::munge_err_EMUNGE_CRED_REWOUND,
    CredReplayed = c::munge_err_EMUNGE_CRED_REPLAYED,
    CredUnauthorized = c::munge_err_EMUNGE_CRED_UNAUTHORIZED,
    // Success = c::munge_err_EMUNGE_SUCCESS,
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
            // c::munge_err_EMUNGE_SUCCESS => MungeError::Success,
            _ => MungeError::BadArg,
        }
    }
}

impl error::Error for MungeError {}

impl fmt::Display for MungeError {
    fn fmt(&'_ self, f: &'_ mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    MungeError(MungeError),
    InvalidUtf8,
    InnerNull,
}

impl error::Error for Error {
    fn source(&'_ self) -> Option<&'_ (dyn error::Error + 'static)> {
        match self {
            Error::MungeError(ref munge_error) => Some(munge_error as _),
            _ => None,
        }
    }
}

impl From<MungeError> for Error {
    fn from(munge_error: MungeError) -> Self {
        Error::MungeError(munge_error)
    }
}
impl From<Utf8Error> for Error {
    fn from(_value: Utf8Error) -> Self {
        Error::InvalidUtf8
    }
}
impl From<NulError> for Error {
    fn from(_value: NulError) -> Self {
        Error::InnerNull
    }
}

impl fmt::Display for Error {
    fn fmt(&'_ self, stream: &'_ mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::MungeError(ref munge_err) => write!(stream, "munge errored: {}", munge_err,),
            Error::InvalidUtf8 => write!(
                stream,
                "C string to Rust string lift failed: got non UTF8 output",
            ),
            Error::InnerNull => write!(
                stream,
                "Rust string to C string lift failed: input had inner null",
            ),
        }
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

    /// [`MungeCipher::LastItem`] ???
    LastItem,
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

    //???
    LastItem,
}

/// MUNGE compression types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeZip {
    None = c::munge_zip_MUNGE_ZIP_NONE,
    Default = c::munge_zip_MUNGE_ZIP_DEFAULT,
    Bzlib = c::munge_zip_MUNGE_ZIP_BZLIB,
    Zlib = c::munge_zip_MUNGE_ZIP_ZLIB,

    //???
    LastItem,
}
