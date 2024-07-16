use std::fmt::Debug;

/// Represents MUNGE context options
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeOption {
    CIPHER_TYPE = crate::munge_opt_MUNGE_OPT_CIPHER_TYPE,
    MAC_TYPE = crate::munge_opt_MUNGE_OPT_MAC_TYPE,
    ZIP_TYPE = crate::munge_opt_MUNGE_OPT_ZIP_TYPE,
    REALM = crate::munge_opt_MUNGE_OPT_REALM,
    TTL = crate::munge_opt_MUNGE_OPT_TTL,
    ADDR4 = crate::munge_opt_MUNGE_OPT_ADDR4,
    ENCODE_TIME = crate::munge_opt_MUNGE_OPT_ENCODE_TIME,
    DECODE_TIME = crate::munge_opt_MUNGE_OPT_DECODE_TIME,
    SOCKET = crate::munge_opt_MUNGE_OPT_SOCKET,
    UID_RESTRICTION = crate::munge_opt_MUNGE_OPT_UID_RESTRICTION,
    GID_RESTRICTION = crate::munge_opt_MUNGE_OPT_GID_RESTRICTION,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeError {
    Snafu = crate::munge_err_EMUNGE_SNAFU,
    BadArg = crate::munge_err_EMUNGE_BAD_ARG,
    BadLength = crate::munge_err_EMUNGE_BAD_LENGTH,
    Overflow = crate::munge_err_EMUNGE_OVERFLOW,
    NoMemory = crate::munge_err_EMUNGE_NO_MEMORY,
    Socket = crate::munge_err_EMUNGE_SOCKET,
    Timeout = crate::munge_err_EMUNGE_TIMEOUT,
    BadCred = crate::munge_err_EMUNGE_BAD_CRED,
    BadVersion = crate::munge_err_EMUNGE_BAD_VERSION,
    BadCipher = crate::munge_err_EMUNGE_BAD_CIPHER,
    BadMac = crate::munge_err_EMUNGE_BAD_MAC,
    BadZip = crate::munge_err_EMUNGE_BAD_ZIP,
    BadRealm = crate::munge_err_EMUNGE_BAD_REALM,
    CredInvalid = crate::munge_err_EMUNGE_CRED_INVALID,
    CredExpired = crate::munge_err_EMUNGE_CRED_EXPIRED,
    CredRewound = crate::munge_err_EMUNGE_CRED_REWOUND,
    CredReplayed = crate::munge_err_EMUNGE_CRED_REPLAYED,
    CredUnauthorized = crate::munge_err_EMUNGE_CRED_UNAUTHORIZED,
    // Success = crate::munge_err_EMUNGE_SUCCESS,
}

impl MungeError {
    pub fn from_u32(err: u32) -> MungeError {
        match err {
            crate::munge_err_EMUNGE_SNAFU => MungeError::Snafu,
            crate::munge_err_EMUNGE_BAD_ARG => MungeError::BadArg,
            crate::munge_err_EMUNGE_BAD_LENGTH => MungeError::BadLength,
            crate::munge_err_EMUNGE_OVERFLOW => MungeError::Overflow,
            crate::munge_err_EMUNGE_NO_MEMORY => MungeError::NoMemory,
            crate::munge_err_EMUNGE_SOCKET => MungeError::Socket,
            crate::munge_err_EMUNGE_TIMEOUT => MungeError::Timeout,
            crate::munge_err_EMUNGE_BAD_CRED => MungeError::BadCred,
            crate::munge_err_EMUNGE_BAD_VERSION => MungeError::BadVersion,
            crate::munge_err_EMUNGE_BAD_CIPHER => MungeError::BadCipher,
            crate::munge_err_EMUNGE_BAD_MAC => MungeError::BadMac,
            crate::munge_err_EMUNGE_BAD_ZIP => MungeError::BadZip,
            crate::munge_err_EMUNGE_BAD_REALM => MungeError::BadRealm,
            crate::munge_err_EMUNGE_CRED_INVALID => MungeError::CredInvalid,
            crate::munge_err_EMUNGE_CRED_EXPIRED => MungeError::CredExpired,
            crate::munge_err_EMUNGE_CRED_REWOUND => MungeError::CredRewound,
            crate::munge_err_EMUNGE_CRED_REPLAYED => MungeError::CredReplayed,
            crate::munge_err_EMUNGE_CRED_UNAUTHORIZED => MungeError::CredUnauthorized,
            // crate::munge_err_EMUNGE_SUCCESS => MungeError::Success,
            _ => MungeError::BadArg,
        }
    }
}

/// MUNGE symmetric cipher types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeCipher {
    None = crate::munge_cipher_MUNGE_CIPHER_NONE,
    Default = crate::munge_cipher_MUNGE_CIPHER_DEFAULT,
    Blowfish = crate::munge_cipher_MUNGE_CIPHER_BLOWFISH,
    Cast5 = crate::munge_cipher_MUNGE_CIPHER_CAST5,
    Aes128 = crate::munge_cipher_MUNGE_CIPHER_AES128,
    Aes256 = crate::munge_cipher_MUNGE_CIPHER_AES256,

    /// [`MungeCipher::LastItem`] ???
    LastItem,
}

/// MUNGE message authentication code types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeMac {
    None = crate::munge_mac_MUNGE_MAC_NONE,
    Default = crate::munge_mac_MUNGE_MAC_DEFAULT,
    MD5 = crate::munge_mac_MUNGE_MAC_MD5,
    SHA1 = crate::munge_mac_MUNGE_MAC_SHA1,
    RIPEMD160 = crate::munge_mac_MUNGE_MAC_RIPEMD160,
    SHA256 = crate::munge_mac_MUNGE_MAC_SHA256,
    SHA512 = crate::munge_mac_MUNGE_MAC_SHA512,

    //???
    LastItem,
}

/// MUNGE compression types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeZip {
    None = crate::munge_zip_MUNGE_ZIP_NONE,
    Default = crate::munge_zip_MUNGE_ZIP_DEFAULT,
    Bzlib = crate::munge_zip_MUNGE_ZIP_BZLIB,
    Zlib = crate::munge_zip_MUNGE_ZIP_ZLIB,

    //???
    LastItem,
}
