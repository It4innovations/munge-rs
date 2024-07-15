pub enum MungeOption {
    CIPHER_TYPE,
    MAC_TYPE,
    ZIP_TYPE,
    REALM,
    TTL,
    ADDR4,
    ENCODE_TIME,
    DECODE_TIME,
    SOCKET,
    UID_RESTRICTION,
    GID_RESTRICTION,
}

impl MungeOption {
    pub fn to_u32(self) -> u32 {
        match self {
            MungeOption::CIPHER_TYPE => crate::munge_opt_MUNGE_OPT_CIPHER_TYPE,
            MungeOption::MAC_TYPE => crate::munge_opt_MUNGE_OPT_MAC_TYPE,
            MungeOption::ZIP_TYPE => crate::munge_opt_MUNGE_OPT_ZIP_TYPE,
            MungeOption::REALM => crate::munge_opt_MUNGE_OPT_REALM,
            MungeOption::TTL => crate::munge_opt_MUNGE_OPT_TTL,
            MungeOption::ADDR4 => crate::munge_opt_MUNGE_OPT_ADDR4,
            MungeOption::ENCODE_TIME => crate::munge_opt_MUNGE_OPT_ENCODE_TIME,
            MungeOption::DECODE_TIME => crate::munge_opt_MUNGE_OPT_DECODE_TIME,
            MungeOption::SOCKET => crate::munge_opt_MUNGE_OPT_SOCKET,
            MungeOption::UID_RESTRICTION => crate::munge_opt_MUNGE_OPT_UID_RESTRICTION,
            MungeOption::GID_RESTRICTION => crate::munge_opt_MUNGE_OPT_GID_RESTRICTION,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MungeError {
    Snafu,
    BadArg,
    BadLength,
    Overflow,
    NoMemory,
    Socket,
    Timeout,
    BadCred,
    BadVersion,
    BadCipher,
    BadMac,
    BadZip,
    BadRealm,
    CredInvalid,
    CredExpired,
    CredRewound,
    CredReplayed,
    CredUnauthorized,
    Success,
}

impl MungeError {
    pub fn to_u32(self) -> u32 {
        match self {
            MungeError::Snafu => crate::munge_err_EMUNGE_SNAFU,
            MungeError::BadArg => crate::munge_err_EMUNGE_BAD_ARG,
            MungeError::BadLength => crate::munge_err_EMUNGE_BAD_LENGTH,
            MungeError::Overflow => crate::munge_err_EMUNGE_OVERFLOW,
            MungeError::NoMemory => crate::munge_err_EMUNGE_NO_MEMORY,
            MungeError::Socket => crate::munge_err_EMUNGE_SOCKET,
            MungeError::Timeout => crate::munge_err_EMUNGE_TIMEOUT,
            MungeError::BadCred => crate::munge_err_EMUNGE_BAD_CRED,
            MungeError::BadVersion => crate::munge_err_EMUNGE_BAD_VERSION,
            MungeError::BadCipher => crate::munge_err_EMUNGE_BAD_CIPHER,
            MungeError::BadMac => crate::munge_err_EMUNGE_BAD_MAC,
            MungeError::BadZip => crate::munge_err_EMUNGE_BAD_ZIP,
            MungeError::BadRealm => crate::munge_err_EMUNGE_BAD_REALM,
            MungeError::CredInvalid => crate::munge_err_EMUNGE_CRED_INVALID,
            MungeError::CredExpired => crate::munge_err_EMUNGE_CRED_EXPIRED,
            MungeError::CredRewound => crate::munge_err_EMUNGE_CRED_REWOUND,
            MungeError::CredReplayed => crate::munge_err_EMUNGE_CRED_REPLAYED,
            MungeError::CredUnauthorized => crate::munge_err_EMUNGE_CRED_UNAUTHORIZED,
            MungeError::Success => crate::munge_err_EMUNGE_SUCCESS,
        }
    }

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
            crate::munge_err_EMUNGE_SUCCESS => MungeError::Success,

            _ => MungeError::BadArg,
        }
    }
}
