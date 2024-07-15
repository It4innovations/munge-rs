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
