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
