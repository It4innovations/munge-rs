/// Credential containing user and group information.
///
/// The `Credential` struct encapsulates the user ID, group ID, and the associated
/// message retrieved during the encoding or decoding process.
#[derive(Debug)]
pub struct Credential {
    /// User ID (UID) associated with the credential.
    pub uid: u32,
    /// Group ID (GID) associated with the credential.
    pub gid: u32,
    /// Message string contained within the credential.
    pub message: String,
}
