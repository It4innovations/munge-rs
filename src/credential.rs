/// Credential containing user and group information.
///
/// The `Credential` struct encapsulates the user ID, group ID, and the associated 
/// message retrieved during the encoding or decoding process.
///
/// # Fields
///
/// * `uid` - The user ID (UID) associated with the credential.
/// * `gid` - The group ID (GID) associated with the credential.
/// * `message` - A message string that provides information about the credential.
#[derive(Debug)]
pub struct Credential {
    pub uid: u32,
    pub gid: u32,
    pub message: String,
}
