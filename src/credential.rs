#[derive(Debug)]
pub struct Credential {
    pub uid: u32,
    pub gid: u32,
    pub message: String,
}

impl Credential {
    pub fn uid(self) -> u32 {
        self.uid
    }
    pub fn gid(self) -> u32 {
        self.gid
    }
    pub fn message(self) -> String {
        self.message
    }
}
