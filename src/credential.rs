pub struct Credential {
    uid: u32,
    gid: u32,
    payload: Option<Vec<u8>>,
}

impl Credential {
    #[inline]
    pub fn uid(self) -> u32 {
        self.uid
    }
    #[inline]
    pub fn gid(self) -> u32 {
        self.gid
    }
    #[inline]
    pub fn payload(self) -> Option<Vec<u8>> {
        self.payload
    }
}
