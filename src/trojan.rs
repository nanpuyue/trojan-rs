use sha2::{Digest, Sha224};

use crate::util::ToHex;

pub struct TrojanRequest<'a> {
    pub password: &'a str,
    pub command: u8,
    pub addr: &'a [u8],
}

impl TrojanRequest<'_> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut sha224 = Sha224::new();
        let mut buf = Vec::new();

        sha224.update(self.password);
        buf.append(&mut sha224.finalize().to_hex().into());
        buf.extend_from_slice("\r\n".as_ref());
        buf.push(self.command);
        buf.extend_from_slice(self.addr);
        buf.extend_from_slice("\r\n".as_ref());

        buf
    }
}
