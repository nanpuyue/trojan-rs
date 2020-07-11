pub trait ToHex {
    fn to_hex(&self) -> String;
}

const CHARS: &[u8] = b"0123456789abcdef";

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        let mut v = Vec::with_capacity(self.len() * 2);
        for &b in self {
            v.push(CHARS[(b >> 4) as usize]);
            v.push(CHARS[(b & 0xf) as usize]);
        }

        unsafe { String::from_utf8_unchecked(v) }
    }
}
