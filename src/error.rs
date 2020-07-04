use std::io::{Error, ErrorKind};

pub fn io_error(desc: &str) -> Error {
    Error::new(ErrorKind::Other, desc)
}
