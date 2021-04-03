use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum RfidDataParseError {
    ByteParseError(std::io::Error),
}

impl From<std::io::Error> for RfidDataParseError {
    fn from(e: std::io::Error) -> Self {
        Self::ByteParseError(e)
    }
}

impl Error for RfidDataParseError {}

impl Display for RfidDataParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RfidDataParseError::ByteParseError(e) => write!(f, "Failed to parse struct: {}", e),
        }
    }
}
