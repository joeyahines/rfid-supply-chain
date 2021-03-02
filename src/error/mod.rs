use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum RFIDDataParseError {
    ByteParseError(std::io::Error),
}

impl From<std::io::Error> for RFIDDataParseError {
    fn from(e: std::io::Error) -> Self {
        Self::ByteParseError(e)
    }
}

impl Error for RFIDDataParseError {}

impl Display for RFIDDataParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RFIDDataParseError::ByteParseError(e) => write!(f, "Failed to parse struct: {}", e),
        }
    }
}
