use config::ConfigError;
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

#[derive(Debug)]
pub enum APIError {
    ReqwestError(reqwest::Error),
    WarpError(warp::Error),
    RFIDDataError(RFIDDataParseError),
    ConfigError(config::ConfigError),
}

impl From<reqwest::Error> for APIError {
    fn from(e: reqwest::Error) -> Self {
        Self::ReqwestError(e)
    }
}

impl From<warp::Error> for APIError {
    fn from(e: warp::Error) -> Self {
        Self::WarpError(e)
    }
}

impl From<RFIDDataParseError> for APIError {
    fn from(e: RFIDDataParseError) -> Self {
        Self::RFIDDataError(e)
    }
}

impl From<config::ConfigError> for APIError {
    fn from(e: ConfigError) -> Self {
        Self::ConfigError(e)
    }
}

impl Display for APIError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            APIError::ReqwestError(e) => write!(f, "Reqwest error: {}", e),
            APIError::WarpError(e) => write!(f, "Warp error: {}", e),
            APIError::RFIDDataError(e) => write!(f, "RFIDDataError: {}", e),
            APIError::ConfigError(e) => writeln!(f, "Config error: {}", e),
        }
    }
}

impl Error for APIError {}

impl warp::reject::Reject for APIError {}
