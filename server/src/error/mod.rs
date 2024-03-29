use config::ConfigError;
use std::error::Error;
use std::fmt::{Display, Formatter};
use models::error::RfidDataParseError;


#[derive(Debug)]
pub enum ApiError {
    ReqwestError(reqwest::Error),
    WarpError(warp::Error),
    RfidDataError(RfidDataParseError),
    ConfigError(config::ConfigError),
}

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        Self::ReqwestError(e)
    }
}

impl From<warp::Error> for ApiError {
    fn from(e: warp::Error) -> Self {
        Self::WarpError(e)
    }
}

impl From<RfidDataParseError> for ApiError {
    fn from(e: RfidDataParseError) -> Self {
        Self::RfidDataError(e)
    }
}

impl From<config::ConfigError> for ApiError {
    fn from(e: ConfigError) -> Self {
        Self::ConfigError(e)
    }
}

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::ReqwestError(e) => write!(f, "Reqwest error: {}", e),
            ApiError::WarpError(e) => write!(f, "Warp error: {}", e),
            ApiError::RfidDataError(e) => write!(f, "RFIDDataError: {}", e),
            ApiError::ConfigError(e) => writeln!(f, "Config error: {}", e),
        }
    }
}

impl Error for ApiError {}

impl warp::reject::Reject for ApiError {}
