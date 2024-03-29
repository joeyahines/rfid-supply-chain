use models::key::PublicKey;
use config::{Config, ConfigError, File};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct ImportConfig {
    pub import: Vec<PublicKey>,
}

impl ImportConfig {
    pub fn new(config_path: &Path) -> Result<Self, ConfigError> {
        let mut cfg = Config::new();
        cfg.merge(File::with_name(config_path.to_str().unwrap()))?;

        cfg.try_into()
    }
}
